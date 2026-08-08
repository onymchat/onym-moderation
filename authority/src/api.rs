//! The authority's operation surface (Moderation.md §6).
//!
//! What it can do is exactly the table in §6, and what it cannot do is
//! just as deliberate: it does not solicit reports, monitor content,
//! scan devices, hold keys, read anything a reporter did not disclose,
//! ban outside its consented population, or write device marks. There
//! is no endpoint here that touches a mark — only ones that emit
//! verdicts the interface may execute.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::canonical;
use crate::cases;
use crate::error::Error;
use crate::state::AppState;
use crate::store::CaseRecord;
use crate::types::*;
use crate::util;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/manifest.json", get(manifest))
        .route("/v1/mandates", post(accept_mandate))
        .route("/v1/reports", post(file_report))
        .route("/v1/cases/:case_id/respond", post(respond))
        .route("/v1/cases/:case_id/appeal", post(appeal))
        .route("/v1/cases/:case_id/status", get(query_status))
        .route("/v1/cases/:case_id/decide", post(decide))
        .route("/v1/verdicts/:verdict_ref/requeue", post(requeue_verdict))
        .with_state(state)
}

/// Statements are free text from unauthenticated or semi-authenticated
/// parties; the store is not a place to put unbounded prose.
const MAX_STATEMENT_BYTES: usize = 16 * 1024;

/// How many separate responses one case will hold. Generous — the
/// accused may answer, then file more counter-evidence as they find
/// it — but not unbounded.
const MAX_RESPONSES_PER_CASE: usize = 32;

/// An authenticated accused may supplement an appeal, but cannot use
/// the case event log as unbounded storage.
const MAX_APPEALS_PER_CASE: usize = 32;

/// The interface and authority may observe consent a few seconds apart.
/// Anything farther in the future is a client-controlled ordering bid,
/// not a credible consent timestamp.
const MAX_MANDATE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

/// How many notices one case will issue. Each one restarts the
/// accused's response window, so an unbounded count is an unbounded
/// case-open mark — and the mark is a pre-verdict effect the contract
/// allows only because a case ends.
const MAX_NOTICES_PER_CASE: i64 = 8;

/// Party credentials for status reads are short-lived and travel in
/// headers, outside proxy access-log request URIs.
const STATUS_CREDENTIAL_MAX_AGE_SECONDS: i64 = 5 * 60;

/// How many new-holder claims one case will record. Bounded rather
/// than capped at one: this path cannot be authenticated, so a cap of
/// one lets any stranger consume the genuine new owner's only remedy.
/// Several duplicates are noise a moderator skips; a burned slot is a
/// remedy nobody can recover.
const MAX_NEW_HOLDER_CLAIMS: usize = 8;

async fn health(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<Value> {
    // Verdicts the interface refuses are surfaced here rather than
    // only in a log. Each one is a mark that should have moved and did
    // not, and "delivery has quietly failed for a week" should not be
    // something an operator finds out from a case record.
    //
    // The *count* is public, because a monitor needs it and a number
    // discloses nothing. The list is not: it carries verdict refs and
    // whatever the interface echoed back in its error — case ids,
    // verdict fields — and this endpoint sits behind no auth on a
    // proxy that publishes every path.
    let stuck = state.store.undeliverable_verdicts().unwrap_or_default();
    let detail = if authorize_moderator(&state, &headers).is_ok() {
        Some(
            stuck
                .iter()
                .map(|(verdict_ref, error)| json!({ "verdictRef": verdict_ref, "error": error }))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    Json(json!({
        "status": "ok",
        "authority": state.config.manifest.component_id,
        "signingKey": util::key_reference(state.signing_key.verifying_key().as_bytes()),
        "manifestHash": util::sha256_hex(&state.config.manifest_raw),
        "interfaceConfigured": state.delivery.configured(),
        "canDecide": state.config.moderator_token.is_some(),
        "undeliverableVerdicts": stuck.len(),
        "undeliverable": detail,
    }))
}

/// The manifest, byte-for-byte as published. Users' mandates pin the
/// SHA-256 of exactly these bytes, so this must never be re-serialized
/// on the way out.
async fn manifest(State(state): State<Arc<AppState>>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        state.config.manifest_raw.clone(),
    )
        .into_response()
}

// ─── accept-mandate ──────────────────────────────────────────────────

/// The interface registers a user's mandate. This is how jurisdiction
/// arrives: without a mandate naming this authority, we have no power
/// over the user at all, and every report about them is refused.
async fn accept_mandate(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    // An expired manifest may not take new mandates: the terms it
    // offers are no longer on offer, and consent to them now would be
    // consent to something this authority has withdrawn (§5.2).
    require_manifest_current(&state, "accept a mandate")?;

    let mandate: ModerationMandate = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed mandate: {e}")))?;

    if mandate.authority != state.config.manifest.component_id {
        return Err(Error::BadRequest(format!(
            "mandate names authority {}, this is {}",
            mandate.authority, state.config.manifest.component_id
        )));
    }
    // The mandate must consent to *this* manifest. A mandate pinning
    // some other version of our terms is not consent to the ones we
    // would judge under.
    let manifest_hash = util::sha256_hex(&state.config.manifest_raw);
    if mandate.manifest_hash != manifest_hash {
        return Err(Error::BadRequest(
            "mandate pins a different manifest than the one this authority publishes".into(),
        ));
    }

    let signing_bytes = canonical::mandate_signing_bytes(&body)?;

    // The user's signature is what makes this consent.
    let user_signature = mandate
        .signatures
        .first()
        .ok_or_else(|| Error::BadRequest("mandate carries no user signature".into()))?;
    verify_signature(&mandate.user, &signing_bytes, user_signature)
        .map_err(|_| Error::SignatureInvalid("user signature did not verify".into()))?;

    // The interface's countersignature is what makes it a mandate
    // rather than a unilateral claim — it says the interface witnessed
    // the consent and will execute verdicts under it.
    match (state.config.interface_key.as_deref(), mandate.signatures.get(1)) {
        (Some(interface_key), Some(countersignature)) => {
            verify_signature(interface_key, &signing_bytes, countersignature).map_err(|_| {
                Error::SignatureInvalid("interface countersignature did not verify".into())
            })?;
        }
        (Some(_), None) => {
            return Err(Error::BadRequest(
                "mandate is not countersigned by the interface".into(),
            ))
        }
        // No interface key configured, so a countersignature cannot be
        // checked — and an unverifiable designation is exactly the
        // forgery this check exists to catch. Refuse. Accepting here
        // would let anyone who can reach this endpoint grant us
        // jurisdiction over a user who never consented, which is the
        // one failure that turns a consent-bound authority into an
        // unbounded one.
        (None, _) => {
            tracing::error!(
                "AUTHORITY_INTERFACE_KEY is unset; refusing mandate registration. Set it to the \
                 interface's countersigning key (its /health `countersigningKey`)."
            );
            return Err(Error::BadRequest(
                "this authority is not configured with an interface countersigning key, so it \
                 cannot verify that the interface witnessed this consent"
                    .into(),
            ));
        }
    }

    if mandate.classes.is_empty() {
        return Err(Error::BadRequest("mandate must consent to at least one class".into()));
    }
    if let Some(class_id) = mandate
        .classes
        .iter()
        .find(|class_id| state.config.manifest.violation_class(class_id).is_none())
    {
        return Err(Error::BadRequest(format!(
            "mandate class {class_id:?} is not declared by this authority"
        )));
    }

    let mandate_ref = util::sha256_hex(&signing_bytes);
    let accepted_at = util::parse_timestamp(&mandate.accepted_at)
        .map_err(|e| Error::BadRequest(format!("acceptedAt: {e}")))?;
    let now = OffsetDateTime::now_utc();
    if accepted_at > now + time::Duration::seconds(MAX_MANDATE_CLOCK_SKEW_SECONDS) {
        return Err(Error::BadRequest(
            "acceptedAt is too far in the future".into(),
        ));
    }
    // The manifest bytes are stored alongside the mandate, not merely
    // referenced: this mandate consents to *these* terms, and when the
    // published manifest is superseded the case must still be judged by
    // what the user actually agreed to.
    state.store.put_mandate(
        &crate::store::MandateRecord {
            mandate_ref: mandate_ref.clone(),
            user_key: mandate.user.clone(),
            device_binding: mandate.device_binding.clone(),
            classes: mandate.classes.clone(),
            manifest_hash: mandate.manifest_hash.clone(),
        },
        &body,
        &state.config.manifest_raw,
        &util::format_timestamp(accepted_at),
    )?;

    tracing::info!(%mandate_ref, user = %mandate.user, "mandate accepted");
    Ok(Json(json!({ "mandateRef": mandate_ref, "accepted": true })))
}

// ─── file-report ─────────────────────────────────────────────────────

/// Reports are free to file — no bond, no fee — and carry weight per
/// the published reputation policy. There is deliberately no reporter
/// bounty: paid reporting industrialises false accusation (§7.2).
async fn file_report(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    let report: Report = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed report: {e}")))?;

    let signing_bytes = canonical::report_signing_bytes(&body)?;
    verify_signature(&report.reporter, &signing_bytes, &report.signature)
        .map_err(|_| Error::SignatureInvalid("reporter signature did not verify".into()))?;

    // A retried filing must not open a second case or double-count the
    // reporter. Identical bytes under the same (reporter, reportId) are
    // the same report arriving twice, and the honest answer is the
    // original receipt.
    let report_already_stored = if let Some(existing) =
        state.store.report(&report.reporter, &report.report_id)?
    {
        if existing.raw != body.as_ref() {
            return Err(Error::BadRequest(format!(
                "reportId {:?} is already on file with different contents; a filed report is \
                 immutable",
                report.report_id
            )));
        }
        // A report already attached to a case is a replay, and gets the
        // original receipt. One with no case yet is a filing that was
        // interrupted between storing the evidence and opening the
        // case; falling through re-attempts that rather than handing
        // back a receipt naming no case.
        if let Some(case_id) = existing.case_id {
            let case = state.store.case(&case_id)?;
            return Ok(Json(json!({
                "reportId": report.report_id,
                "receivedAt": case.as_ref().map(|c| c.opened_at.clone()),
                "caseId": case_id,
                "duplicate": true,
                "responseDeadline": case.as_ref().map(|c| c.response_deadline.clone()),
                "decisionDeadline": case.as_ref().map(|c| c.decision_deadline.clone()),
            })));
        }
        true
    } else {
        false
    };

    // Standing follows the reporter's mandate: reporting requires
    // having consented to this authority too.
    // Any mandate this key has registered, not only its newest. A
    // reporter who re-consents after the authority republishes its
    // manifest would otherwise have every already-signed, in-flight
    // report refused as `reporter_unconsented` — punished for keeping
    // their consent current.
    let reporter_mandates = state.store.mandates_for_user(&report.reporter)?;
    if reporter_mandates.is_empty() {
        return Err(Error::ReporterUnconsented);
    }
    if !reporter_mandates.iter().any(|m| m.mandate_ref == report.reporter_mandate) {
        return Err(Error::ReporterUnconsented);
    }

    // Jurisdiction follows the accused's mandate. Abuse arriving from a
    // user of a different interface or authority is outside our reach,
    // and the honest disposition is refusal — not a verdict we have no
    // standing to issue.
    let accused_mandate = state
        .store
        .mandate_for_user(&report.accused)?
        .ok_or(Error::NoJurisdiction)?;

    // The class must be one the accused consented to and one we
    // declare — and the terms come from the manifest *their mandate
    // pinned*, not from whatever this authority publishes today.
    // Otherwise republishing a manifest with a longer ban term would
    // silently re-term everyone who consented before it.
    if !accused_mandate.classes.iter().any(|c| c == &report.class_id) {
        return Err(Error::ClassOutsideMandate(report.class_id.clone()));
    }
    let consented = consented_manifest(&state, &accused_mandate)?;
    let class = consented
        .violation_class(&report.class_id)
        .ok_or_else(|| Error::ClassOutsideMandate(report.class_id.clone()))?
        .clone();

    // Every evidence item must verify against the accused's key.
    // Content without an authenticity proof is a complaint, not
    // evidence, and cannot alone support a verdict (§5.4 constraint 1).
    if report.evidence.is_empty() {
        return Err(Error::AuthenticityUnverified("report carries no evidence".into()));
    }
    for (index, item) in report.evidence.iter().enumerate() {
        verify_signature(
            &report.accused,
            item.disclosed_content.as_bytes(),
            &item.authenticity_proof,
        )
        .map_err(|_| {
            Error::AuthenticityUnverified(format!(
                "evidence item {index} does not verify against the accused's key"
            ))
        })?;
    }
    let evidence_summary = report_evidence_summary(&report)?;

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);
    let weight = state.store.reporter(&report.reporter)?.weight();

    // The report goes on file *before* a case exists for it, and is
    // attached afterwards. The other order left a window where a case
    // — and the mark it sets — existed with no report behind it, which
    // is a mark the accused could not be shown a reason for. A report
    // with no case yet is the harmless direction: it is evidence
    // sitting on file, and re-filing it picks up where this left off.
    if !report_already_stored {
        state.store.put_report(
            &report.report_id,
            &report.reporter,
            &report.accused,
            &report.class_id,
            None,
            weight,
            &body,
            &stamp,
        )?;
    }

    // Further reports join an open case rather than opening a second
    // one. Opening a case sets a mark before any response, so
    // duplicate cases would be a way to punish without deciding.
    //
    // The lookup and the insert are separate statements, so two reports
    // arriving together can both find nothing. The store's unique
    // partial index settles that race; losing it means someone else
    // opened the case a moment ago, and the honest response is to join
    // theirs — the same thing we would have done had we looked a
    // moment later.
    let case = match state.store.open_case_for(&report.accused, &report.class_id)? {
        Some(existing) => join_case(&state, &existing, &report, now, &evidence_summary)?,
        None => {
            // Consent has a horizon at both ends. The accused's
            // consented terms must still be live — opening a case under
            // an agreement neither side is still offering would apply
            // terms nobody stands behind, and opening a case sets a
            // mark. And this authority's own published manifest must
            // still be live, which the README and the boot log both
            // promise: an expired authority stops taking new work.
            require_manifest_current(&state, "open a case")?;
            let valid_until = util::parse_timestamp(&consented.valid_until)
                .map_err(|e| Error::Internal(format!("consented manifest validUntil: {e}")))?;
            if now > valid_until {
                return Err(Error::NoJurisdiction);
            }
            match open_case(
                &state,
                &report,
                &accused_mandate,
                &class,
                now,
                &evidence_summary,
            )
            .await?
            {
                Some(opened) => opened,
                None => {
                    let existing = state
                        .store
                        .open_case_for(&report.accused, &report.class_id)?
                        .ok_or_else(|| {
                            Error::Internal(
                                "a concurrent case opening was refused, but no open case is on \
                                 file for this accused and class"
                                    .into(),
                            )
                        })?;
                    join_case(&state, &existing, &report, now, &evidence_summary)?
                }
            }
        }
    };

    state.store.attach_report_to_case(&report.reporter, &report.report_id, &case.case_id)?;

    Ok(Json(json!({
        "reportId": report.report_id,
        // The interface's receipt decoder requires this; without it the
        // client cannot tell a filed report from a dropped one.
        "receivedAt": stamp,
        "caseId": case.case_id,
        "intakeWeight": weight,
        // The notice the accused is owed, so the interface can serve it.
        "responseDeadline": case.response_deadline,
        "decisionDeadline": case.decision_deadline,
    })))
}

/// The manifest a mandate consented to, parsed. A legacy mandate with
/// no snapshot may use the published bytes only when they still hash to
/// the mandate's reference; otherwise there is no safe reconstruction.
fn consented_manifest(
    state: &AppState,
    mandate: &crate::store::MandateRecord,
) -> Result<AuthorityManifest, Error> {
    match state.store.manifest_bytes(&mandate.manifest_hash)? {
        Some(raw) => serde_json::from_slice(&raw)
            .map_err(|e| Error::Internal(format!("stored consented manifest unparseable: {e}"))),
        None => {
            let published_hash = util::sha256_hex(&state.config.manifest_raw);
            if published_hash == mandate.manifest_hash {
                tracing::warn!(
                    mandate_ref = %mandate.mandate_ref,
                    "legacy mandate has no snapshot; published bytes still match its hash"
                );
                Ok(state.config.manifest.clone())
            } else {
                Err(Error::Internal(format!(
                    "mandate {} pins manifest {}, but its snapshot is missing and the published \
                     manifest hashes to {published_hash}; refusing to judge under unconsented terms",
                    mandate.mandate_ref, mandate.manifest_hash
                )))
            }
        }
    }
}

/// Refuse work that an expired manifest cannot authorise. Live cases
/// keep running to their deadlines — an expiry must not strand someone
/// under a case-open mark — but nothing new starts under lapsed terms.
fn require_manifest_current(state: &AppState, action: &str) -> Result<(), Error> {
    let valid_until = util::parse_timestamp(&state.config.manifest.valid_until)
        .map_err(|e| Error::Internal(format!("manifest validUntil: {e}")))?;
    if OffsetDateTime::now_utc() > valid_until {
        return Err(Error::BadRequest(format!(
            "this authority's manifest expired at {}; it cannot {action} under lapsed terms",
            state.config.manifest.valid_until
        )));
    }
    Ok(())
}

/// Push the delivery backlog without making the caller wait for it.
///
/// `flush` drains the *whole* queue at fifteen seconds a verdict, so
/// running it inline meant filing a report took time proportional to
/// the backlog whenever the interface was down — and every request
/// re-attempted every stuck verdict, inflating their counts. The sweep
/// flushes on its own schedule; this only makes a fresh verdict leave
/// promptly when the interface is healthy.
fn flush_soon(state: &Arc<AppState>) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        if let Err(e) = state.delivery.flush(&state.store).await {
            tracing::warn!(error = %e, "background verdict delivery failed; the sweep will retry");
        }
    });
}

fn report_evidence_summary(report: &Report) -> Result<String, Error> {
    let evidence = serde_json::to_vec(&report.evidence)
        .map_err(|e| Error::Internal(format!("encode evidence summary: {e}")))?;
    Ok(format!("sha256:{}", util::sha256_hex(&evidence)))
}

/// Attach a report to an already-open case and issue a revised notice.
/// The new allegations cannot support a sanction under the old notice's
/// nearly-spent window, so both windows restart from this revision.
fn join_case(
    state: &Arc<AppState>,
    existing: &CaseRecord,
    report: &Report,
    now: OffsetDateTime,
    evidence_summary: &str,
) -> Result<CaseRecord, Error> {
    let mandate = state.store.mandate(&existing.mandate_ref)?.ok_or_else(|| {
        Error::Internal(format!(
            "case {} references missing mandate {}; cannot notice joined evidence",
            existing.case_id, existing.mandate_ref
        ))
    })?;
    let manifest = consented_manifest(state, &mandate)?;
    let valid_until = util::parse_timestamp(&manifest.valid_until)
        .map_err(|e| Error::Internal(format!("consented manifest validUntil: {e}")))?;
    if now > valid_until {
        return Err(Error::NoJurisdiction);
    }

    // A case past its decision deadline is dismissed by default, sweep
    // or no sweep. Joining evidence to it would move the horizon
    // forward on a case the contract had already ended in the accused's
    // favour — the "undecided is dismissal" race again, reached through
    // intake rather than through a decider.
    let existing_deadline = util::parse_timestamp(&existing.decision_deadline)
        .map_err(|e| Error::Internal(format!("stored decisionDeadline: {e}")))?;
    if now > existing_deadline {
        return Err(Error::WindowClosed(format!(
            "case {} passed its decision deadline at {}; it is dismissed by default and takes \
             no further evidence",
            existing.case_id, existing.decision_deadline
        )));
    }

    // Evidence already before the accused alleges nothing new, and a
    // notice restating it would restart their windows for no reason.
    // Re-filing the same accused-signed material under fresh report
    // ids was otherwise a way to hold a case — and its mark — open
    // indefinitely.
    let (notices, already_noticed) =
        state.store.notice_status(&existing.case_id, evidence_summary)?;
    if already_noticed || notices >= MAX_NOTICES_PER_CASE {
        let reason = if already_noticed {
            "its evidence is already before the accused"
        } else {
            "this case has issued as many notices as it may"
        };
        state.store.attach_joined_report(
            &report.reporter,
            &report.report_id,
            &existing.case_id,
            &util::format_timestamp(now),
            &format!("report {} joined without a new notice: {reason}", report.report_id),
        )?;
        return Ok(existing.clone());
    }
    let class = manifest
        .violation_class(&existing.class_id)
        .ok_or_else(|| Error::ClassOutsideMandate(existing.class_id.clone()))?;
    let response_days = util::parse_days(&class.response_window)
        .map_err(|e| Error::Internal(format!("manifest responseWindow: {e}")))?;
    // Parsed to validate the consented terms, though the horizon it
    // describes was fixed when this case opened and does not move.
    util::parse_days(&class.decision_deadline)
        .map_err(|e| Error::Internal(format!("manifest decisionDeadline: {e}")))?;

    // The response window restarts — the accused needs time to answer
    // allegations they have just been served — but the decision
    // deadline never moves *outward*. The terminal horizon is fixed
    // when the case opens, so a stream of joins cannot walk it forward
    // forever. A join late enough to push the response window past
    // that horizon simply means no ban can issue on this case: it
    // dismisses at its deadline, and the new evidence is free to open
    // a fresh case afterwards.
    let mut revised = existing.clone();
    revised.response_deadline =
        util::format_timestamp(now + time::Duration::days(response_days));
    // The decision deadline does not move. It is set when the case
    // opens and it is the accused's guarantee that this ends: a stream
    // of joins each pushing it out would make the case-open mark
    // permanent, and that mark is a pre-verdict effect the contract
    // allows only because a case has a horizon.
    //
    // A join late enough that the restarted response window runs past
    // that horizon simply means no ban can issue here — the case
    // dismisses at its deadline and the new evidence is free to open a
    // fresh case afterwards, with its own full windows.
    let issued = cases::open_case_verdict(
        &revised,
        &state.config.manifest.component_id,
        evidence_summary,
        now,
        &state.signing_key,
    )?;
    let stamp = util::format_timestamp(now);
    let joined = state.store.renotice_case_atomically(
        &revised,
        &report.reporter,
        &report.report_id,
        &issued.verdict_ref,
        &issued.disposition,
        &issued.raw,
        &stamp,
        &format!("report {} joined; notice and windows restarted", report.report_id),
        evidence_summary,
    )?;
    if !joined {
        return Err(Error::CaseState(
            "the case was decided while joined evidence was being noticed; retry the report"
                .into(),
        ));
    }
    flush_soon(state);
    Ok(revised)
}

/// Open a case: set the deadlines the manifest declares, issue the
/// interim `open-case` verdict, and hand it to the interface.
///
/// `Ok(None)` means another case for this accused and class was opened
/// concurrently and won; the caller joins that one.
async fn open_case(
    state: &Arc<AppState>,
    report: &Report,
    accused_mandate: &crate::store::MandateRecord,
    class: &ViolationClass,
    now: OffsetDateTime,
    evidence_summary: &str,
) -> Result<Option<CaseRecord>, Error> {
    let response_days = util::parse_days(&class.response_window)
        .map_err(|e| Error::Internal(format!("manifest responseWindow: {e}")))?;
    let decision_days = util::parse_days(&class.decision_deadline)
        .map_err(|e| Error::Internal(format!("manifest decisionDeadline: {e}")))?;

    let case = CaseRecord {
        case_id: format!("case-{}", uuid::Uuid::new_v4()),
        accused: report.accused.clone(),
        reporter: report.reporter.clone(),
        class_id: report.class_id.clone(),
        mandate_ref: accused_mandate.mandate_ref.clone(),
        device_binding: accused_mandate.device_binding.clone(),
        stage: "open".into(),
        opened_at: util::format_timestamp(now),
        response_deadline: util::format_timestamp(now + time::Duration::days(response_days)),
        decision_deadline: util::format_timestamp(now + time::Duration::days(decision_days)),
        responded: false,
        disposition: None,
        appeal_deadline: None,
    };
    let issued = cases::open_case_verdict(
        &case,
        &state.config.manifest.component_id,
        evidence_summary,
        now,
        &state.signing_key,
    )?;
    let stamp = util::format_timestamp(now);
    // The case row, its interim verdict, and the event are one write.
    // Split, a crash in between leaves either a mark with no signed
    // verdict behind it or a verdict for a case that does not exist.
    let opened = state.store.open_case_atomically(
        &case,
        &report.reporter,
        &report.report_id,
        &issued.verdict_ref,
        &issued.disposition,
        &issued.raw,
        &stamp,
        &issued.verdict_ref,
        evidence_summary,
    )?;
    if !opened {
        tracing::info!(
            accused = %report.accused,
            class_id = %report.class_id,
            "a case for this accused and class was opened concurrently; joining it"
        );
        return Ok(None);
    }

    flush_soon(state);
    tracing::info!(case_id = %case.case_id, "case opened");
    Ok(Some(case))
}

// ─── respond / appeal ────────────────────────────────────────────────

/// The accused's response. A missing response does not concede the
/// case; it proceeds to decision on the record. A *late* one enters the
/// record at this authority's declared discretion, which is why this
/// accepts after the window rather than refusing.
async fn respond(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    let response: CaseResponse = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed response: {e}")))?;
    // The signed object names its own case; the path must agree with
    // it. Without this the signature covers a statement that could be
    // presented against any case at all.
    if response.case_id != case_id {
        return Err(Error::BadRequest(format!(
            "this response is signed for case {}, not {case_id}",
            response.case_id
        )));
    }
    if response.statement.len() > MAX_STATEMENT_BYTES {
        return Err(Error::BadRequest(format!(
            "statement exceeds {MAX_STATEMENT_BYTES} bytes"
        )));
    }
    // Nothing about the case is said before the caller proves they are
    // the accused. Reading the stage first meant an unauthenticated
    // holder of a case id learned it existed (404 vs anything else) and
    // whether it had been decided (409) — the same probe the status
    // endpoint refuses, through a door left open beside it.
    //
    // A wrong signature therefore answers "no such case" rather than
    // "bad signature". Less helpful to a client with a bug, and the
    // only shape that tells a stranger nothing.
    let case = match state.store.case(&case_id)? {
        Some(case) => case,
        None => return Err(Error::NotFound(format!("case {case_id}"))),
    };
    let signing_bytes = canonical::report_signing_bytes(&body)?;
    if verify_signature(&case.accused, &signing_bytes, &response.signature).is_err() {
        return Err(Error::NotFound(format!("case {case_id}")));
    }
    let mut case = case;

    if case.stage != "open" {
        return Err(Error::CaseState("case is already decided".into()));
    }
    // Counter-evidence must verify against the accused's own key, the
    // same rule the reporter's evidence is held to.
    for (index, item) in response.evidence.iter().enumerate() {
        verify_signature(&case.accused, item.disclosed_content.as_bytes(), &item.authenticity_proof)
            .map_err(|_| {
                Error::AuthenticityUnverified(format!(
                    "response evidence item {index} does not verify against the accused's key"
                ))
            })?;
    }

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);
    let late = util::parse_timestamp(&case.response_deadline)
        .map(|deadline| now > deadline)
        .unwrap_or(false);

    case.responded = true;
    // The response is stored whole — statement *and* evidence. Keeping
    // only a summary line would mean deciding, and later reviewing on
    // appeal, without the material the accused actually offered.
    state.store.put_response(&crate::store::ResponseFiling {
        case: &case,
        raw: &body,
        late,
        filed_at: &stamp,
        event_kind: if late { "response_late" } else { "response" },
        event_detail: &response.statement,
        limit: MAX_RESPONSES_PER_CASE,
    })?;

    Ok(Json(json!({ "caseId": case_id, "recorded": true, "late": late })))
}

/// An appeal, or a new-holder claim. The latter is the device's new
/// owner and gets expedited review — the mark punishes hardware that
/// may now carry a different, innocent person (§5.7, §11.10).
async fn appeal(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    let submission: AppealSubmission = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed appeal: {e}")))?;
    if submission.case_id != case_id {
        return Err(Error::BadRequest(format!(
            "this submission is signed for case {}, not {case_id}",
            submission.case_id
        )));
    }
    if submission.statement.len() > MAX_STATEMENT_BYTES {
        return Err(Error::BadRequest(format!(
            "statement exceeds {MAX_STATEMENT_BYTES} bytes"
        )));
    }
    let new_holder = match submission.kind.as_str() {
        "appeal" => false,
        "new-holder-claim" => true,
        other => {
            return Err(Error::BadRequest(format!(
                "unknown appeal kind {other:?} (expected appeal | new-holder-claim)"
            )))
        }
    };

    // A new holder is, by definition, not the mandated identity, so
    // their claim cannot be signature-checked against it — which would
    // otherwise make this an unauthenticated endpoint anyone can append
    // to without limit. Two bounds stand in for the signature it cannot
    // have: the claim must answer a ban that is actually in force (a
    // claim against a dismissed case has nothing to remedy), and only
    // one may be pending at a time. Real attestation that the device
    // changed hands needs the interface, which holds the device key;
    // this service cannot verify it alone.
    // This path answers strangers, so its refusals must all look
    // alike. Refusing a claim against a non-banned case with a
    // *distinguishable* error let anyone holding a case id read the
    // disposition off the status code — precisely what an
    // unauthenticated endpoint must not do, and the reason the bounds
    // below are stated as one answer rather than three.
    // A new-holder claim is unauthenticated by design, so it answers
    // every caller identically — filed or not. Two things went wrong
    // when it did not:
    //
    // 1. A banned case answered 200 where everything else answered
    //    404, which made the endpoint a working "is this case a ban?"
    //    oracle for anyone holding a case id.
    // 2. The one-claim-per-case rule matched *any* claim ever filed and
    //    nothing ever resolved one, so a stranger — the banned user
    //    included — could permanently consume the genuine new owner's
    //    only remedy, which §5.7 makes mandatory.
    //
    // So: record the claim when it is one the authority can act on,
    // ignore it otherwise, and say the same thing either way. Claims
    // are bounded per case rather than capped at one, because a
    // duplicate is noise a moderator can skip while a consumed slot is
    // a remedy nobody can get back.
    if new_holder {
        // The lookup happens *inside* this branch, and its result never
        // reaches the caller: a claim about a case that does not exist
        // answers exactly as one about a case that does.
        let case = state.store.case(&case_id)?;
        let actionable = case.as_ref().and_then(|c| c.disposition.as_deref()) == Some("ban");
        if actionable {
            let stamp = util::format_timestamp(OffsetDateTime::now_utc());
            // Count and insert share one store lock. This endpoint is
            // unauthenticated, so a check followed by a separate write
            // would let a concurrent burst overrun the advertised cap.
            let _ = state.store.append_event_bounded(
                &case_id,
                &stamp,
                "new_holder_claim",
                &submission.statement,
                MAX_NEW_HOLDER_CLAIMS,
            )?;
            tracing::info!(%case_id, "new-holder claim filed");
        }
        // Same answer whether it was recorded or not.
        return Ok(Json(json!({
            "caseId": case_id,
            "filed": true,
            "kind": submission.kind,
            "note": "a new-holder claim is reviewed by a human on an expedited basis; a device \
                     is not a person"
        })));
    }

    let case = match state.store.case(&case_id)? {
        Some(case) => case,
        None => return Err(Error::NotFound(format!("case {case_id}"))),
    };

    {
        let signing_bytes = canonical::report_signing_bytes(&body)?;
        // As on `respond`: a caller who cannot prove they are the
        // accused learns nothing about the case, including whether it
        // exists.
        if verify_signature(&case.accused, &signing_bytes, &submission.signature).is_err() {
            return Err(Error::NotFound(format!("case {case_id}")));
        }

        if case.disposition.as_deref() != Some("ban") {
            return Err(Error::CaseState("only a ban may be appealed".into()));
        }
        let deadline = case
            .appeal_deadline
            .as_deref()
            .ok_or_else(|| Error::Internal("a banned case has no appealDeadline".into()))?;
        let deadline = util::parse_timestamp(deadline)
            .map_err(|e| Error::Internal(format!("stored appealDeadline: {e}")))?;
        if OffsetDateTime::now_utc() > deadline {
            return Err(Error::WindowClosed("the appeal window has closed".into()));
        }
    }

    let stamp = util::format_timestamp(OffsetDateTime::now_utc());
    let filed = state.store.append_event_bounded(
        &case_id,
        &stamp,
        "appeal_filed",
        &submission.statement,
        MAX_APPEALS_PER_CASE,
    )?;
    if !filed {
        return Err(Error::CaseState(format!(
            "this case already holds {MAX_APPEALS_PER_CASE} appeals; further material belongs \
             in one of them rather than in another filing"
        )));
    }

    tracing::info!(%case_id, kind = %submission.kind, "appeal filed");
    Ok(Json(json!({
        "caseId": case_id,
        "filed": true,
        "kind": submission.kind,
        // Whether a non-final ban keeps executing meanwhile follows the
        // class's consented appeal effect; the interface applies it.
        "note": "an appeal is reviewed by the authority; a successful one issues a reversal verdict"
    })))
}

// ─── query-status ────────────────────────────────────────────────────

/// Stage and deadlines, per the confidentiality policy. The reporter's
/// identity is deliberately absent: it is visible to the authority,
/// never to the accused unless the reporter consents (§5.4 constraint 4).
async fn query_status(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    // Case existence, stage, and timing are not public facts. A case id
    // is a bearer secret otherwise: anyone holding one could learn that
    // a given person is under investigation, which is exactly what the
    // confidentiality policy withholds. A party proves who they are by
    // signing the case id with the key that made them a party.
    authorize_case_party(&state, &case, &case_id, &headers)?;

    let events: Vec<Value> = state
        .store
        .events(&case_id)?
        .into_iter()
        .map(|(at, kind, _detail)| json!({ "at": at, "kind": kind }))
        .collect();

    Ok(Json(json!({
        "caseId": case.case_id,
        "stage": case.stage,
        "classId": case.class_id,
        "openedAt": case.opened_at,
        "responseDeadline": case.response_deadline,
        "decisionDeadline": case.decision_deadline,
        "responded": case.responded,
        // So the accused can confirm their answer is on file — a
        // response that vanished silently is indistinguishable from one
        // that was never sent.
        "responsesOnFile": state.store.responses(&case_id)?.len(),
        "disposition": case.disposition,
        "appealDeadline": case.appeal_deadline,
        "events": events,
    })))
}

// ─── issue-verdict ───────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Decision {
    /// `dismiss` | `ban` | `reverse`
    disposition: String,
    /// Content address of the findings against the consented class
    /// definition. Mandatory: an unexplained ban is nonconforming even
    /// where confidentiality keeps it private.
    reasoning: String,
}

/// The moderator's decision. This is the one place human judgment
/// enters, and it is the only way a ban can be issued — there is no
/// automatic path from a report to a sanction.
async fn decide(
    State(state): State<Arc<AppState>>,
    Path(case_id): Path<String>,
    headers: HeaderMap,
    Json(decision): Json<Decision>,
) -> Result<Json<Value>, Error> {
    authorize_moderator(&state, &headers)?;

    let mut case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    if decision.reasoning.trim().is_empty() {
        return Err(Error::BadRequest("reasoning is required on every disposition".into()));
    }

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);

    // Every reporter on the case, not just whoever filed first. A case
    // three people reported was upheld or dismissed for all three.
    let reporters = {
        let mut reporters = state.store.case_reporters(&case_id)?;
        if !reporters.contains(&case.reporter) {
            reporters.push(case.reporter.clone());
        }
        reporters
    };

    let issued = match decision.disposition.as_str() {
        "dismiss" => {
            if case.stage != "open" {
                return Err(Error::CaseState("case is already decided".into()));
            }
            // Notice must precede sanction, but a dismissal is not a
            // sanction — it can land any time before the deadline.
            cases::dismissal_verdict(
                &case,
                &state.config.manifest.component_id,
                &decision.reasoning,
                now,
                &state.signing_key,
            )?
        }
        "ban" => {
            if case.stage != "open" {
                return Err(Error::CaseState("case is already decided".into()));
            }
            if !state.store.open_case_verdict_delivered(&case_id)? {
                return Err(Error::CaseState(
                    "the opening verdict has not reached the interface; banning before notice \
                     would run the response window silently"
                        .into(),
                ));
            }
            // The decision deadline is not advisory: once it passes the
            // case is dismissed by default, whether or not the sweep
            // has run yet (§3.5). Without this check a moderator could
            // ban a case that the contract had already ended in the
            // accused's favour — and the sweep would simply lose the
            // race. "Undecided is dismissal" has to hold at the moment
            // of decision, not at the moment a background task notices.
            let decision_deadline = util::parse_timestamp(&case.decision_deadline)
                .map_err(|e| Error::Internal(format!("stored decisionDeadline: {e}")))?;
            if now > decision_deadline {
                return Err(Error::WindowClosed(format!(
                    "the decision deadline passed at {}; this case is dismissed by default and \
                     cannot be banned",
                    case.decision_deadline
                )));
            }
            // The response window must have *elapsed* before any ban
            // verdict: §8 obligation 4 says hold it, and §11.4 says the
            // banned mark is set "only after the response window a
            // consented class declared". Neither admits an exception
            // for a case that has already been answered.
            //
            // An earlier version banned as soon as any response
            // existed. That reads the window as a formality to be
            // discharged rather than as time the accused was promised:
            // they may answer on day one and keep gathering
            // counter-evidence until day three, and a ban on day one
            // takes the other two days away. The case-open mark is the
            // only pre-verdict effect this authority may have.
            let response_deadline = util::parse_timestamp(&case.response_deadline)
                .map_err(|e| Error::Internal(format!("stored responseDeadline: {e}")))?;
            if now < response_deadline {
                return Err(Error::CaseState(format!(
                    "the response window runs until {}; a ban before it closes is nonconforming",
                    case.response_deadline
                )));
            }
            let mandate = state.store.mandate(&case.mandate_ref)?.ok_or_else(|| {
                Error::Internal(format!(
                    "case {} references missing mandate {}; refusing to judge under published \
                     terms the accused may not have consented to",
                    case.case_id, case.mandate_ref
                ))
            })?;
            let consented = consented_manifest(&state, &mandate)?;
            let class = consented
                .violation_class(&case.class_id)
                .ok_or_else(|| Error::ClassOutsideMandate(case.class_id.clone()))?;
            cases::ban_verdict(
                &case,
                class,
                &state.config.manifest.component_id,
                &decision.reasoning,
                now,
                &state.signing_key,
            )?
        }
        "reverse" => {
            // A reversal is a new verdict that clears marks — the only
            // conforming way to correct one, since verdicts are
            // immutable and corrections never travel as edits (§12).
            if case.disposition.as_deref() != Some("ban") {
                return Err(Error::CaseState("only a ban can be reversed".into()));
            }
            cases::reversal_verdict(
                &case,
                &state.config.manifest.component_id,
                &decision.reasoning,
                now,
                &state.signing_key,
            )?
        }
        other => {
            return Err(Error::BadRequest(format!(
                "unknown disposition {other:?} (expected dismiss | ban | reverse)"
            )))
        }
    };

    // A reversal ends the sanction; the case stays decided either way.
    case.stage = "decided".into();
    case.disposition = Some(if decision.disposition == "reverse" {
        "reversed".into()
    } else {
        decision.disposition.clone()
    });
    if decision.disposition == "ban" {
        let v: Value = serde_json::from_slice(&issued.raw)
            .map_err(|e| Error::Internal(format!("re-read verdict: {e}")))?;
        case.appeal_deadline = v["appealDeadline"].as_str().map(str::to_string);
    }

    // Verdict, case stage, event, and reporter track records commit
    // together — and only after the verdict was successfully built and
    // signed. Crediting reporters first meant a decision that failed to
    // sign still moved their standing.
    //
    // A reversal is not a dismissal of the report: it corrects this
    // authority's own error, so nobody's record moves for it.
    let credited: &[String] = if decision.disposition == "reverse" { &[] } else { &reporters };
    state.store.commit_decision(&crate::store::Decision {
        case: &case,
        verdict_ref: &issued.verdict_ref,
        disposition: &issued.disposition,
        raw: &issued.raw,
        at: &stamp,
        event_kind: "decided",
        event_detail: &decision.disposition,
        credited_reporters: credited,
        // What the guards above checked. A reversal was found decided
        // and banned; everything else was found open.
        expect_stage: if decision.disposition == "reverse" { "decided" } else { "open" },
        expect_disposition: if decision.disposition == "reverse" { Some("ban") } else { None },
    })?;

    flush_soon(&state);

    tracing::info!(%case_id, verdict_ref = %issued.verdict_ref, disposition = %issued.disposition, "case decided");
    Ok(Json(json!({
        "caseId": case_id,
        "verdictRef": issued.verdict_ref,
        // The case's disposition, which for a reversal is "reversed".
        // The *verdict* still says "dismiss": that is the only wire
        // value meaning "clear the marks", and the interface's
        // vocabulary is open-case | dismiss | ban. Reporting the
        // verdict's word here made a reversal read as a dismissal in
        // the one place a caller looks to confirm what it just did.
        "disposition": case.disposition.clone().unwrap_or_else(|| issued.disposition.clone()),
        "verdictDisposition": issued.disposition,
    })))
}

/// Return a repaired, previously permanent refusal to the delivery
/// queue. This is an operator action: the verdict remains immutable;
/// only its delivery state is reset after the underlying mismatch has
/// been fixed.
async fn requeue_verdict(
    State(state): State<Arc<AppState>>,
    Path(verdict_ref): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    authorize_moderator(&state, &headers)?;
    if !state.store.requeue_verdict(&verdict_ref)? {
        return Err(Error::CaseState(format!(
            "verdict {verdict_ref} is not an undeliverable verdict awaiting repair"
        )));
    }
    tracing::warn!(%verdict_ref, "operator requeued an undeliverable verdict");
    flush_soon(&state);
    Ok(Json(json!({ "verdictRef": verdict_ref, "requeued": true })))
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// A caller may read a case if they are the accused, a reporter on it,
/// or a moderator. Party proof is a fresh signature carried in headers,
/// never in a query string that proxies and caches routinely retain.
fn authorize_case_party(
    state: &AppState,
    case: &CaseRecord,
    case_id: &str,
    headers: &HeaderMap,
) -> Result<(), Error> {
    if authorize_moderator(state, headers).is_ok() {
        return Ok(());
    }
    let credential = |name: &'static str| headers.get(name).and_then(|value| value.to_str().ok());
    let (Some(key), Some(timestamp), Some(signature)) = (
        credential("x-onym-key"),
        credential("x-onym-timestamp"),
        credential("x-onym-signature"),
    ) else {
        // Not `SignatureInvalid`. A 401 here and a 404 for a case that
        // does not exist would let anyone holding a case id tell the
        // two apart with no credential at all — the whole probe, in one
        // request with no query string. The advice about what to send
        // belongs in the docs, not in a reply that doubles as an
        // existence oracle.
        return Err(Error::NotFound(format!("case {case_id}")));
    };

    // Signature first, party membership second — and the same refusal
    // for both. Checking membership first answered a question the
    // caller had proved no right to ask: a non-party key got `404` and
    // a party key with a bogus signature got `401`, so anyone holding a
    // case id could learn whether a given key is the accused, or a
    // reporter on the case, with no proof at all. That is precisely the
    // fact the not-found answer exists to withhold.
    let now = OffsetDateTime::now_utc();
    let fresh = util::parse_timestamp(timestamp)
        .map(|signed_at| {
            (now - signed_at).whole_seconds().abs() <= STATUS_CREDENTIAL_MAX_AGE_SECONDS
        })
        .unwrap_or(false);
    let message = format!("query-status:{case_id}:{timestamp}");
    let signature_valid = fresh && verify_signature(key, message.as_bytes(), signature).is_ok();

    let is_party = key == case.accused
        || key == case.reporter
        || state.store.case_reporters(case_id)?.iter().any(|r| r == key);

    if signature_valid && is_party {
        return Ok(());
    }

    // One answer for every failure: wrong signature, right key; right
    // signature, wrong key; a case that does not exist at all. A
    // distinguishable refusal would confirm that a named person is
    // under investigation.
    Err(Error::NotFound(format!("case {case_id}")))
}

fn verify_signature(key_reference: &str, message: &[u8], signature: &str) -> Result<(), Error> {
    let key_bytes = util::key_bytes_from_reference(key_reference)
        .ok_or_else(|| Error::BadRequest(format!("{key_reference:?} is not an onym:key: reference")))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| Error::BadRequest("key is not 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::BadRequest(format!("not a valid Ed25519 key: {e}")))?;
    let raw = util::base64_decode(signature)
        .ok_or_else(|| Error::BadRequest("signature is not base64".into()))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|e| Error::BadRequest(format!("signature is malformed: {e}")))?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::SignatureInvalid("signature did not verify".into()))
}

/// Deciding a case is this authority's judgment. Without a moderator
/// token configured, nothing may decide one — the deadline default
/// still applies, so cases resolve by dismissal rather than hanging.
fn authorize_moderator(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    let Some(expected) = state.config.moderator_token.as_deref() else {
        return Err(Error::SignatureInvalid(
            "AUTHORITY_MODERATOR_TOKEN is not configured; no case can be decided".into(),
        ));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err(Error::SignatureInvalid("moderator bearer token missing or wrong".into())),
    }
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.iter().zip(rhs).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

// ─── Tests ───────────────────────────────────────────────────────────
//
// These drive the real router. What is being pinned here is mostly what
// this service *refuses* — the restraint is the reviewable part of a
// moderation service, and a refusal that quietly regresses into an
// acceptance is the failure that matters.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::testing::{self, ACCUSED_SEED, INTERFACE_SEED, REPORTER_SEED, STRANGER_SEED};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct Harness {
        state: Arc<AppState>,
    }

    impl Harness {
        fn new() -> Self {
            Self { state: Arc::new(AppState::for_tests(Store::in_memory().unwrap())) }
        }

        async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
            let response = router(self.state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            (status, body)
        }

        async fn post(&self, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
            self.send(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
        }

        async fn decide(&self, case_id: &str, body: Value) -> (StatusCode, Value) {
            self.send(
                Request::post(format!("/v1/cases/{case_id}/decide"))
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
        }
    }

    /// Serialize, sign the canonical bytes, and put the signature back
    /// — the shape a real client produces.
    fn signed(mut object: Value, signature_field: &str, seeds: &[[u8; 32]]) -> Vec<u8> {
        let raw = serde_json::to_vec(&object).unwrap();
        let signing_bytes = canonical::canonical_bytes(&raw, &[signature_field]).unwrap();
        let signatures: Vec<String> =
            seeds.iter().map(|seed| testing::sign(*seed, &signing_bytes)).collect();
        object[signature_field] = if signature_field == "signatures" {
            json!(signatures)
        } else {
            json!(signatures[0])
        };
        serde_json::to_vec(&object).unwrap()
    }

    fn mandate_json(user_seed: [u8; 32], classes: Value, manifest_hash: &str) -> Value {
        json!({
            "mandateVersion": 1,
            "user": testing::key_reference(user_seed),
            "interface": "onym:component:test-interface",
            "authority": "onym:component:test-authority",
            "manifestHash": manifest_hash,
            "classes": classes,
            "deviceBinding": format!("device-{}", user_seed[0]),
            "acceptedAt": "2026-08-01T00:00:00Z",
        })
    }

    async fn register_mandate(harness: &Harness, user_seed: [u8; 32]) -> String {
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);
        let body = signed(
            mandate_json(user_seed, json!(["csam", "unsolicited-pornography"]), &manifest_hash),
            "signatures",
            &[user_seed, INTERFACE_SEED],
        );
        let (status, response) = harness.post("/v1/mandates", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["mandateRef"].as_str().unwrap().to_string()
    }

    fn report_json(reporter_mandate: &str, report_id: &str) -> Value {
        let content = "prohibited thing";
        json!({
            "reportVersion": 1,
            "reportId": report_id,
            "reporter": testing::key_reference(REPORTER_SEED),
            "reporterMandate": reporter_mandate,
            "accused": testing::key_reference(ACCUSED_SEED),
            "classId": "csam",
            "evidence": [{
                "disclosedContent": content,
                // Authenticity is a signature by the *accused* over the
                // content: that is what makes it evidence of authorship
                // rather than an assertion about it.
                "authenticityProof": testing::sign(ACCUSED_SEED, content.as_bytes()),
            }],
            "filedAt": "2026-08-02T00:00:00Z",
        })
    }

    /// A registered accused, a registered reporter, and an open case.
    async fn open_case(harness: &Harness) -> String {
        register_mandate(harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(harness, REPORTER_SEED).await;
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();
        let opening = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(opening.len(), 1);
        harness.state.store.mark_delivered(&opening[0].verdict_ref).unwrap();
        case_id
    }

    // ─── Jurisdiction ────────────────────────────────────────────────

    #[tokio::test]
    async fn a_report_about_an_unmandated_user_is_refused_not_judged() {
        let harness = Harness::new();
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"], "no_jurisdiction");
    }

    #[tokio::test]
    async fn a_reporter_without_their_own_mandate_has_no_standing() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let body = signed(report_json("some-mandate", "r-1"), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"], "reporter_unconsented");
    }

    #[tokio::test]
    async fn content_without_an_authenticity_proof_is_a_complaint_not_evidence() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let mut report = report_json(&reporter_mandate, "r-1");
        // Signed by someone who is not the accused.
        report["evidence"][0]["authenticityProof"] =
            json!(testing::sign(STRANGER_SEED, b"prohibited thing"));
        let body = signed(report, "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert_eq!(response["error"], "authenticity_unverified");
    }

    /// A crash after evidence storage but before case opening must not
    /// strand an otherwise valid report forever. Refiling the exact
    /// signed bytes resumes at case opening.
    #[tokio::test]
    async fn an_interrupted_report_filing_resumes_from_the_stored_evidence() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(
            report_json(&reporter_mandate, "interrupted-report"),
            "signature",
            &[REPORTER_SEED],
        );

        harness
            .state
            .store
            .put_report(
                "interrupted-report",
                &testing::key_reference(REPORTER_SEED),
                &testing::key_reference(ACCUSED_SEED),
                "csam",
                None,
                1.0,
                &body,
                "2026-08-02T00:00:00Z",
            )
            .unwrap();

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap();
        assert_eq!(
            harness
                .state
                .store
                .report(&testing::key_reference(REPORTER_SEED), "interrupted-report")
                .unwrap()
                .unwrap()
                .case_id
                .as_deref(),
            Some(case_id)
        );
    }

    // ─── Mandates ────────────────────────────────────────────────────

    /// Re-delivering an old signed mandate is idempotent. It must not
    /// refresh that row's ordering and restore classes the user's newer
    /// mandate no longer grants.
    #[tokio::test]
    async fn replaying_an_older_mandate_does_not_restore_its_jurisdiction() {
        let harness = Harness::new();
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);

        let broad = signed(
            mandate_json(
                ACCUSED_SEED,
                json!(["csam", "unsolicited-pornography"]),
                &manifest_hash,
            ),
            "signatures",
            &[ACCUSED_SEED, INTERFACE_SEED],
        );
        let (status, _) = harness.post("/v1/mandates", broad.clone()).await;
        assert_eq!(status, StatusCode::OK);

        let mut narrow = mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash);
        // Deliberately older than the broad mandate: receipt order,
        // not this client-controlled timestamp, decides precedence.
        narrow["acceptedAt"] = json!("2026-07-31T00:00:00Z");
        let narrow = signed(narrow, "signatures", &[ACCUSED_SEED, INTERFACE_SEED]);
        let (status, narrow_response) = harness.post("/v1/mandates", narrow).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = harness.post("/v1/mandates", broad).await;
        assert_eq!(status, StatusCode::OK);

        let current = harness
            .state
            .store
            .mandate_for_user(&testing::key_reference(ACCUSED_SEED))
            .unwrap()
            .unwrap();
        assert_eq!(
            current.mandate_ref,
            narrow_response["mandateRef"].as_str().unwrap()
        );
        assert_eq!(current.classes, vec!["csam".to_string()]);
    }

    #[tokio::test]
    async fn a_future_or_policy_empty_mandate_is_refused() {
        let harness = Harness::new();
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);

        let mut future = mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash);
        future["acceptedAt"] = json!("2099-01-01T00:00:00Z");
        let (status, response) = harness
            .post(
                "/v1/mandates",
                signed(future, "signatures", &[ACCUSED_SEED, INTERFACE_SEED]),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");

        for classes in [json!([]), json!(["not-in-the-manifest"])] {
            let body = signed(
                mandate_json(ACCUSED_SEED, classes, &manifest_hash),
                "signatures",
                &[ACCUSED_SEED, INTERFACE_SEED],
            );
            let (status, response) = harness.post("/v1/mandates", body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        }
        assert!(
            harness
                .state
                .store
                .mandate_for_user(&testing::key_reference(ACCUSED_SEED))
                .unwrap()
                .is_none()
        );
    }

    /// Without a configured interface key a countersignature cannot be
    /// checked, and an unverifiable designation is the forgery the
    /// check exists to catch.
    #[tokio::test]
    async fn mandate_registration_fails_closed_without_an_interface_key() {
        let mut state = AppState::for_tests(Store::in_memory().unwrap());
        state.config.interface_key = None;
        let harness = Harness { state: Arc::new(state) };

        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);
        let body = signed(
            mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash),
            "signatures",
            &[ACCUSED_SEED, INTERFACE_SEED],
        );

        let (status, _) = harness.post("/v1/mandates", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_mandate_countersigned_by_the_wrong_key_is_refused() {
        let harness = Harness::new();
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);
        let body = signed(
            mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash),
            "signatures",
            &[ACCUSED_SEED, STRANGER_SEED],
        );

        let (status, _) = harness.post("/v1/mandates", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_mandate_pinning_another_manifest_is_refused() {
        let harness = Harness::new();
        let body = signed(
            mandate_json(ACCUSED_SEED, json!(["csam"]), &"a".repeat(64)),
            "signatures",
            &[ACCUSED_SEED, INTERFACE_SEED],
        );

        let (status, _) = harness.post("/v1/mandates", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A class the accused did not consent to is outside this
    /// authority's reach even though the manifest declares it.
    #[tokio::test]
    async fn a_class_outside_the_mandate_is_refused() {
        let harness = Harness::new();
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);
        let body = signed(
            mandate_json(ACCUSED_SEED, json!(["unsolicited-pornography"]), &manifest_hash),
            "signatures",
            &[ACCUSED_SEED, INTERFACE_SEED],
        );
        harness.post("/v1/mandates", body).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // The report names `csam`, which this accused did not consent to.
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"], "class_outside_mandate");
    }

    // ─── Report immutability ─────────────────────────────────────────

    /// A report is evidence. Refiling identical bytes is a retry and
    /// gets the original receipt; refiling *different* bytes under a
    /// used id is an attempt to rewrite the record.
    #[tokio::test]
    async fn a_filed_report_cannot_be_rewritten_but_may_be_retried() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let original = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, first) = harness.post("/v1/reports", original.clone()).await;
        assert_eq!(status, StatusCode::OK);

        let (status, retry) = harness.post("/v1/reports", original).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry["duplicate"], true);
        assert_eq!(retry["caseId"], first["caseId"], "a retry must not open a second case");

        let mut edited = report_json(&reporter_mandate, "r-1");
        edited["filedAt"] = json!("2026-08-03T00:00:00Z");
        let (status, _) =
            harness.post("/v1/reports", signed(edited, "signature", &[REPORTER_SEED])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Two reports about the same accused and class join one case: a
    /// second case would set a second mark before anyone decided
    /// anything.
    #[tokio::test]
    async fn further_reports_join_the_open_case() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // A live case with a nearly-spent response window. Joined
        // evidence must restart that window — the accused has just been
        // served with something new — without touching the decision
        // deadline, which is their guarantee the case ends.
        let mut original_case = harness.state.store.case(&case_id).unwrap().unwrap();
        original_case.response_deadline = "2026-08-09T00:00:00Z".into();
        harness.state.store.put_case(&original_case).unwrap();

        let mut report = report_json(&reporter_mandate, "r-2");
        report["evidence"][0]["disclosedContent"] = json!("a different prohibited thing");
        report["evidence"][0]["authenticityProof"] = json!(testing::sign(
            ACCUSED_SEED,
            b"a different prohibited thing"
        ));
        let body = signed(report, "signature", &[REPORTER_SEED]);
        let expected_evidence_summary = report_evidence_summary(
            &serde_json::from_slice::<Report>(&body).expect("the test report is valid"),
        )
        .unwrap();
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["caseId"], case_id);
        assert!(
            !harness.state.store.open_case_verdict_delivered(&case_id).unwrap(),
            "the new evidence has a revised notice that must be delivered before a ban"
        );
        let revised_notice = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(revised_notice.len(), 1);
        let notice: Value = serde_json::from_slice(&revised_notice[0].raw).unwrap();
        assert_eq!(notice["reasoning"].as_str(), Some(expected_evidence_summary.as_str()));
        let revised_case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_ne!(
            revised_case.response_deadline, original_case.response_deadline,
            "the accused gets their window back for allegations they have just been served"
        );
        assert_eq!(
            revised_case.decision_deadline, original_case.decision_deadline,
            "the horizon does not move: joins must not be able to walk it forward forever"
        );
        harness
            .state
            .store
            .mark_delivered(&revised_notice[0].verdict_ref)
            .unwrap();
        assert!(harness.state.store.open_case_verdict_delivered(&case_id).unwrap());
    }

    // ─── Notice before sanction ──────────────────────────────────────

    #[tokio::test]
    async fn a_ban_inside_the_response_window_is_refused() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let (status, response) =
            harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["error"], "case_state");
    }

    #[tokio::test]
    async fn a_ban_is_refused_until_the_opening_verdict_is_delivered() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();

        let (status, response) = harness
            .decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"}))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        assert_eq!(response["error"], "case_state");
        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().stage, "open");
    }

    #[tokio::test]
    async fn a_ban_fails_closed_when_its_mandate_row_is_missing() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.state.store.remove_mandate(&case.mandate_ref).unwrap();

        let (status, response) = harness
            .decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"}))
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{response}");
        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().stage, "open");
    }

    /// An answered case does not shorten the window. The accused was
    /// promised the time, not merely the opportunity to speak once.
    #[tokio::test]
    async fn a_response_does_not_open_the_door_to_an_early_ban() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let response_body = signed(
            json!({"caseId": case_id, "statement": "it wasn't me", "evidence": []}),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) =
            harness.post(&format!("/v1/cases/{case_id}/respond"), response_body).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) =
            harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;
        assert_eq!(status, StatusCode::CONFLICT, "the window still has days to run");
    }

    /// Undecided is dismissal, and it binds at the moment of decision —
    /// not whenever the sweep next happens to run.
    #[tokio::test]
    async fn a_ban_after_the_decision_deadline_is_refused() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        case.decision_deadline = "2020-01-08T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();

        let (status, response) =
            harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(response["error"], "window_closed");
    }

    #[tokio::test]
    async fn a_ban_after_the_window_closes_is_issued_and_credits_every_reporter() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();

        let (status, response) =
            harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["disposition"], "ban");

        let reporter = harness.state.store.reporter(&testing::key_reference(REPORTER_SEED)).unwrap();
        assert_eq!(reporter.upheld, 1);
    }

    #[tokio::test]
    async fn deciding_requires_the_moderator_token_and_a_reason() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let (status, _) = harness
            .post(
                &format!("/v1/cases/{case_id}/decide"),
                serde_json::to_vec(&json!({"disposition": "dismiss", "reasoning": "hash:f"}))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no bearer token");

        let (status, _) =
            harness.decide(&case_id, json!({"disposition": "dismiss", "reasoning": "  "})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "an unexplained disposition");
    }

    // ─── Signed-object binding ───────────────────────────────────────

    /// A response signed for one case must not be replayable onto
    /// another: "that wasn't me" against a spam case would otherwise
    /// register as an answer to an accusation the signer never saw.
    #[tokio::test]
    async fn a_response_signed_for_another_case_is_refused() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let body = signed(
            json!({"caseId": "some-other-case", "statement": "no", "evidence": []}),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/respond"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn only_the_accused_may_respond() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let body = signed(
            json!({"caseId": case_id, "statement": "no", "evidence": []}),
            "signature",
            &[STRANGER_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/respond"), body).await;
        // Not 401: a caller who cannot prove they are the accused must
        // not learn that the case exists either.
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// The new-holder path cannot be signature-checked — the new owner
    /// is not the mandated identity — so it answers every caller the
    /// same way and records only what it can act on. What it must not
    /// do is *tell* the caller which of those happened: a
    /// distinguishable answer made it an oracle for "is this case a
    /// ban?".
    #[tokio::test]
    async fn a_new_holder_claim_is_recorded_only_against_a_ban_but_answers_the_same() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let claim = |case_id: &str| {
            serde_json::to_vec(&json!({
                "caseId": case_id,
                "kind": "new-holder-claim",
                "statement": "I bought this device secondhand",
            }))
            .unwrap()
        };

        // Open case, no ban: accepted-looking, and recorded nowhere.
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), claim(&case_id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(claims_on_file(&harness, &case_id), 0, "nothing to be relieved of");

        // Ban it, and the same request is now recorded — with the same
        // answer as before.
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;

        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), claim(&case_id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(claims_on_file(&harness, &case_id), 1);
    }

    fn claims_on_file(harness: &Harness, case_id: &str) -> usize {
        harness
            .state
            .store
            .events(case_id)
            .unwrap()
            .iter()
            .filter(|(_, kind, _)| kind == "new_holder_claim")
            .count()
    }

    /// Appeals are authenticated, but their statements are still
    /// untrusted storage. They apply only to a ban and are bounded just
    /// like repeated responses.
    #[tokio::test]
    async fn appeals_are_only_for_bans_and_bounded() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let appeal = |statement: String| {
            signed(
                json!({
                    "caseId": &case_id,
                    "kind": "appeal",
                    "statement": statement,
                }),
                "signature",
                &[ACCUSED_SEED],
            )
        };

        let (status, _) = harness
            .post(&format!("/v1/cases/{case_id}/appeal"), appeal("too early".into()))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        let (status, response) = harness
            .decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"}))
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");

        for index in 0..MAX_APPEALS_PER_CASE {
            let (status, response) = harness
                .post(
                    &format!("/v1/cases/{case_id}/appeal"),
                    appeal(format!("appeal material {index}")),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{response}");
        }
        let (status, _) = harness
            .post(
                &format!("/v1/cases/{case_id}/appeal"),
                appeal("one filing too many".into()),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            harness
                .state
                .store
                .events(&case_id)
                .unwrap()
                .iter()
                .filter(|(_, kind, _)| kind == "appeal_filed")
                .count(),
            MAX_APPEALS_PER_CASE
        );
    }

    /// The unauthenticated path is storage-bounded, but the cap remains
    /// exhaustible. A claim arriving before exhaustion reaches review;
    /// ownership attestation is an interface responsibility.
    #[tokio::test]
    async fn new_holder_claims_are_bounded_but_not_authenticated() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;

        let claim = |statement: &str| {
            serde_json::to_vec(&json!({
                "caseId": case_id,
                "kind": "new-holder-claim",
                "statement": statement,
            }))
            .unwrap()
        };

        // Somebody floods it. The genuine claim still lands.
        for _ in 0..3 {
            harness.post(&format!("/v1/cases/{case_id}/appeal"), claim("noise")).await;
        }
        let (status, _) = harness
            .post(&format!("/v1/cases/{case_id}/appeal"), claim("I am the new owner"))
            .await;
        assert_eq!(status, StatusCode::OK);

        let recorded: Vec<String> = harness
            .state
            .store
            .events(&case_id)
            .unwrap()
            .into_iter()
            .filter(|(_, kind, _)| kind == "new_holder_claim")
            .map(|(_, _, detail)| detail)
            .collect();
        assert!(
            recorded.iter().any(|d| d == "I am the new owner"),
            "the real claim must reach a human despite the noise: {recorded:?}"
        );

        // And the append is bounded rather than unlimited.
        for _ in 0..20 {
            harness.post(&format!("/v1/cases/{case_id}/appeal"), claim("more noise")).await;
        }
        assert_eq!(claims_on_file(&harness, &case_id), MAX_NEW_HOLDER_CLAIMS);
    }


    // ─── Confidentiality ─────────────────────────────────────────────

    /// A case id is not a credential. Anyone holding one could
    /// otherwise learn that a named person is under investigation.
    #[tokio::test]
    async fn query_status_requires_a_party_credential() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let (status, _) =
            harness.send(Request::get(format!("/v1/cases/{case_id}/status")).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A stranger who signs correctly is still not a party — and
        // gets the same answer as for a case that does not exist.
        let timestamp = util::format_timestamp(OffsetDateTime::now_utc());
        let message = format!("query-status:{case_id}:{timestamp}");
        let signature = testing::sign(STRANGER_SEED, message.as_bytes());
        let (status, _) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("x-onym-key", testing::key_reference(STRANGER_SEED))
                    .header("x-onym-timestamp", &timestamp)
                    .header("x-onym-signature", signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The accused can read their own case.
        let signature = testing::sign(ACCUSED_SEED, message.as_bytes());
        let (status, body) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("x-onym-key", testing::key_reference(ACCUSED_SEED))
                    .header("x-onym-timestamp", &timestamp)
                    .header("x-onym-signature", signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["stage"], "open");
        // The reporter's identity is never in the answer (§5.4).
        assert!(!body.to_string().contains(&testing::key_reference(REPORTER_SEED)));

        let stale = "2020-01-01T00:00:00Z";
        let stale_signature = testing::sign(
            ACCUSED_SEED,
            format!("query-status:{case_id}:{stale}").as_bytes(),
        );
        let (status, _) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("x-onym-key", testing::key_reference(ACCUSED_SEED))
                    .header("x-onym-timestamp", stale)
                    .header("x-onym-signature", stale_signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a logged old credential must not replay");
    }

    // ─── Manifest snapshots ──────────────────────────────────────────

    /// A case is judged by the terms the accused actually consented
    /// to. Republishing the manifest with a longer response window must
    /// not re-term the people who consented before it — their mandate
    /// pinned different bytes, and those bytes are what they agreed to.
    #[tokio::test]
    async fn a_case_uses_the_terms_its_mandate_pinned_not_the_published_ones() {
        let harness = Harness::new();

        // The accused consented to a manifest declaring a 30-day
        // response window for csam; the published one declares 3.
        let consented_manifest =
            crate::testing::MANIFEST_JSON.replace("\"responseWindow\": \"P3D\"", "\"responseWindow\": \"P30D\"");
        assert_ne!(consented_manifest, crate::testing::MANIFEST_JSON);
        harness
            .state
            .store
            .put_mandate(
                &crate::store::MandateRecord {
                    mandate_ref: "mandate-consented".into(),
                    user_key: testing::key_reference(ACCUSED_SEED),
                    device_binding: "device-2".into(),
                    classes: vec!["csam".into()],
                    manifest_hash: util::sha256_hex(consented_manifest.as_bytes()),
                },
                b"{}",
                consented_manifest.as_bytes(),
                "2026-08-01T00:00:00Z",
            )
            .unwrap();

        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");

        let case = harness
            .state
            .store
            .case(response["caseId"].as_str().unwrap())
            .unwrap()
            .unwrap();
        let opened = util::parse_timestamp(&case.opened_at).unwrap();
        let deadline = util::parse_timestamp(&case.response_deadline).unwrap();
        assert_eq!(
            (deadline - opened).whole_days(),
            30,
            "the case must hold the window the accused consented to, not the published one"
        );
    }

    #[tokio::test]
    async fn a_missing_old_snapshot_never_falls_forward_to_different_terms() {
        let harness = Harness::new();
        let consented_manifest =
            crate::testing::MANIFEST_JSON.replace("\"responseWindow\": \"P3D\"", "\"responseWindow\": \"P30D\"");
        let manifest_hash = util::sha256_hex(consented_manifest.as_bytes());
        harness
            .state
            .store
            .put_mandate(
                &crate::store::MandateRecord {
                    mandate_ref: "legacy-without-snapshot".into(),
                    user_key: testing::key_reference(ACCUSED_SEED),
                    device_binding: "device-2".into(),
                    classes: vec!["csam".into()],
                    manifest_hash: manifest_hash.clone(),
                },
                b"{}",
                consented_manifest.as_bytes(),
                "2026-08-01T00:00:00Z",
            )
            .unwrap();
        harness.state.store.remove_manifest_snapshot(&manifest_hash).unwrap();

        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{response}");
        assert!(
            harness
                .state
                .store
                .open_case_for(&testing::key_reference(ACCUSED_SEED), "csam")
                .unwrap()
                .is_none()
        );
    }

    /// Checking party membership before the signature answered a
    /// question the caller had proved no right to ask: a non-party key
    /// got 404 and a party key with a bad signature got 401, so anyone
    /// holding a case id could learn whether a given key is a party to
    /// it. Every failure now looks the same.
    #[tokio::test]
    async fn query_status_does_not_reveal_party_membership_without_a_signature() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let bogus = testing::sign(STRANGER_SEED, b"some other message");
        let ask = |key: [u8; 32]| {
            Request::get(format!("/v1/cases/{case_id}/status"))
                .header("x-onym-key", testing::key_reference(key))
                .header("x-onym-timestamp", "2026-08-08T00:00:00Z")
                .header("x-onym-signature", &bogus)
                .body(Body::empty())
                .unwrap()
        };

        // The accused, with a signature that does not verify.
        let (party, _) = harness.send(ask(ACCUSED_SEED)).await;
        // A stranger, with the same bad signature.
        let (stranger, _) = harness.send(ask(STRANGER_SEED)).await;
        // A case that does not exist at all.
        let (missing, _) = harness
            .send(
                Request::get("/v1/cases/case-nope/status")
                    .header("x-onym-key", "onym:key:00")
                    .header("x-onym-timestamp", "2026-08-08T00:00:00Z")
                    .header("x-onym-signature", "x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

        assert_eq!(party, StatusCode::NOT_FOUND);
        assert_eq!(stranger, StatusCode::NOT_FOUND);
        assert_eq!(missing, StatusCode::NOT_FOUND);
        assert_eq!(
            party, stranger,
            "a party with a bad signature must be indistinguishable from a non-party"
        );
    }

    /// Two reports arriving together must not open two cases: each
    /// would set a mark before anyone decided anything.
    #[tokio::test]
    async fn concurrent_reports_open_exactly_one_case() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // Same accused and class, two distinct reports, filed together.
        let first = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let second = signed(report_json(&reporter_mandate, "r-2"), "signature", &[REPORTER_SEED]);
        let (a, b) = tokio::join!(
            harness.post("/v1/reports", first),
            harness.post("/v1/reports", second)
        );
        assert_eq!(a.0, StatusCode::OK, "{}", a.1);
        assert_eq!(b.0, StatusCode::OK, "{}", b.1);
        assert_eq!(a.1["caseId"], b.1["caseId"], "both reports must join one case");

        // And exactly one open-case verdict was issued, so exactly one
        // mark was ever authorized.
        let queued = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(queued.len(), 1, "one case opening, one interim verdict");
    }

    /// The store refuses a second open case for the same accused and
    /// class outright — the race above is settled there, not by
    /// hoping the check-then-act window stays narrow.
    #[test]
    fn the_store_refuses_a_second_open_case_for_the_same_accused_and_class() {
        let store = Store::in_memory().unwrap();
        let case = |case_id: &str| crate::store::CaseRecord {
            case_id: case_id.into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
        };
        for report_id in ["r1", "r2", "r3"] {
            store
                .put_report(
                    report_id,
                    "onym:key:rep",
                    "onym:key:acc",
                    "csam",
                    None,
                    1.0,
                    b"{}",
                    "t0",
                )
                .unwrap();
        }
        assert!(store
            .open_case_atomically(
                &case("c1"),
                "onym:key:rep",
                "r1",
                "v1",
                "open-case",
                b"{}",
                "t0",
                "v1",
                "sha256:test-evidence",
            )
            .unwrap());
        assert_eq!(
            store.report("onym:key:rep", "r1").unwrap().unwrap().case_id.as_deref(),
            Some("c1"),
            "the opening report is attached in the transaction that exposes the verdict"
        );
        assert!(
            !store
                .open_case_atomically(
                    &case("c2"),
                    "onym:key:rep",
                    "r2",
                    "v2",
                    "open-case",
                    b"{}",
                    "t0",
                    "v2",
                    "sha256:test-evidence",
                )
                .unwrap(),
            "a second open case for the same accused and class is refused"
        );

        // Once the first is decided, a later case may open.
        let mut decided = case("c1");
        decided.stage = "decided".into();
        decided.disposition = Some("dismiss".into());
        store.put_case(&decided).unwrap();
        assert!(store
            .open_case_atomically(
                &case("c3"),
                "onym:key:rep",
                "r3",
                "v3",
                "open-case",
                b"{}",
                "t1",
                "v3",
                "sha256:test-evidence",
            )
            .unwrap());
    }

    /// `appeal` bounded its statement and `respond` did not. Same
    /// untrusted free text, same store.
    #[tokio::test]
    async fn a_response_statement_is_bounded_like_an_appeal_is() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let body = signed(
            json!({
                "caseId": case_id,
                "statement": "x".repeat(MAX_STATEMENT_BYTES + 1),
                "evidence": [],
            }),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/respond"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }


    /// The probe the confidentiality story stands or falls on: no
    /// credentials at all, on a real case and an invented one. If those
    /// two answers differ, a case id alone tells a stranger that a
    /// named person is under investigation — and every endpoint taking
    /// a case id is a place to ask.
    #[tokio::test]
    async fn no_endpoint_reveals_whether_a_case_exists_to_an_unauthenticated_caller() {
        let harness = Harness::new();
        let real = open_case(&harness).await;
        let invented = "case-00000000-0000-0000-0000-000000000000".to_string();

        // query-status, with nothing at all.
        let mut status = Vec::new();
        for id in [&real, &invented] {
            status.push(
                harness
                    .send(Request::get(format!("/v1/cases/{id}/status")).body(Body::empty()).unwrap())
                    .await
                    .0,
            );
        }
        assert_eq!(status[0], status[1], "query-status leaks existence");

        // respond, signed by someone who is not the accused.
        let mut responded = Vec::new();
        for id in [&real, &invented] {
            let body = signed(
                json!({"caseId": id, "statement": "not me", "evidence": []}),
                "signature",
                &[STRANGER_SEED],
            );
            responded.push(harness.post(&format!("/v1/cases/{id}/respond"), body).await.0);
        }
        assert_eq!(responded[0], responded[1], "respond leaks existence");

        // appeal, likewise.
        let mut appealed = Vec::new();
        for id in [&real, &invented] {
            let body = signed(
                json!({"caseId": id, "kind": "appeal", "statement": "wrong"}),
                "signature",
                &[STRANGER_SEED],
            );
            appealed.push(harness.post(&format!("/v1/cases/{id}/appeal"), body).await.0);
        }
        assert_eq!(appealed[0], appealed[1], "appeal leaks existence");

        // And the new-holder path, which is unauthenticated by design.
        // The real case here is open, not banned, so a distinguishable
        // refusal would disclose its disposition.
        let mut claimed = Vec::new();
        for id in [&real, &invented] {
            let body = serde_json::to_vec(&json!({
                "caseId": id,
                "kind": "new-holder-claim",
                "statement": "I bought this device secondhand",
            }))
            .unwrap();
            claimed.push(harness.post(&format!("/v1/cases/{id}/appeal"), body).await.0);
        }
        assert_eq!(claimed[0], claimed[1], "the new-holder path leaks the disposition");
    }


    /// A response wrote the whole case row back from a record read
    /// before the lock, so one arriving between a decider's read and
    /// its commit put the case back to `open` with its disposition
    /// erased. The deadline sweep would then find it overdue and
    /// dismiss it by default — clearing a ban already in force and
    /// taking the appeal deadline the accused was owed with it.
    #[tokio::test]
    async fn a_response_cannot_reopen_a_decided_case() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        // Decide it.
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"})).await;
        let decided = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(decided.stage, "decided");

        // A response filed against it — signed correctly, just late to
        // the decision.
        let body = signed(
            json!({"caseId": case_id, "statement": "wait, it wasn't me", "evidence": []}),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/respond"), body).await;
        assert_eq!(status, StatusCode::CONFLICT);

        let after = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(after.stage, "decided", "the case must not be reopened");
        assert_eq!(after.disposition.as_deref(), Some("ban"));
        assert_eq!(
            after.appeal_deadline, decided.appeal_deadline,
            "the appeal deadline the accused was owed must survive"
        );
    }

    /// Standing follows any mandate this key registered, not only the
    /// newest. A reporter who re-consents after a manifest is
    /// republished has not withdrawn the consent they already gave, and
    /// reports already signed against it are still theirs.
    #[tokio::test]
    async fn a_report_signed_against_an_earlier_mandate_still_has_standing() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let first = register_mandate(&harness, REPORTER_SEED).await;

        // The reporter re-registers: same key, a later mandate.
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);
        let mut later =
            mandate_json(REPORTER_SEED, json!(["csam"]), &manifest_hash);
        later["acceptedAt"] = json!("2026-08-02T00:00:00Z");
        let (status, response) = harness
            .post("/v1/mandates", signed(later, "signatures", &[REPORTER_SEED, INTERFACE_SEED]))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(response["mandateRef"].as_str().unwrap(), first);

        // A report signed against the *earlier* mandate is still theirs.
        let body = signed(report_json(&first, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    /// `/health` is unauthenticated and proxied on every path, so the
    /// interface's error bodies — which echo case ids and verdict
    /// fields — must not be published on it.
    #[tokio::test]
    async fn health_publishes_the_count_of_stuck_verdicts_but_not_their_detail() {
        let harness = Harness::new();

        let (status, public) =
            harness.send(Request::get("/health").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(public["undeliverableVerdicts"].is_number(), "a monitor needs the count");
        assert!(public["undeliverable"].is_null(), "and nothing more");

        let (_, moderator) = harness
            .send(
                Request::get("/health")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(moderator["undeliverable"].is_array(), "the operator gets the detail");
    }

    #[tokio::test]
    async fn a_moderator_can_requeue_a_repaired_delivery_refusal() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        let (status, response) = harness
            .decide(&case_id, json!({"disposition": "ban", "reasoning": "hash:f"}))
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");

        let queued = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(queued.len(), 1);
        let verdict_ref = queued[0].verdict_ref.clone();
        harness.state.store.mark_undeliverable(&verdict_ref).unwrap();

        let path = format!("/v1/verdicts/{verdict_ref}/requeue");
        let (status, _) = harness
            .send(Request::post(&path).body(Body::empty()).unwrap())
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = harness
            .send(
                Request::post(&path)
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["requeued"], true);
        assert!(harness.state.store.undeliverable_verdicts().unwrap().is_empty());
        assert_eq!(harness.state.store.undelivered_verdicts().unwrap().len(), 1);
    }


    /// A case past its decision deadline is dismissed by default,
    /// sweep or no sweep. Joining evidence to it moved the horizon
    /// forward on a case the contract had already ended in the
    /// accused's favour — the same race the deciders were fixed for,
    /// reached through intake instead.
    #[tokio::test]
    async fn a_join_cannot_revive_a_case_past_its_decision_deadline() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.decision_deadline = "2020-01-02T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();

        let mut report = report_json(&reporter_mandate, "r-2");
        report["evidence"][0]["disclosedContent"] = json!("a different prohibited thing");
        report["evidence"][0]["authenticityProof"] =
            json!(testing::sign(ACCUSED_SEED, b"a different prohibited thing"));
        let (status, _) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;

        assert_eq!(status, StatusCode::GONE);
        let after = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(
            after.decision_deadline, "2020-01-02T00:00:00Z",
            "the horizon must not move on a case that is already over"
        );
    }

    /// The same accused-signed material under a fresh report id used to
    /// produce a fresh notice and restart the accused's windows, so a
    /// reporter could hold a case — and its mark — open indefinitely
    /// without alleging anything new.
    #[tokio::test]
    async fn re_filing_the_same_evidence_joins_without_a_new_notice() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;
        let before = harness.state.store.case(&case_id).unwrap().unwrap();

        // Same evidence, new report id.
        let body = signed(report_json(&reporter_mandate, "r-2"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["caseId"], case_id, "it still joins the case");

        let after = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(
            after.response_deadline, before.response_deadline,
            "nothing new was alleged, so nothing restarts"
        );
        assert_eq!(
            harness
                .state
                .store
                .events(&case_id)
                .unwrap()
                .iter()
                .filter(|(_, kind, _)| kind == "notice_evidence")
                .count(),
            1,
            "and no second notice was issued"
        );
    }

    /// Each joined report emits its own notice covering only its own
    /// evidence. Checking that the *latest* was delivered let an
    /// undelivered earlier one's allegations sit in the case —
    /// attached, credited, and available to support a ban — while the
    /// accused had never been served with them. Two joins were enough.
    #[tokio::test]
    async fn every_notice_must_be_delivered_not_merely_the_latest() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // The opening notice never reaches the interface.
        harness.state.store.undeliver_open_case_verdicts(&case_id).unwrap();
        let opening = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(opening.len(), 1);
        let opening_ref = opening[0].verdict_ref.clone();

        // A second report joins, carrying its own notice.
        let mut report = report_json(&reporter_mandate, "r-2");
        report["evidence"][0]["disclosedContent"] = json!("a different prohibited thing");
        report["evidence"][0]["authenticityProof"] =
            json!(testing::sign(ACCUSED_SEED, b"a different prohibited thing"));
        let (status, _) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;
        assert_eq!(status, StatusCode::OK);

        // The later notice lands; the opening one is still queued.
        for queued in harness.state.store.undelivered_verdicts().unwrap() {
            if queued.verdict_ref != opening_ref {
                harness.state.store.mark_delivered(&queued.verdict_ref).unwrap();
            }
        }

        assert!(
            !harness.state.store.open_case_verdict_delivered(&case_id).unwrap(),
            "an unserved allegation is still unserved, whatever landed after it"
        );

        // Serve it, and only then is the case fully noticed.
        harness.state.store.mark_delivered(&opening_ref).unwrap();
        assert!(harness.state.store.open_case_verdict_delivered(&case_id).unwrap());
    }

}
