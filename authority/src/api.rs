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
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "authority": state.config.manifest.component_id,
        "signingKey": util::key_reference(state.signing_key.verifying_key().as_bytes()),
        "manifestHash": util::sha256_hex(&state.config.manifest_raw),
        "interfaceConfigured": state.delivery.configured(),
        "canDecide": state.config.moderator_token.is_some(),
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
        // No interface key configured: accept, but say so. A deployment
        // that never sets one cannot tell a real designation from a
        // forged one.
        (None, _) => tracing::warn!(
            "AUTHORITY_INTERFACE_KEY is unset; accepting a mandate without checking the \
             interface countersignature"
        ),
    }

    let mandate_ref = util::sha256_hex(&signing_bytes);
    state.store.put_mandate(
        &crate::store::MandateRecord {
            mandate_ref: mandate_ref.clone(),
            user_key: mandate.user.clone(),
            device_binding: mandate.device_binding.clone(),
            classes: mandate.classes.clone(),
        },
        &body,
        &util::format_timestamp(OffsetDateTime::now_utc()),
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

    // Standing follows the reporter's mandate: reporting requires
    // having consented to this authority too.
    let reporter_mandate = state
        .store
        .mandate_for_user(&report.reporter)?
        .ok_or(Error::ReporterUnconsented)?;
    if reporter_mandate.mandate_ref != report.reporter_mandate {
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

    // The class must be one the accused consented to and one we declare.
    if !accused_mandate.classes.iter().any(|c| c == &report.class_id) {
        return Err(Error::ClassOutsideMandate(report.class_id.clone()));
    }
    let class = state
        .config
        .manifest
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

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);
    let weight = state.store.reporter(&report.reporter)?.weight();

    // Further reports join an open case rather than opening a second
    // one. Opening a case sets a mark before any response, so
    // duplicate cases would be a way to punish without deciding.
    let case = match state.store.open_case_for(&report.accused, &report.class_id)? {
        Some(existing) => {
            state.store.append_event(
                &existing.case_id,
                &stamp,
                "report_joined",
                &format!("report {} joined the open case", report.report_id),
            )?;
            existing
        }
        None => open_case(&state, &report, &accused_mandate, &class, now).await?,
    };

    state.store.put_report(
        &report.report_id,
        &report.reporter,
        &report.accused,
        &report.class_id,
        Some(&case.case_id),
        weight,
        &body,
        &stamp,
    )?;

    Ok(Json(json!({
        "reportId": report.report_id,
        "caseId": case.case_id,
        "intakeWeight": weight,
        // The notice the accused is owed, so the interface can serve it.
        "responseDeadline": case.response_deadline,
        "decisionDeadline": case.decision_deadline,
    })))
}

/// Open a case: set the deadlines the manifest declares, issue the
/// interim `open-case` verdict, and hand it to the interface.
async fn open_case(
    state: &AppState,
    report: &Report,
    accused_mandate: &crate::store::MandateRecord,
    class: &ViolationClass,
    now: OffsetDateTime,
) -> Result<CaseRecord, Error> {
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
    state.store.put_case(&case)?;

    let issued = cases::open_case_verdict(
        &case,
        &state.config.manifest.component_id,
        &format!("intake: report {}", report.report_id),
        now,
        &state.signing_key,
    )?;
    let stamp = util::format_timestamp(now);
    state
        .store
        .put_verdict(&issued.verdict_ref, &case.case_id, &issued.disposition, &issued.raw, &stamp)?;
    state
        .store
        .append_event(&case.case_id, &stamp, "case_opened", &issued.verdict_ref)?;

    state.delivery.flush(&state.store).await?;
    tracing::info!(case_id = %case.case_id, "case opened");
    Ok(case)
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
    let mut case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;
    if case.stage != "open" {
        return Err(Error::CaseState("case is already decided".into()));
    }

    let signing_bytes = canonical::report_signing_bytes(&body)?;
    verify_signature(&case.accused, &signing_bytes, &response.signature)
        .map_err(|_| Error::SignatureInvalid("accused signature did not verify".into()))?;

    let now = OffsetDateTime::now_utc();
    let stamp = util::format_timestamp(now);
    let late = util::parse_timestamp(&case.response_deadline)
        .map(|deadline| now > deadline)
        .unwrap_or(false);

    case.responded = true;
    state.store.put_case(&case)?;
    state.store.append_event(
        &case_id,
        &stamp,
        if late { "response_late" } else { "response" },
        &response.statement,
    )?;

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
    let case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    let new_holder = submission.kind == "new-holder-claim";

    // A new holder is, by definition, not the mandated identity, so
    // their claim cannot be signature-checked against it. Everyone else
    // must sign.
    if !new_holder {
        let signing_bytes = canonical::report_signing_bytes(&body)?;
        verify_signature(&case.accused, &signing_bytes, &submission.signature)
            .map_err(|_| Error::SignatureInvalid("accused signature did not verify".into()))?;

        // Late filing of an appeal is refused (§10 `window_closed`).
        // The new-holder path is not bounded this way: it stays open
        // for as long as the ban runs.
        if let Some(deadline) = case.appeal_deadline.as_deref() {
            let deadline = util::parse_timestamp(deadline)
                .map_err(|e| Error::Internal(format!("stored appealDeadline: {e}")))?;
            if OffsetDateTime::now_utc() > deadline {
                return Err(Error::WindowClosed("the appeal window has closed".into()));
            }
        }
    }

    let stamp = util::format_timestamp(OffsetDateTime::now_utc());
    state.store.append_event(
        &case_id,
        &stamp,
        if new_holder { "new_holder_claim" } else { "appeal_filed" },
        &submission.statement,
    )?;

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
) -> Result<Json<Value>, Error> {
    let case = state
        .store
        .case(&case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;
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

    let issued = match decision.disposition.as_str() {
        "dismiss" => {
            if case.stage != "open" {
                return Err(Error::CaseState("case is already decided".into()));
            }
            // Notice must precede sanction, but a dismissal is not a
            // sanction — it can land any time before the deadline.
            state.store.record_report_outcome(&case.reporter, false)?;
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
            // Notice and the response window must have elapsed before
            // any ban verdict (§8 obligation 4). The case-open mark is
            // the only pre-verdict effect this authority may have.
            let response_deadline = util::parse_timestamp(&case.response_deadline)
                .map_err(|e| Error::Internal(format!("stored responseDeadline: {e}")))?;
            if now < response_deadline && !case.responded {
                return Err(Error::CaseState(format!(
                    "the response window runs until {}; a ban before it closes is nonconforming",
                    case.response_deadline
                )));
            }
            let class = state
                .config
                .manifest
                .violation_class(&case.class_id)
                .ok_or_else(|| Error::ClassOutsideMandate(case.class_id.clone()))?;
            state.store.record_report_outcome(&case.reporter, true)?;
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

    state
        .store
        .put_verdict(&issued.verdict_ref, &case_id, &issued.disposition, &issued.raw, &stamp)?;

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
    state.store.put_case(&case)?;
    state
        .store
        .append_event(&case_id, &stamp, "decided", &decision.disposition)?;

    state.delivery.flush(&state.store).await?;

    tracing::info!(%case_id, verdict_ref = %issued.verdict_ref, disposition = %issued.disposition, "case decided");
    Ok(Json(json!({
        "caseId": case_id,
        "verdictRef": issued.verdict_ref,
        "disposition": issued.disposition,
    })))
}

// ─── Helpers ─────────────────────────────────────────────────────────

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
