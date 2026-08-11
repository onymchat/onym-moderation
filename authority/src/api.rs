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
use axum::routing::{get, post, put};
use axum::{Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::canonical;
use crate::cases;
use crate::decisions;
use crate::media;
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
        .route("/v1/cases/mine", get(list_my_cases))
        .route("/v1/recovery-claims", post(file_recovery_claim))
        .route("/v1/recovery-claims/:claim_id", get(recovery_claim_status))
        .route("/v1/cases/:case_id/status", get(query_status))
        .route("/v1/cases/:case_id/decide", post(decide))
        .route("/v1/verdicts/:verdict_ref/requeue", post(requeue_verdict))
        .with_state(state)
}

/// Evidence bytes, on their own router because they need their own body
/// ceiling.
///
/// Kept separate so the caller can apply the 1 MiB JSON limit to every
/// other route and merge this afterwards. The alternative — raising the
/// global limit until an image fits — would hand every JSON endpoint a
/// megabytes-wide surface it has no use for.
pub fn evidence_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/evidence-blobs/:sha256", put(put_evidence_blob))
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            media::MAX_EVIDENCE_BLOB_BYTES,
        ))
        .with_state(state)
}

/// Freshness window for an evidence-upload credential, matching the
/// status-query window.
const UPLOAD_CREDENTIAL_MAX_AGE_SECONDS: i64 = 300;

/// How many uploads one key may hold that no report has claimed.
///
/// Generous next to any real reporting session — a report discloses one
/// photo — and small enough that the worst a consented key can park on
/// this authority is bounded rather than open-ended.
const MAX_UNREFERENCED_UPLOADS_PER_KEY: usize = 16;

/// How many evidence images may be decoded at once.
///
/// Bounds total decode memory rather than only per-request: the
/// per-image ceiling is what one upload can allocate, this is how many
/// can allocate it simultaneously.
static DECODE_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Classes that do not accept media evidence.
///
/// `csam` is refused on purpose, and the refusal is about this
/// authority's readiness rather than the report's merit. Accepting the
/// bytes would make it a custodian of illegal imagery — stored,
/// rendered to human reviewers on appeal — while it still has no
/// retention schedule, no deletion machinery beyond the minimum below,
/// and no statutory-reporting path. The honest disposition is to say so
/// and point at lawful reporting channels, not to take custody it
/// cannot discharge. Text reports for the class are unaffected.
const CLASSES_REFUSING_MEDIA: [&str; 1] = ["csam"];

/// Check every media commitment in a report against the bytes on file.
///
/// Returns the digests the report depends on, in evidence order, so the
/// caller can bind them to the case.
fn verify_media_evidence(
    state: &AppState,
    class_id: &str,
    evidence: &[EvidenceItem],
    already_on_case: usize,
) -> Result<Vec<String>, Error> {
    // Three passes, in this order, and the order is the point.
    //
    // Everything here is attacker-chosen: the commitment is written by
    // the accused, so its length is theirs to pick. Bounds therefore
    // come first, before anything that costs a query. Refusals come
    // second, so a refusal deletes every blob the filing named rather
    // than only the ones seen before the first `return`. Resolution
    // comes last.
    let mut committed: Vec<(usize, media::MediaCommitment)> = Vec::new();
    for (index, item) in evidence.iter().enumerate() {
        if let media::Disclosed::Media(commitments) =
            media::parse_disclosed(&item.disclosed_content)?
        {
            for commitment in commitments {
                committed.push((index, commitment));
            }
            // Bound as we go, so a preimage naming ten thousand blobs
            // is refused while reading it rather than after.
            if committed.len() > media::MAX_MEDIA_PER_FILING {
                return Err(Error::BadRequest(format!(
                    "this filing commits to more than {} media items",
                    media::MAX_MEDIA_PER_FILING
                )));
            }
        }
    }
    if committed.is_empty() {
        return Ok(Vec::new());
    }
    // A ceiling across the case, not just this filing. Reports join an
    // open case and responses accumulate on one, so the per-filing
    // bound alone left a case able to gather hundreds of images, every
    // one of them resolved on each document build.
    if already_on_case + committed.len() > media::MAX_MEDIA_PER_CASE {
        return Err(Error::BadRequest(format!(
            "this case already rests on {already_on_case} images; the ceiling is {}",
            media::MAX_MEDIA_PER_CASE
        )));
    }

    // Refusals. Both delete every blob this filing named — bytes
    // arrived before anything knew what they would be claimed as, so
    // this authority is holding them, and the honest remedy is to hold
    // them for this request rather than for the expiry window. Only
    // blobs no case rests on: a digest a live case depends on is not
    // this filing's to take.
    let refusal = if CLASSES_REFUSING_MEDIA.contains(&class_id) {
        Some(format!(
            "class {class_id:?} does not accept media evidence at this authority"
        ))
    } else if state.config.triage.as_ref().is_some_and(|t| !t.profile.supports_images) {
        // The pinned model cannot inspect an image, so this authority
        // cannot adjudicate one. Refusing at intake — rather than
        // taking the evidence and declining to decide later — is what
        // stops image evidence becoming a way to end a case: a case
        // that can never be decided is dismissed at its deadline, and
        // anyone able to file against this accused could reach that by
        // attaching a picture.
        Some(format!(
            "this authority's pinned model profile cannot review images, so it does not accept              image evidence; a text report for {class_id:?} is unaffected"
        ))
    } else {
        None
    };
    if let Some(reason) = refusal {
        let named: Vec<String> =
            committed.iter().map(|(_, c)| c.plaintext_sha256.clone()).collect();
        state.store.delete_unheld_evidence_blobs(&named)?;
        return Err(Error::MediaClassRefused(reason));
    }

    let mut digests = Vec::new();
    for (index, commitment) in committed {
        if !media::ALLOWED_MEDIA_TYPES.contains(&commitment.mime_type.as_str()) {
            return Err(Error::MediaUnsupported(format!(
                "evidence item {index} commits to {:?}, which this authority does not accept",
                commitment.mime_type
            )));
        }
        // Dimensions are required for an image, not optional-and-checked
        // -if-present. They are printed in the case document and in the
        // panel as facts about the evidence, so a commitment that
        // omitted them would have those numbers attributed to a
        // signature that never covered them.
        let (Some(width), Some(height)) = (commitment.width, commitment.height) else {
            return Err(Error::AuthenticityUnverified(format!(
                "evidence item {index} commits to an image without dimensions; they are shown                  as attested and must be signed"
            )));
        };
        let stored = state.store.evidence_blob(&commitment.plaintext_sha256)?.ok_or_else(|| {
            Error::MediaMissing(format!(
                "evidence item {index} names an image that has not been uploaded"
            ))
        })?;

        // Every field the accused signed must match what is on file. A
        // mismatch is an authenticity failure, not a format one: the
        // bytes may be a perfectly good image, just not the one this
        // proof attests to.
        let mismatch = stored.mime_type != commitment.mime_type
            || stored.byte_length != commitment.plaintext_byte_length
            || width != stored.width
            || height != stored.height;
        if mismatch {
            return Err(Error::AuthenticityUnverified(format!(
                "evidence item {index} does not match the image it commits to"
            )));
        }
        digests.push(stored.sha256);
    }
    Ok(digests)
}

/// Accept the bytes of one reported image.
///
/// The path segment is the SHA-256 the caller claims, and the first
/// thing this does is recompute it. That check — not the credential
/// below — is what makes the upload safe to accept: a report can only
/// use these bytes by presenting the accused's signature over this same
/// digest, so bytes that hash to something else are simply not the
/// reported photo.
///
/// The credential exists for a narrower reason: uploading is the one
/// operation here that costs storage before any report justifies it, so
/// it is restricted to keys that have consented to this authority, and
/// bounded per key. That is resource control, not the integrity story.
async fn put_evidence_blob(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    let credential = |name: &'static str| headers.get(name).and_then(|value| value.to_str().ok());
    let (Some(key), Some(timestamp), Some(signature)) = (
        credential("x-onym-key"),
        credential("x-onym-timestamp"),
        credential("x-onym-signature"),
    ) else {
        return Err(Error::SignatureInvalid("evidence upload is not authenticated".into()));
    };
    let now = OffsetDateTime::now_utc();
    let fresh = util::parse_timestamp(timestamp)
        .map(|signed_at| {
            (now - signed_at).whole_seconds().abs() <= UPLOAD_CREDENTIAL_MAX_AGE_SECONDS
        })
        .unwrap_or(false);
    let message = format!("evidence-blob:{sha256}:{timestamp}");
    if !fresh || verify_signature(key, message.as_bytes(), signature).is_err() {
        return Err(Error::SignatureInvalid("evidence upload credential did not verify".into()));
    }
    if state.store.mandates_for_user(key)?.is_empty() {
        return Err(Error::ReporterUnconsented);
    }
    // Consent alone is not a budget. Without this a single consented key
    // can push unlimited blobs into the store and wait for nothing —
    // uploads are only reclaimed a day later, and only if no report ever
    // named them. The bound is on *unreferenced* uploads, so a reporter
    // filing real reports is never blocked by their own history; only
    // one accumulating bytes they never report is.
    // Bytes already on file cost nothing new, and re-sending them is
    // the documented recovery path — so the cap must not be the thing
    // that breaks it. Checked before the bound, not after.
    let already_stored = state.store.evidence_blob(&sha256)?.is_some();
    if !already_stored && state.store.unreferenced_uploads_by(key)? >= MAX_UNREFERENCED_UPLOADS_PER_KEY {
        return Err(Error::MediaQuotaExceeded(format!(
            "this key already holds {MAX_UNREFERENCED_UPLOADS_PER_KEY} uploads no case rests \
             on; file or abandon those before uploading more"
        )));
    }

    // Validate and normalize before anything is persisted, so a
    // decompression bomb is a rejected request rather than a row.
    //
    // Off the async runtime, and behind a permit. Decoding a 24-megapixel
    // image and resizing it is hundreds of milliseconds of CPU and a
    // ~96 MB allocation; inline on a tokio worker it blocks a thread
    // that is supposed to be handling every other request, and nothing
    // bounded how many ran at once.
    let _permit = DECODE_PERMITS
        .acquire()
        .await
        .map_err(|_| Error::Internal("decode permits closed".into()))?;
    let decode_input = body.clone();
    let accepted = tokio::task::spawn_blocking(move || media::accept_image(&decode_input))
        .await
        .map_err(|e| Error::Internal(format!("evidence decode task failed: {e}")))??;
    if !sha256.eq_ignore_ascii_case(&accepted.sha256) || sha256 != sha256.to_lowercase() {
        return Err(Error::BadRequest(format!(
            "uploaded bytes hash to {}, not the {sha256:?} in the path",
            accepted.sha256
        )));
    }

    state.store.put_evidence_blob(&accepted, &body, &util::format_timestamp(now), key)?;

    Ok(Json(json!({
        "sha256": accepted.sha256,
        "mimeType": accepted.mime_type,
        "byteLength": accepted.byte_length,
        "width": accepted.width,
        "height": accepted.height,
        "derivativeSha256": accepted.derivative_sha256,
        "derivativeVersion": accepted.derivative_version,
    })))
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
    match (state.config.interface_keys.as_slice(), mandate.signatures.get(1)) {
        // No interface key configured, so a countersignature cannot be
        // checked — and an unverifiable designation is exactly the
        // forgery this check exists to catch. Refuse. Accepting here
        // would let anyone who can reach this endpoint grant us
        // jurisdiction over a user who never consented, which is the
        // one failure that turns a consent-bound authority into an
        // unbounded one.
        ([], _) => {
            tracing::error!(
                "AUTHORITY_INTERFACE_KEY is unset; refusing mandate registration. Set it to the \
                 interface's countersigning key for this authority — its /health `interfaceKey`, \
                 or `rotatedInterfaceKeys[<our componentId>].key` if the interface has rotated \
                 ours."
            );
            return Err(Error::BadRequest(
                "this authority is not configured with an interface countersigning key, so it \
                 cannot verify that the interface witnessed this consent"
                    .into(),
            ));
        }
        (_, None) => {
            return Err(Error::BadRequest(
                "mandate is not countersigned by the interface".into(),
            ))
        }
        (interface_keys, Some(countersignature)) => {
            // Any configured key. More than one is how a rotation
            // happens without a window in which every registration
            // fails: with a single accepted key there is no order that
            // avoids one — whichever side moves first, registrations
            // break until the other catches up. Listing the incoming
            // key alongside the outgoing one closes that window.
            let witnessed = interface_keys.iter().any(|interface_key| {
                verify_signature(interface_key, &signing_bytes, countersignature).is_ok()
            });
            if !witnessed {
                return Err(Error::SignatureInvalid(
                    "interface countersignature did not verify against any configured interface \
                     key"
                        .into(),
                ));
            }
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

    // Media evidence: the signed commitment names bytes, and those
    // bytes have to be here and be the ones named. The signature check
    // above already proved the accused wrote the commitment; this proves
    // the authority is holding what the commitment describes.
    // Counted against the case this report will join, if one is open.
    // Reports join rather than open a second case, so passing zero here
    // left the case-wide ceiling dead on the path that actually
    // accumulates: every joining report added its own filing's worth
    // with nothing bounding the total.
    let joining = state.store.open_case_for(&report.accused, &report.class_id)?;
    let already_on_case = match &joining {
        Some(case) => state.store.case_media_count(&case.case_id)?,
        None => 0,
    };
    let media_digests =
        verify_media_evidence(&state, &report.class_id, &report.evidence, already_on_case)?;

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
    // The report is on file; its case does not exist yet. Restart the
    // uploads' expiry clock so they survive that gap — including the
    // paths just below that return an error inside it, a lapsed
    // manifest and an expired mandate.
    if !media_digests.is_empty() {
        state.store.touch_evidence_blobs(&media_digests, &stamp)?;
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
    let case = match joining {
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
    if !media_digests.is_empty() {
        state.store.attach_evidence_blobs(&case.case_id, &media_digests)?;
    }

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
    if already_noticed {
        let attached = state.store.attach_noticed_report(
            &report.reporter,
            &report.report_id,
            &existing.case_id,
            &util::format_timestamp(now),
            evidence_summary,
            &format!(
                "report {} joined without a new notice: its evidence is already before the accused",
                report.report_id
            ),
        )?;
        if !attached {
            return Err(Error::CaseState(
                "the case stopped accepting this joined report while it was being filed; retry"
                    .into(),
            ));
        }
        return Ok(existing.clone());
    }
    if notices >= MAX_NOTICES_PER_CASE {
        // New evidence may not become adjudicable without notice. Keep
        // the stored report unattached so retrying after this case
        // closes can open a later case with full windows.
        return Err(Error::CaseState(format!(
            "case {} has reached its notice limit; retry this report after the case closes",
            existing.case_id
        )));
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
        MAX_NOTICES_PER_CASE,
    )?;
    if !joined {
        return Err(Error::CaseState(
            "the case no longer accepts a new notice (it closed, reached its notice limit, or \
             the evidence was concurrently noticed); retry the report"
                .into(),
        ));
    }
    crate::delivery::flush_soon(state);
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
        appeal_state: "none".into(),
        new_holder_state: "none".into(),
        revision: 0,
        claim_revision: 0,
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

    crate::delivery::flush_soon(state);
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

    // Counter-evidence carrying media goes through exactly the checks
    // the report's evidence did. The accused answering a photo with a
    // photo is the same kind of claim, and it earns the same scrutiny.
    let media_digests = verify_media_evidence(
        &state,
        &case.class_id,
        &response.evidence,
        state.store.case_media_count(&case_id)?,
    )?;

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
    if !media_digests.is_empty() {
        state.store.touch_evidence_blobs(&media_digests, &stamp)?;
        state.store.attach_evidence_blobs(&case_id, &media_digests)?;
    }

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
            // Bounded, logged, and queued in one write. The count and
            // the insert share a lock because this endpoint is
            // unauthenticated and a concurrent burst would otherwise
            // overrun the cap; the queue state is its own field
            // because a claim is not an appeal, and writing the
            // appeal's would let a stranger swallow the accused's.
            let _ = state.store.record_new_holder_claim(
                &case_id,
                &stamp,
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

    // This is where a human enters. Triage decides in the first
    // instance; an appeal puts the file in the moderator panel's
    // queue. (New-holder claims returned above — they are tracked in
    // their own field, because they are not appeals.)
    //
    // Two rules, from two different findings, and they compose:
    //
    // - A *decided* review is not re-opened by filing again. Resetting
    //   `appeal_state` to `pending` let an accused flip an `upheld` —
    //   or even a `reversed` — back into the queue, erasing the record
    //   of a review that did happen.
    // - A *pending* one may be supplemented. The accused may find more
    //   to say while waiting, and refusing that would make the first
    //   filing their only chance; the count is bounded so the case log
    //   cannot be used as storage.
    let stamp = util::format_timestamp(OffsetDateTime::now_utc());
    match case.appeal_state.as_str() {
        "none" => {
            // Conditioned on `none`: the case read and this write are
            // separate lock acquisitions, so concurrent first filings
            // could each take this unbounded arm and overrun the cap
            // the "pending" arm enforces. Only one can win now; the
            // rest fall through to the bounded path on retry.
            state.store.set_appeal_state(
                &case_id,
                "pending",
                Some("none"),
                // A filing is not a review, so it pins no revision — it
                // moves one.
                None,
                &stamp,
                "appeal_filed",
                &submission.statement,
            )?;
        }
        "pending" => {
            // Through the claim-aware path: a supplement leaves the
            // appeal `pending` and the case document untouched, so
            // moving the claim revision is the only thing that tells a
            // review rendered before it that it is now out of date.
            let filed = state.store.append_claim_event_bounded(
                &case_id,
                &stamp,
                "appeal_filed",
                &submission.statement,
                MAX_APPEALS_PER_CASE,
            )?;
            if !filed {
                return Err(Error::CaseState(format!(
                    "this case already holds {MAX_APPEALS_PER_CASE} appeal filings; further \
                     material belongs in one of them rather than in another"
                )));
            }
        }
        decided => {
            return Err(Error::CaseState(format!(
                "this case's appeal was already reviewed ({decided}); a decided review is not \
                 re-opened by filing again"
            )))
        }
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

/// Return the signed-in accused identity's banned cases without requiring
/// the user to recover a case ID from an old install. The credential is
/// verified before the identity is used in the query; the response omits
/// reporter, evidence, and event data.
async fn list_my_cases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, Error> {
    let accused = authorize_identity_lookup(&headers)?;
    let cases = state.store.banned_cases_for_accused(&accused)?;
    Ok(Json(cases.into_iter().map(|case| case.case_id).collect()))
}

// ─── Device recovery claims ──────────────────────────────────────────

const MAX_RECOVERY_CONTACT_CHARS: usize = 200;
const MAX_RECOVERY_STATEMENT_CHARS: usize = 4000;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryClaimSubmission {
    /// The claimant's *new* identity key — the one a grant would name.
    grantee: String,
    /// A real way to reach the claimant. A moderator may need to ask
    /// questions before deciding, and a claim that cannot be answered
    /// cannot be verified.
    contact: String,
    /// The claimant's own account of how they came to hold the marked
    /// device — the proof of new-holder status a human weighs.
    statement: String,
    timestamp: String,
    signature: String,
}

/// File a device-recovery claim (§6). The claimant is, by
/// construction, not the mandated identity — their old key is exactly
/// what they lost — so like a new-holder claim this is authenticated
/// only to the *new* key, and bounded rather than trusted: one open
/// claim per key, a capacity cap on the queue, and a human decides.
/// Nothing about filing moves any record anywhere.
async fn file_recovery_claim(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Error> {
    let submission: RecoveryClaimSubmission = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed claim: {e}")))?;

    let now = OffsetDateTime::now_utc();
    let signed_at = util::parse_timestamp(&submission.timestamp)
        .map_err(|e| Error::BadRequest(format!("timestamp: {e}")))?;
    if (now - signed_at).whole_seconds().abs() > STATUS_CREDENTIAL_MAX_AGE_SECONDS {
        return Err(Error::SignatureInvalid("claim timestamp is stale".into()));
    }
    let signing_bytes = canonical::grant_signing_bytes(&body)?;
    verify_signature(&submission.grantee, &signing_bytes, &submission.signature)?;

    let contact = submission.contact.trim();
    let statement = submission.statement.trim();
    if contact.is_empty() || contact.chars().count() > MAX_RECOVERY_CONTACT_CHARS {
        return Err(Error::BadRequest(format!(
            "contact is required, at most {MAX_RECOVERY_CONTACT_CHARS} characters"
        )));
    }
    if statement.is_empty() || statement.chars().count() > MAX_RECOVERY_STATEMENT_CHARS {
        return Err(Error::BadRequest(format!(
            "statement is required, at most {MAX_RECOVERY_STATEMENT_CHARS} characters"
        )));
    }

    let claim = crate::store::RecoveryClaim {
        claim_id: format!("claim-{}", uuid::Uuid::new_v4()),
        grantee: submission.grantee.clone(),
        contact: contact.to_string(),
        statement: statement.to_string(),
        filed_at: util::format_timestamp(now),
        state: "open".into(),
        case_id: None,
        decided_at: None,
        reasoning: None,
        grant_raw: None,
    };
    if !state.store.file_recovery_claim(&claim)? {
        return Err(Error::CaseState(
            "a recovery claim for this identity is already open, or intake is at capacity".into(),
        ));
    }
    tracing::info!(claim_id = %claim.claim_id, "recovery claim filed");
    Ok(Json(json!({
        "claimId": claim.claim_id,
        "state": "open",
        "note": "a human reviews recovery claims; poll this claim with the same identity key",
    })))
}

/// A claimant checking on their claim. Answered only to the key the
/// claim names, with one refusal for a claim that does not exist and a
/// claim that is not theirs. When granted, the response carries the
/// signed grant bytes the device presents to the interface.
async fn recovery_claim_status(
    State(state): State<Arc<AppState>>,
    Path(claim_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let credential = |name: &'static str| headers.get(name).and_then(|value| value.to_str().ok());
    let (Some(key), Some(timestamp), Some(signature)) = (
        credential("x-onym-key"),
        credential("x-onym-timestamp"),
        credential("x-onym-signature"),
    ) else {
        return Err(Error::NotFound(format!("claim {claim_id}")));
    };
    let now = OffsetDateTime::now_utc();
    let fresh = util::parse_timestamp(timestamp)
        .map(|signed_at| {
            (now - signed_at).whole_seconds().abs() <= STATUS_CREDENTIAL_MAX_AGE_SECONDS
        })
        .unwrap_or(false);
    let message = format!("recovery-claim-status:{claim_id}:{timestamp}");
    if !fresh || verify_signature(key, message.as_bytes(), signature).is_err() {
        return Err(Error::NotFound(format!("claim {claim_id}")));
    }
    let claim = state
        .store
        .recovery_claim(&claim_id)?
        .filter(|claim| claim.grantee == key)
        .ok_or_else(|| Error::NotFound(format!("claim {claim_id}")))?;
    Ok(Json(json!({
        "claimId": claim.claim_id,
        "state": claim.state,
        "decidedAt": claim.decided_at,
        "reasoning": claim.reasoning,
        "grant": claim.grant_raw.as_deref().map(util::base64_encode),
    })))
}

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
    let moderator = authorize_moderator(&state, &headers).is_ok();
    let is_accused = headers
        .get("x-onym-key")
        .and_then(|value| value.to_str().ok())
        == Some(case.accused.as_str())
        || moderator;

    let events: Vec<Value> = state
        .store
        .events(&case_id)?
        .into_iter()
        .map(|(at, kind, _detail)| json!({ "at": at, "kind": kind }))
        .collect();

    // The accused is entitled to the record their case was decided on;
    // a reporter is not — it contains the accused's own response.
    //
    // And the accused's copy is *redacted*: the document carries the
    // reporter's own account of the material, which is the reporter
    // writing in their own words, and the identity behind those words
    // is the one thing this endpoint has always withheld. A moderator
    // reading the same case in the panel sees the whole of it, because
    // the authority is allowed to.
    let assessment = if is_accused {
        match state.store.assessment(&case_id)? {
            Some((raw, _)) => {
                let mut value: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                if let Some(object) = value.as_object_mut() {
                    if let Ok(Some(document)) = state.store.assessed_document(&case_id) {
                        let visible = if moderator {
                            document
                        } else {
                            crate::casedoc::redact_report_context(&document)
                        };
                        object.insert("document".into(), Value::String(visible));
                    }
                    // The model's own words can quote what it was
                    // shown. Withholding the reporter's account from
                    // the document and then handing it back inside
                    // `rawOutput` would close one channel and leave the
                    // one beside it open.
                    if !moderator {
                        let contexts = state.store.report_context_for_case(&case_id)?;
                        if let Some(raw) = object.get("rawOutput").and_then(Value::as_str) {
                            let cleaned =
                                crate::casedoc::withhold_quoted_context(raw, &contexts);
                            object.insert("rawOutput".into(), Value::String(cleaned));
                        }
                        // The adapter's own note is generated here, but
                        // it can echo an unreadable output back for
                        // diagnosis, so it gets the same treatment.
                        if let Some(note) = object.get("note").and_then(Value::as_str) {
                            let cleaned =
                                crate::casedoc::withhold_quoted_context(note, &contexts);
                            object.insert("note".into(), Value::String(cleaned));
                        }
                        // And the labels. For a taxonomy read line by
                        // line, *every line after the first* becomes a
                        // label — and on the unknown-code path the
                        // whole unreadable list is kept — so a model
                        // emitting `unsafe` followed by the reporter's
                        // account put it straight into the accused's
                        // copy, through the one field the redaction
                        // did not cover.
                        if let Some(labels) = object.get("labels").and_then(Value::as_array) {
                            let cleaned: Vec<Value> = labels
                                .iter()
                                .map(|label| match label.as_str() {
                                    Some(text) => Value::String(
                                        crate::casedoc::withhold_quoted_context(text, &contexts),
                                    ),
                                    None => label.clone(),
                                })
                                .collect();
                            object.insert("labels".into(), Value::Array(cleaned));
                        }
                    }
                }
                value
            }
            None => Value::Null,
        }
    } else {
        Value::Null
    };

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
        "appealState": case.appeal_state,
        "newHolderState": case.new_holder_state,
        // The token a reviewer posts back with their decision. It moves
        // whenever either claim is filed, supplemented, or answered, so
        // `decide` can refuse a review of a file that has changed since
        // it was read. Nothing about the case is disclosed by it — it
        // counts events the reader can already see in `events`.
        "claimRevision": case.claim_revision,
        // What decided the case, resolved rather than hashed. The
        // verdict's `reasoning` is a content address of exactly this,
        // and without a route that resolves it the promise that a
        // verdict identifies the model, its revision, what it was
        // shown and what it said is a promise nobody can check.
        "assessment": assessment,
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
    /// Which claim this decision answers, when it is a reversal:
    /// `appeal` or `new-holder`. Omitted, a reversal still clears the
    /// marks and anything pending becomes moot — but no review is
    /// recorded against a claim nobody said they read.
    #[serde(default)]
    reviewed: Option<String>,
    /// Whether the decider actually saw the classifier's assessment.
    /// Recorded on the case, so "a human decided this" and "a human
    /// signed off what a model concluded" stay distinguishable. It is
    /// an assertion by the caller, which is the only party that knows.
    #[serde(default)]
    reviewed_assessment: bool,
    /// The case's `claimRevision` when the caller read the claim it is
    /// answering, from `query-status`. Optional, because an API caller
    /// may be acting on a claim it has just been handed — but supplying
    /// it is what makes the decision refuse to commit if the claim
    /// gained a supplementary filing, or was answered by someone else,
    /// in between. The panel always supplies it.
    #[serde(default)]
    claim_revision: Option<i64>,
    /// Required for moderator-issued bans so the accused receives working
    /// appeal and new-holder routes with the signed verdict.
    #[serde(default)]
    appeal_url: Option<String>,
    #[serde(default)]
    new_holder_url: Option<String>,
    #[serde(default)]
    authority_contact: Option<String>,
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

    let disposition = decisions::Disposition::parse(&decision.disposition)?;
    // Unassisted, unless the caller says otherwise. The field exists to
    // tell a user what kind of judgment they got, so it has to record
    // what was actually put in front of the decider — and an API caller
    // may never have seen the assessment at all. Inferring it from the
    // mere existence of an assessment row made the distinction noise:
    // it would have marked a decision "assisted" by an assessment that
    // reached no decision and therefore recommended nothing.
    //
    // The panel sets this, because the panel renders the assessment on
    // the page the moderator decided from.
    let decider = if decision.reviewed_assessment {
        decisions::Decider::HumanAssisted
    } else {
        decisions::Decider::Human
    };

    let issued = match decision.reviewed.as_deref() {
        Some("appeal") => {
            decisions::apply_reviewing(
                &state,
                &case_id,
                disposition,
                &decision.reasoning,
                decider,
                OffsetDateTime::now_utc(),
                decisions::Claim::Appeal,
                decision.claim_revision,
            )
            .await?
        }
        Some("new-holder") => {
            decisions::apply_reviewing(
                &state,
                &case_id,
                disposition,
                &decision.reasoning,
                decider,
                OffsetDateTime::now_utc(),
                decisions::Claim::NewHolder,
                decision.claim_revision,
            )
            .await?
        }
        Some(other) => {
            return Err(Error::BadRequest(format!(
                "unknown reviewed claim {other:?} (expected appeal | new-holder)"
            )))
        }
        None => {
            decisions::apply_with_appeal_routes(
                &state,
                &case_id,
                disposition,
                &decision.reasoning,
                decider,
                OffsetDateTime::now_utc(),
                match disposition {
                    decisions::Disposition::Ban => Some(decisions::AppealRoutes {
                        appeal_url: decision.appeal_url.ok_or_else(|| {
                            Error::BadRequest("appealUrl is required for a human ban".into())
                        })?,
                        new_holder_url: decision.new_holder_url.ok_or_else(|| {
                            Error::BadRequest("newHolderUrl is required for a human ban".into())
                        })?,
                        authority_contact: decision.authority_contact.ok_or_else(|| {
                            Error::BadRequest("authorityContact is required for a human ban".into())
                        })?,
                    }),
                    _ => None,
                },
            )
            .await?
        }
    };

    Ok(Json(json!({
        "caseId": case_id,
        "verdictRef": issued.verdict_ref,
        // The case's disposition, which for a reversal is "reversed".
        // The *verdict* still says "dismiss": that is the only wire
        // value meaning "clear the marks", and the interface's
        // vocabulary is open-case | dismiss | ban. Reporting the
        // verdict's word here made a reversal read as a dismissal in
        // the one place a caller looks to confirm what it just did.
        "disposition": if disposition == decisions::Disposition::Reverse {
            "reversed"
        } else {
            issued.disposition.as_str()
        },
        "verdictDisposition": issued.disposition,
        "decidedBy": decider.as_str(),
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
    crate::delivery::flush_soon(&state);
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

/// Authenticate a case-list lookup by the identity's own fresh signature.
/// A valid identity may discover only cases where it is the accused; the
/// endpoint never accepts a bare public key as authorization.
fn authorize_identity_lookup(headers: &HeaderMap) -> Result<String, Error> {
    let credential = |name: &'static str| headers.get(name).and_then(|value| value.to_str().ok());
    let (Some(key), Some(timestamp), Some(signature)) = (
        credential("x-onym-key"),
        credential("x-onym-timestamp"),
        credential("x-onym-signature"),
    ) else {
        return Err(Error::NotFound("no cases".into()));
    };
    let now = OffsetDateTime::now_utc();
    let fresh = util::parse_timestamp(timestamp)
        .map(|signed_at| {
            (now - signed_at).whole_seconds().abs() <= STATUS_CREDENTIAL_MAX_AGE_SECONDS
        })
        .unwrap_or(false);
    let message = format!("list-cases:{timestamp}");
    if fresh && verify_signature(key, message.as_bytes(), signature).is_ok() {
        return Ok(key.to_string());
    }
    Err(Error::NotFound("no cases".into()))
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

        /// A harness whose pinned profile is a real published one, so
        /// intake decisions that depend on the model's declared inputs
        /// are exercised against terms that actually exist.
        fn with_profile(profile_id: &str) -> Self {
            Self {
                state: Arc::new(AppState::for_tests_with_triage(
                    Store::in_memory().unwrap(),
                    profile_id,
                    "http://127.0.0.1:1",
                    crate::config::TriageMode::Autonomous,
                )),
            }
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

        /// Drive the evidence-blob route, which lives on its own router
        /// with its own body limit — so it has to be exercised through
        /// that router rather than the JSON one.
        async fn put_blob(
            &self,
            sha256: &str,
            bytes: Vec<u8>,
            seed: [u8; 32],
        ) -> (StatusCode, Value) {
            let timestamp = util::format_timestamp(OffsetDateTime::now_utc());
            let message = format!("evidence-blob:{sha256}:{timestamp}");
            let request = Request::put(format!("/v1/evidence-blobs/{sha256}"))
                .header("x-onym-key", testing::key_reference(seed))
                .header("x-onym-timestamp", timestamp)
                .header("x-onym-signature", testing::sign(seed, message.as_bytes()))
                .body(Body::from(bytes))
                .unwrap();
            let response = evidence_router(self.state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
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

    fn party_status_request(case_id: &str, seed: [u8; 32]) -> Request<Body> {
        let timestamp = util::format_timestamp(OffsetDateTime::now_utc());
        let message = format!("query-status:{case_id}:{timestamp}");
        Request::get(format!("/v1/cases/{case_id}/status"))
            .header("x-onym-key", testing::key_reference(seed))
            .header("x-onym-timestamp", timestamp)
            .header("x-onym-signature", testing::sign(seed, message.as_bytes()))
            .body(Body::empty())
            .unwrap()
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

    /// A v2 proof preimage: the shape an iOS sender signs for a message
    /// carrying media. Keys are in UTF-8 byte order because that is what
    /// the client's encoder produces; the authority verifies the
    /// signature over these bytes verbatim and parses the fields out.
    fn media_preimage(image: &media::AcceptedImage) -> String {
        format!(
            r#"{{"body":"","group_binding":"ab","media":[{{"blob_sha256":"cipher","height":{},"mime_type":"{}","plaintext_byte_length":{},"plaintext_sha256":"{}","width":{}}}],"message_id":"m-1","proof_version":2,"sent_at_millis":1}}"#,
            image.height, image.mime_type, image.byte_length, image.sha256, image.width
        )
    }

    /// A v2 preimage committing to several images at once.
    fn media_preimage_many(images: &[media::AcceptedImage]) -> String {
        let entries: Vec<String> = images
            .iter()
            .map(|image| {
                format!(
                    r#"{{"blob_sha256":"cipher","height":{},"mime_type":"{}","plaintext_byte_length":{},"plaintext_sha256":"{}","width":{}}}"#,
                    image.height, image.mime_type, image.byte_length, image.sha256, image.width
                )
            })
            .collect();
        format!(
            r#"{{"body":"","group_binding":"ab","media":[{}],"message_id":"m-1","proof_version":2,"sent_at_millis":1}}"#,
            entries.join(",")
        )
    }

    /// A report whose single evidence item is a photo.
    fn photo_report_json(reporter_mandate: &str, report_id: &str, content: &str) -> Value {
        json!({
            "reportVersion": 1,
            "reportId": report_id,
            "reporter": testing::key_reference(REPORTER_SEED),
            "reporterMandate": reporter_mandate,
            "accused": testing::key_reference(ACCUSED_SEED),
            "classId": "unsolicited-pornography",
            "evidence": [{
                "disclosedContent": content,
                "authenticityProof": testing::sign(ACCUSED_SEED, content.as_bytes()),
            }],
            "filedAt": "2026-08-02T00:00:00Z",
        })
    }

    /// Registered parties, an uploaded photo, and the signed commitment
    /// naming it — everything a valid photo report needs.
    async fn seed_photo(harness: &Harness) -> (String, media::AcceptedImage, String) {
        register_mandate(harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(harness, REPORTER_SEED).await;
        let bytes = media::tiny_jpeg(24, 16);
        let accepted = media::accept_image(&bytes).unwrap();
        let (status, response) =
            harness.put_blob(&accepted.sha256, bytes, REPORTER_SEED).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let content = media_preimage(&accepted);
        (reporter_mandate, accepted, content)
    }

    // ─── Media evidence ──────────────────────────────────────────────

    #[tokio::test]
    async fn a_reported_photo_opens_a_case_and_reaches_the_document() {
        let harness = Harness::new();
        let (mandate, accepted, content) = seed_photo(&harness).await;
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");

        let case_id = response["caseId"].as_str().unwrap();
        let case = harness.state.store.case(case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        assert_eq!(document.images.len(), 1);
        assert_eq!(document.images[0].sha256, accepted.sha256);
        // The image's identity is inside the text, so the input digest
        // covers what the model saw and not merely its caption.
        assert!(document.text.contains(&accepted.sha256));
        assert!(document.text.contains(&accepted.derivative_sha256));
        assert!(document.text.contains("24x16"));
    }

    #[tokio::test]
    async fn a_photo_report_is_refused_until_its_bytes_are_uploaded() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let mandate = register_mandate(&harness, REPORTER_SEED).await;
        // The commitment is perfectly valid; the authority just does not
        // hold what it names.
        let accepted = media::accept_image(&media::tiny_jpeg(8, 8)).unwrap();
        let content = media_preimage(&accepted);
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(response["error"], "media_missing");
    }

    #[tokio::test]
    async fn one_flipped_byte_makes_the_photo_a_different_image() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let mandate = register_mandate(&harness, REPORTER_SEED).await;

        // Upload one image, then commit to a *different* one. The
        // signature is valid over the commitment; the bytes on file are
        // simply not the ones it names.
        let uploaded = media::tiny_jpeg(24, 16);
        let accepted = media::accept_image(&uploaded).unwrap();
        harness.put_blob(&accepted.sha256, uploaded, REPORTER_SEED).await;

        let other = media::accept_image(&media::tiny_jpeg(25, 16)).unwrap();
        let content = media_preimage(&other);
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(response["error"], "media_missing");
    }

    #[tokio::test]
    async fn a_commitment_that_misstates_the_image_does_not_authenticate_it() {
        let harness = Harness::new();
        let (mandate, accepted, _) = seed_photo(&harness).await;
        // Right digest, wrong declared length: the bytes on file are the
        // ones named, but the proof describes something else, so it does
        // not attest to them.
        let content = format!(
            r#"{{"body":"","group_binding":"ab","media":[{{"blob_sha256":"cipher","height":{},"mime_type":"image/jpeg","plaintext_byte_length":{},"plaintext_sha256":"{}","width":{}}}],"message_id":"m-1","proof_version":2,"sent_at_millis":1}}"#,
            accepted.height,
            accepted.byte_length + 1,
            accepted.sha256,
            accepted.width
        );
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response["error"], "authenticity_unverified");
    }

    #[tokio::test]
    async fn csam_does_not_accept_image_evidence() {
        let harness = Harness::new();
        let (mandate, _, content) = seed_photo(&harness).await;
        let mut report = photo_report_json(&mandate, "r-1", &content);
        report["classId"] = json!("csam");
        let body = signed(report, "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"], "media_class_refused");
    }

    #[tokio::test]
    async fn an_upload_from_an_unconsented_key_is_refused() {
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;
        let bytes = media::tiny_jpeg(8, 8);
        let accepted = media::accept_image(&bytes).unwrap();

        let (status, response) =
            harness.put_blob(&accepted.sha256, bytes, STRANGER_SEED).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
        assert_eq!(response["error"], "reporter_unconsented");
    }

    #[tokio::test]
    async fn an_upload_whose_bytes_do_not_match_its_name_is_refused() {
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;
        let bytes = media::tiny_jpeg(8, 8);
        let wrong_name = util::sha256_hex(b"something else entirely");

        let (status, response) = harness.put_blob(&wrong_name, bytes, REPORTER_SEED).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }

    #[tokio::test]
    async fn re_uploading_the_same_photo_is_the_same_blob() {
        // Content addressing makes retries free: an interrupted upload
        // resumes by simply sending the bytes again, and two reporters
        // who received the same photo share one row.
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;
        let bytes = media::tiny_jpeg(12, 12);
        let accepted = media::accept_image(&bytes).unwrap();

        for _ in 0..2 {
            let (status, _) =
                harness.put_blob(&accepted.sha256, bytes.clone(), REPORTER_SEED).await;
            assert_eq!(status, StatusCode::OK);
        }
        let stored = harness.state.store.evidence_blob(&accepted.sha256).unwrap().unwrap();
        assert_eq!(stored.byte_length, accepted.byte_length);
    }

    #[tokio::test]
    async fn a_key_cannot_park_unlimited_uploads() {
        // Consent is not a budget: uploading happens before any report
        // justifies it, and the expiry sweep only reclaims a day later.
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;

        for size in 0..MAX_UNREFERENCED_UPLOADS_PER_KEY {
            let bytes = media::tiny_jpeg(8 + size as u32, 8);
            let accepted = media::accept_image(&bytes).unwrap();
            let (status, response) =
                harness.put_blob(&accepted.sha256, bytes, REPORTER_SEED).await;
            assert_eq!(status, StatusCode::OK, "{response}");
        }

        let bytes = media::tiny_jpeg(200, 8);
        let accepted = media::accept_image(&bytes).unwrap();
        let (status, response) = harness.put_blob(&accepted.sha256, bytes, REPORTER_SEED).await;
        // Not `media_too_large`: nothing is wrong with the image, and a
        // client reading only the status would otherwise shrink it and
        // retry forever against a limit that is not about size.
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{response}");
        assert_eq!(response["error"], "media_quota_exceeded");
    }

    #[tokio::test]
    async fn a_text_only_authority_refuses_image_evidence_at_intake() {
        // Not merely "declines to decide later". A case that can never
        // be decided is dismissed at its deadline, so accepting image
        // evidence a text-only model cannot read would hand anyone able
        // to file against this accused — the accused included, since
        // they can sign their own disclosed content — a way to end the
        // case.
        let harness = Harness::with_profile("qwen3guard-8b");
        let (mandate, accepted, content) = seed_photo(&harness).await;
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;

        assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
        assert_eq!(response["error"], "media_class_refused");
        assert!(harness.state.store.evidence_blob(&accepted.sha256).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_joining_report_cannot_push_a_case_past_its_media_ceiling() {
        // Reports join an open case rather than opening a second one,
        // so the case-wide ceiling has to be measured against the case
        // being joined — measuring against zero left it dead on the
        // one path that actually accumulates.
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let mandate = register_mandate(&harness, REPORTER_SEED).await;

        // Four images per report, so the ceiling is reached before the
        // separate cap on how many notices a case may emit.
        let per_report = 4usize;
        let mut images_on_case = 0usize;
        let mut last_status = StatusCode::OK;
        for round in 0..(media::MAX_MEDIA_PER_CASE / per_report + 2) {
            let mut accepted = Vec::new();
            for slot in 0..per_report {
                let bytes = media::tiny_jpeg(20 + (round * per_report + slot) as u32, 16);
                let image = media::accept_image(&bytes).unwrap();
                harness.put_blob(&image.sha256, bytes, REPORTER_SEED).await;
                accepted.push(image);
            }
            let content = media_preimage_many(&accepted);
            let body = signed(
                photo_report_json(&mandate, &format!("r-{round}"), &content),
                "signature",
                &[REPORTER_SEED],
            );
            let (status, _) = harness.post("/v1/reports", body).await;
            last_status = status;
            if status != StatusCode::OK {
                break;
            }
            images_on_case += per_report;
        }

        assert_eq!(images_on_case, media::MAX_MEDIA_PER_CASE);
        assert_eq!(last_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_refusal_deletes_every_image_the_filing_named() {
        // The refusal used to `return` inside the per-item loop, so a
        // report carrying images on two evidence items left the second
        // item's bytes on disk for the full expiry window.
        let harness = Harness::new();
        let (mandate, first, first_content) = seed_photo(&harness).await;
        let second_bytes = media::tiny_jpeg(31, 17);
        let second = media::accept_image(&second_bytes).unwrap();
        harness.put_blob(&second.sha256, second_bytes, REPORTER_SEED).await;

        let mut report = photo_report_json(&mandate, "r-1", &first_content);
        report["classId"] = json!("csam");
        let second_content = media_preimage(&second);
        report["evidence"] = json!([
            {
                "disclosedContent": first_content,
                "authenticityProof": testing::sign(ACCUSED_SEED, first_content.as_bytes()),
            },
            {
                "disclosedContent": second_content,
                "authenticityProof": testing::sign(ACCUSED_SEED, second_content.as_bytes()),
            },
        ]);

        let (status, _) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(harness.state.store.evidence_blob(&first.sha256).unwrap().is_none());
        assert!(
            harness.state.store.evidence_blob(&second.sha256).unwrap().is_none(),
            "every image the filing named, not only the first item's"
        );
    }

    #[tokio::test]
    async fn an_oversized_commitment_is_bounded_before_it_becomes_work() {
        // A signed preimage's length is attacker-chosen, and the
        // refusal path costs two queries per digest. Bounding after
        // refusing made a preimage naming thousands of blobs into
        // thousands of queries per request.
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let mandate = register_mandate(&harness, REPORTER_SEED).await;
        let entries: Vec<String> = (0..500)
            .map(|i| {
                format!(
                    r#"{{"blob_sha256":"c","height":4,"mime_type":"image/jpeg","plaintext_byte_length":9,"plaintext_sha256":"{:064x}","width":3}}"#,
                    i
                )
            })
            .collect();
        let content = format!(
            r#"{{"body":"","group_binding":"ab","media":[{}],"message_id":"m","proof_version":2,"sent_at_millis":1}}"#,
            entries.join(",")
        );
        let mut report = photo_report_json(&mandate, "r-1", &content);
        report["classId"] = json!("csam");

        let (status, response) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;

        // Bounded, not refused for the class — the bound comes first.
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "bad_request");
    }

    #[tokio::test]
    async fn a_commitment_without_dimensions_does_not_authenticate_an_image() {
        // Width and height are printed in the case document and the
        // panel as facts about the evidence. A commitment omitting them
        // would have those numbers attributed to a signature that never
        // covered them.
        let harness = Harness::new();
        let (mandate, accepted, _) = seed_photo(&harness).await;
        let content = format!(
            r#"{{"body":"","group_binding":"ab","media":[{{"blob_sha256":"cipher","mime_type":"image/jpeg","plaintext_byte_length":{},"plaintext_sha256":"{}"}}],"message_id":"m-1","proof_version":2,"sent_at_millis":1}}"#,
            accepted.byte_length, accepted.sha256
        );
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert_eq!(response["error"], "authenticity_unverified");
    }

    #[tokio::test]
    async fn a_refused_csam_report_does_not_leave_the_image_on_the_server() {
        // The upload route has no class context, so the bytes are on
        // disk before anything knows what they will be claimed as.
        // Custody is unavoidable; holding it for a day is not.
        let harness = Harness::new();
        let (mandate, accepted, content) = seed_photo(&harness).await;
        let mut report = photo_report_json(&mandate, "r-1", &content);
        report["classId"] = json!("csam");

        let (status, response) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"], "media_class_refused");
        assert!(
            harness.state.store.evidence_blob(&accepted.sha256).unwrap().is_none(),
            "a refused class must not leave the image sitting for the expiry window"
        );
    }

    #[tokio::test]
    async fn a_refusal_does_not_take_an_image_a_live_case_rests_on() {
        // The same digest can serve two cases. A refusal is this
        // report's business and no other's.
        let harness = Harness::new();
        let (mandate, accepted, content) = seed_photo(&harness).await;
        let (ok_status, _) = harness
            .post(
                "/v1/reports",
                signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]),
            )
            .await;
        assert_eq!(ok_status, StatusCode::OK);

        let mut refused = photo_report_json(&mandate, "r-2", &content);
        refused["classId"] = json!("csam");
        let (status, _) =
            harness.post("/v1/reports", signed(refused, "signature", &[REPORTER_SEED])).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            harness.state.store.evidence_blob(&accepted.sha256).unwrap().is_some(),
            "a live case still rests on these bytes"
        );
    }

    #[tokio::test]
    async fn a_re_upload_at_the_edge_of_expiry_refreshes_the_clock() {
        // The 200 has to mean the bytes are here and will stay. It did
        // not: an ignored insert left `uploaded_at` stale, so the sweep
        // could take a blob the server had just acknowledged.
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;
        let bytes = media::tiny_jpeg(12, 12);
        let accepted = media::accept_image(&bytes).unwrap();
        harness.put_blob(&accepted.sha256, bytes.clone(), REPORTER_SEED).await;
        // Age it to the brink.
        harness
            .state
            .store
            .touch_evidence_blobs(&[accepted.sha256.clone()], "2020-01-01T00:00:00Z")
            .unwrap();

        let (status, _) = harness.put_blob(&accepted.sha256, bytes, REPORTER_SEED).await;
        assert_eq!(status, StatusCode::OK);

        let swept = harness
            .state
            .store
            .sweep_unreferenced_evidence_blobs("2020-06-01T00:00:00Z")
            .unwrap();
        assert_eq!(swept, 0, "the re-upload restarted the clock");
        assert!(harness.state.store.evidence_blob(&accepted.sha256).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_key_at_the_quota_can_still_re_upload_what_it_already_sent() {
        // The cap must not break the one recovery path the design
        // leans on: re-sending bytes already on file costs nothing new.
        let harness = Harness::new();
        register_mandate(&harness, REPORTER_SEED).await;
        let mut first: Option<Vec<u8>> = None;
        for size in 0..MAX_UNREFERENCED_UPLOADS_PER_KEY {
            let bytes = media::tiny_jpeg(8 + size as u32, 8);
            let accepted = media::accept_image(&bytes).unwrap();
            harness.put_blob(&accepted.sha256, bytes.clone(), REPORTER_SEED).await;
            if first.is_none() {
                first = Some(bytes);
            }
        }

        let bytes = first.unwrap();
        let accepted = media::accept_image(&bytes).unwrap();
        let (status, response) = harness.put_blob(&accepted.sha256, bytes, REPORTER_SEED).await;
        assert_eq!(status, StatusCode::OK, "{response}");

        // A genuinely new one is still refused.
        let fresh = media::tiny_jpeg(300, 8);
        let fresh_accepted = media::accept_image(&fresh).unwrap();
        let (status, _) = harness.put_blob(&fresh_accepted.sha256, fresh, REPORTER_SEED).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn uploads_a_case_rests_on_do_not_count_against_the_bound() {
        // The bound is on uploads no case rests on — keyed on the join
        // table rather than on a flag set at filing time, so an upload
        // whose case never opened keeps counting instead of vanishing
        // from the budget the way the earlier flag let it.
        let harness = Harness::new();
        let (mandate, _, content) = seed_photo(&harness).await;
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);
        let (status, _) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK);

        let reporter = testing::key_reference(REPORTER_SEED);
        assert_eq!(harness.state.store.unreferenced_uploads_by(&reporter).unwrap(), 0);
    }

    #[tokio::test]
    async fn a_commitment_spelling_its_digest_in_uppercase_still_finds_the_bytes() {
        // Uploads are stored under lowercase hex. A digest differing
        // only in case would otherwise be refused as missing with the
        // bytes sitting on disk.
        let harness = Harness::new();
        let (mandate, accepted, _) = seed_photo(&harness).await;
        let content = format!(
            r#"{{"body":"","group_binding":"ab","media":[{{"blob_sha256":"cipher","height":{},"mime_type":"image/jpeg","plaintext_byte_length":{},"plaintext_sha256":"{}","width":{}}}],"message_id":"m-1","proof_version":2,"sent_at_millis":1}}"#,
            accepted.height,
            accepted.byte_length,
            accepted.sha256.to_uppercase(),
            accepted.width
        );
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    #[tokio::test]
    async fn a_filed_photo_report_survives_a_retry_without_re_uploading() {
        let harness = Harness::new();
        let (mandate, _, content) = seed_photo(&harness).await;
        let body =
            signed(photo_report_json(&mandate, "r-1", &content), "signature", &[REPORTER_SEED]);

        let (first_status, first) = harness.post("/v1/reports", body.clone()).await;
        assert_eq!(first_status, StatusCode::OK, "{first}");
        let (second_status, second) = harness.post("/v1/reports", body).await;
        assert_eq!(second_status, StatusCode::OK, "{second}");
        assert_eq!(second["duplicate"], true);
        assert_eq!(second["caseId"], first["caseId"]);
    }

    #[tokio::test]
    async fn a_text_report_still_files_unchanged_alongside_media_support() {
        // The regression that matters most: disclosed content is now
        // parsed, and everything already on file predates that.
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let mandate = register_mandate(&harness, REPORTER_SEED).await;
        let body = signed(report_json(&mandate, "r-1"), "signature", &[REPORTER_SEED]);

        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap();
        let case = harness.state.store.case(case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        assert!(document.images.is_empty());
        assert!(!document.text.contains("shown-as"));
    }

    /// A human ban decision with the appeal routes #23 made
    /// mandatory — the shape every moderator ban must send.
    fn ban_decision() -> serde_json::Value {
        json!({
            "disposition": "ban",
            "reasoning": "hash:f",
            "appealUrl": "https://authority.test/appeal",
            "newHolderUrl": "https://authority.test/new-holder",
            "authorityContact": "appeals@authority.test",
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
        state.config.interface_keys.clear();
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

    /// The reason `interface_keys` is a list.
    ///
    /// The interface derives a separate countersigning key per
    /// authority and can rotate ours. With a single accepted key there
    /// is no order in which that rotation avoids downtime — whichever
    /// side moves first, every registration fails until the other
    /// catches up. Accepting the incoming key alongside the outgoing
    /// one is what closes that window: both verify while the cutover
    /// happens, and the old entry is dropped afterwards.
    #[tokio::test]
    async fn both_keys_verify_while_a_rotation_is_in_flight() {
        // A second interface key, as the interface would derive after
        // bumping our epoch.
        const NEXT_INTERFACE_SEED: [u8; 32] = [23u8; 32];
        let next = crate::testing::key_reference(NEXT_INTERFACE_SEED);

        let mut state = AppState::for_tests(Store::in_memory().unwrap());
        state.config.interface_keys.push(next);
        let harness = Harness { state: Arc::new(state) };
        let manifest_hash = util::sha256_hex(&harness.state.config.manifest_raw);

        // Countersigned with the outgoing key: still accepted.
        let (status, response) = harness
            .post(
                "/v1/mandates",
                signed(
                    mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash),
                    "signatures",
                    &[ACCUSED_SEED, INTERFACE_SEED],
                ),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "outgoing key: {response}");

        // Countersigned with the incoming key: also accepted, which is
        // the whole point — the interface can cut over without a gap.
        let (status, response) = harness
            .post(
                "/v1/mandates",
                signed(
                    mandate_json(REPORTER_SEED, json!(["csam"]), &manifest_hash),
                    "signatures",
                    &[REPORTER_SEED, NEXT_INTERFACE_SEED],
                ),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "incoming key: {response}");

        // A key on neither side of the rotation is still refused —
        // accepting a list is not accepting anything.
        let (status, _) = harness
            .post(
                "/v1/mandates",
                signed(
                    mandate_json(ACCUSED_SEED, json!(["csam"]), &manifest_hash),
                    "signatures",
                    &[ACCUSED_SEED, [99u8; 32]],
                ),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
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
            harness.decide(&case_id, ban_decision()).await;
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
            .decide(&case_id, ban_decision())
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        assert_eq!(response["error"], "case_state");
        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().stage, "open");
    }

    /// The refusal has to be actionable. A notice still in the queue
    /// and a notice the interface has given up on look the same to
    /// `open_case_verdict_delivered`, and the old error said only "the
    /// opening verdict has not reached the interface" for both — so a
    /// moderator could not tell a case that will clear itself from one
    /// that never will without an operator.
    #[tokio::test]
    async fn a_ban_refused_for_an_undelivered_notice_names_it() {
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

        let stuck = harness.state.store.undelivered_verdicts().unwrap();
        assert_eq!(stuck.len(), 1);
        let stuck_ref = stuck[0].verdict_ref.clone();

        // Still queued: name it, and say nothing about requeueing —
        // waiting is the right thing to do.
        let (status, response) =
            harness.decide(&case_id, ban_decision()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        let message = response["message"].as_str().unwrap_or_default().to_string();
        assert!(message.contains(&stuck_ref), "{message}");
        assert!(!message.contains("requeue"), "nothing is stuck yet: {message}");

        // Given up on: the case is now unbannable for life unless an
        // operator intervenes, so say so and name the route out.
        harness.state.store.mark_undeliverable(&stuck_ref).unwrap();
        let (status, response) =
            harness.decide(&case_id, ban_decision()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        let message = response["message"].as_str().unwrap_or_default().to_string();
        assert!(message.contains(&stuck_ref), "{message}");
        assert!(message.contains("given up on"), "{message}");
        assert!(
            message.contains(&format!("/v1/verdicts/{stuck_ref}/requeue")),
            "the only way out has to be in the error: {message}"
        );

        // And the guard itself has not softened.
        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().stage, "open");
    }

    /// A case can hold more than one stuck notice, and each needs its
    /// own requeue. Listing every ref and then one URL built from the
    /// first left a moderator with two problems and one instruction.
    #[tokio::test]
    async fn every_stuck_notice_gets_its_own_requeue_url() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let first = signed(report_json(&reporter_mandate, "r-1"), "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", first).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();

        // A second report joins the case, which issues a second notice.
        let mut report = report_json(&reporter_mandate, "r-2");
        report["evidence"][0]["disclosedContent"] = json!("a different prohibited thing");
        report["evidence"][0]["authenticityProof"] =
            json!(testing::sign(ACCUSED_SEED, b"a different prohibited thing"));
        let (status, response) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["caseId"], case_id);

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();

        let stuck: Vec<String> = harness
            .state
            .store
            .undelivered_verdicts()
            .unwrap()
            .into_iter()
            .map(|v| v.verdict_ref)
            .collect();
        assert_eq!(stuck.len(), 2, "two joined reports, two notices");
        for reference in &stuck {
            harness.state.store.mark_undeliverable(reference).unwrap();
        }

        let (status, response) =
            harness.decide(&case_id, ban_decision()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        let message = response["message"].as_str().unwrap_or_default().to_string();
        for reference in &stuck {
            assert!(
                message.contains(&format!("POST /v1/verdicts/{reference}/requeue")),
                "every stuck notice needs its own requeue, not just the first: {message}"
            );
        }
        assert!(message.contains("notices"), "plural, since there are two: {message}");
    }

    /// The refusal used to be assembled from two reads — a yes-or-no
    /// and then a lookup — so a flush marking the last notice delivered
    /// in between produced a message asserting the case had *no*
    /// notice, on a case that had one and had just been served. One
    /// query now, so the answer cannot contradict itself; the
    /// no-notice wording is reserved for a case that genuinely has
    /// none.
    #[tokio::test]
    async fn a_case_with_no_notice_at_all_says_so_without_asserting_a_queue() {
        let harness = Harness::new();
        assert_eq!(
            harness.state.store.notice_delivery("case-that-does-not-exist").unwrap(),
            crate::store::NoticeDelivery::NoneIssued
        );

        let case_id = open_case(&harness).await;
        let delivered = harness.state.store.undelivered_verdicts().unwrap();
        for verdict in &delivered {
            harness.state.store.mark_delivered(&verdict.verdict_ref).unwrap();
        }
        assert_eq!(
            harness.state.store.notice_delivery(&case_id).unwrap(),
            crate::store::NoticeDelivery::AllDelivered,
            "every notice served: the guard must let the ban through on its own merits"
        );
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
            .decide(&case_id, ban_decision())
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
            harness.decide(&case_id, ban_decision()).await;
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
            harness.decide(&case_id, ban_decision()).await;
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
            harness.decide(&case_id, ban_decision()).await;
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
        harness.decide(&case_id, ban_decision()).await;

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
            .decide(&case_id, ban_decision())
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
        harness.decide(&case_id, ban_decision()).await;

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
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
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
        harness.decide(&case_id, ban_decision()).await;
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
            .decide(&case_id, ban_decision())
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

    #[tokio::test]
    async fn evidence_beyond_the_notice_cap_is_not_attached_unserved() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // The opening report is notice one; seven distinct allegations
        // bring the case to its cap of eight.
        for index in 2..=8 {
            let content = format!("distinct prohibited thing {index}");
            let mut report = report_json(&reporter_mandate, &format!("r-{index}"));
            report["evidence"][0]["disclosedContent"] = json!(content);
            report["evidence"][0]["authenticityProof"] =
                json!(testing::sign(ACCUSED_SEED, content.as_bytes()));
            let (status, body) =
                harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }

        let content = "distinct prohibited thing 9";
        let mut report = report_json(&reporter_mandate, "r-9");
        report["evidence"][0]["disclosedContent"] = json!(content);
        report["evidence"][0]["authenticityProof"] =
            json!(testing::sign(ACCUSED_SEED, content.as_bytes()));
        let (status, body) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "case_state");
        assert_eq!(
            harness
                .state
                .store
                .report(&testing::key_reference(REPORTER_SEED), "r-9")
                .unwrap()
                .unwrap()
                .case_id,
            None,
            "unserved evidence must not become part of the case"
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
            MAX_NOTICES_PER_CASE as usize
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
    /// Re-filing a valid signed appeal used to reset `appeal_state` to
    /// `pending`, so an accused could flip a completed review — even a
    /// reversal — back into the queue by POSTing the same object
    /// again. That erases the record of a review that did happen, in
    /// the place the panel reads it from.
    #[tokio::test]
    async fn an_appeal_cannot_be_refiled_to_reopen_a_completed_review() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        // Ban it, so there is something to appeal.
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let appeal = || {
            signed(
                json!({"caseId": case_id, "kind": "appeal", "statement": "it was a quotation"}),
                "signature",
                &[ACCUSED_SEED],
            )
        };
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().appeal_state, "pending");

        // A moderator reviews it.
        harness
            .state
            .store
            .set_appeal_state(&case_id, "upheld", None, None, "2026-08-09T00:00:00Z", "appeal_upheld", "hash:r")
            .unwrap();

        // Re-filing must not put it back in the queue.
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().appeal_state,
            "upheld",
            "the completed review stands"
        );
    }

    /// The accused may supplement a pending appeal, and doing so
    /// changes neither `appealState` nor the case revision — a
    /// supplement is not a new claim and does not touch the document a
    /// model would read. `claimRevision` is the only thing that moves,
    /// which is why a decision may pin it: a review submitted against
    /// the earlier value is a review of a shorter file than the one it
    /// would decide.
    #[tokio::test]
    async fn a_decision_pinned_to_a_stale_claim_revision_is_refused() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let appeal = |statement: &str| {
            signed(
                json!({"caseId": case_id, "kind": "appeal", "statement": statement}),
                "signature",
                &[ACCUSED_SEED],
            )
        };
        let (status, _) =
            harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal("it was a quotation")).await;
        assert_eq!(status, StatusCode::OK);

        // What a reviewer would read now.
        let read_at = harness.state.store.case(&case_id).unwrap().unwrap().claim_revision;

        // …and then more material arrives.
        let (status, _) =
            harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal("and here is the thread")).await;
        assert_eq!(status, StatusCode::OK);
        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(case.appeal_state, "pending", "a supplement does not move the state");
        assert!(case.claim_revision > read_at, "it moves the claim revision");

        let stale = json!({
            "disposition": "reverse",
            "reasoning": "hash:r",
            "reviewed": "appeal",
            "claimRevision": read_at,
        });
        let (status, _) = harness.decide(&case_id, stale).await;
        assert_eq!(status, StatusCode::CONFLICT, "a review of a file that has grown must not commit");
        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().disposition.as_deref(),
            Some("ban")
        );

        // Reading the whole file and deciding against *that* works.
        let current = harness.state.store.case(&case_id).unwrap().unwrap().claim_revision;
        let (status, _) = harness
            .decide(
                &case_id,
                json!({
                    "disposition": "reverse",
                    "reasoning": "hash:r",
                    "reviewed": "appeal",
                    "claimRevision": current,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("reversed"));
        assert_eq!(case.appeal_state, "reversed");
    }

    /// A device-changed-hands claim is not an appeal against the
    /// verdict, and must not be queued as one — the panel's uphold
    /// branch would otherwise write "appeal upheld" into the log of a
    /// case nobody appealed.
    #[tokio::test]
    async fn a_new_holder_claim_is_queued_as_itself() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;

        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let claim = serde_json::to_vec(&json!({
            "caseId": case_id,
            "kind": "new-holder-claim",
            "statement": "I bought this device secondhand",
        }))
        .unwrap();
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), claim).await;
        assert_eq!(status, StatusCode::OK);

        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(case.new_holder_state, "pending");
        assert_eq!(case.appeal_state, "none", "it is not an appeal, and must not occupy one");
        // It still reaches a human: both kinds are in the queue.
        assert_eq!(harness.state.store.cases_awaiting_appeal_review().unwrap().len(), 1);
    }


    /// A new-holder claim and an appeal are different claims, by
    /// different people, about different questions. Sharing one field
    /// let a claim swallow a pending appeal — and since the claim path
    /// is unauthenticated, let anyone knowing a case id lock the
    /// accused out of appealing at all.
    #[tokio::test]
    async fn a_new_holder_claim_neither_swallows_nor_blocks_an_appeal() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        // The accused appeals.
        let appeal = signed(
            json!({"caseId": case_id, "kind": "appeal", "statement": "it was a quotation"}),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal).await;
        assert_eq!(status, StatusCode::OK);

        // A stranger files a new-holder claim on the same case.
        let claim = serde_json::to_vec(&json!({
            "caseId": case_id,
            "kind": "new-holder-claim",
            "statement": "I bought this device secondhand",
        }))
        .unwrap();
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), claim).await;
        assert_eq!(status, StatusCode::OK);

        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(case.appeal_state, "pending", "the appeal must survive the claim");
        assert_eq!(case.new_holder_state, "pending", "and the claim is queued too");
    }

    /// The order that mattered more: a claim filed *first* must not
    /// stop the accused appealing.
    #[tokio::test]
    async fn a_claim_filed_first_does_not_lock_out_the_appeal() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let claim = serde_json::to_vec(&json!({
            "caseId": case_id,
            "kind": "new-holder-claim",
            "statement": "I bought this device secondhand",
        }))
        .unwrap();
        harness.post(&format!("/v1/cases/{case_id}/appeal"), claim).await;

        let appeal = signed(
            json!({"caseId": case_id, "kind": "appeal", "statement": "it was a quotation"}),
            "signature",
            &[ACCUSED_SEED],
        );
        let (status, _) = harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal).await;
        assert_eq!(status, StatusCode::OK, "§12 relief must not be blockable by a stranger");
        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().appeal_state,
            "pending"
        );
    }

    /// A reversal through the JSON API answers the appeal too — it left
    /// the case in the panel's queue, where a moderator could then
    /// "uphold" a verdict that had already been reversed.
    #[tokio::test]
    async fn a_reversal_through_the_api_resolves_the_appeal() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let appeal = signed(
            json!({"caseId": case_id, "kind": "appeal", "statement": "it was a quotation"}),
            "signature",
            &[ACCUSED_SEED],
        );
        harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal).await;

        let (status, _) = harness
            .decide(
                &case_id,
                json!({"disposition": "reverse", "reasoning": "hash:r", "reviewed": "appeal"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        assert_eq!(harness.state.store.case(&case_id).unwrap().unwrap().appeal_state, "reversed");
        assert!(
            harness.state.store.cases_awaiting_appeal_review().unwrap().is_empty(),
            "an answered appeal leaves the queue whichever door the answer came through"
        );
    }

    /// Reversing a ban nobody appealed is the authority correcting
    /// itself, not an appeal outcome. Recording it as one puts a review
    /// that never happened into the case log.
    #[tokio::test]
    async fn reversing_without_an_appeal_is_not_recorded_as_an_appeal_outcome() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let (status, _) =
            harness.decide(&case_id, json!({"disposition": "reverse", "reasoning": "hash:r"})).await;
        assert_eq!(status, StatusCode::OK);

        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        assert_eq!(case.disposition.as_deref(), Some("reversed"));
        assert_eq!(case.appeal_state, "none", "nobody appealed");
        assert!(
            !harness
                .state
                .store
                .events(&case_id)
                .unwrap()
                .iter()
                .any(|(_, kind, _)| kind == "appeal_reversed"),
            "the log must not claim an appeal was reversed"
        );
    }


    /// End to end on the disclosure: the accused resolving their
    /// verdict's `reasoning` gets the record, and does not get the
    /// reporter's own account of it. A moderator does.
    #[tokio::test]
    async fn the_accused_can_resolve_their_case_without_learning_who_reported_it() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        // A report whose context is the reporter writing about it.
        let mut report = report_json(&reporter_mandate, "r-1");
        report["evidence"][0]["context"] =
            json!("he sent it after I asked him to stop, on our group chat");
        let body = signed(report, "signature", &[REPORTER_SEED]);
        let (status, response) = harness.post("/v1/reports", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();

        // An assessment on file, as triage would leave one.
        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        harness
            .state
            .store
            .put_assessment(&case_id, br#"{"outcome":"no-decision"}"#, "no-decision", &document.text, true)
            .unwrap();

        let (status, accused_view) = harness.send(party_status_request(&case_id, ACCUSED_SEED)).await;
        assert_eq!(status, StatusCode::OK);

        let seen = accused_view["assessment"]["document"].as_str().expect("the record is served");
        // The evidence itself, by the words the report actually
        // carried — not by a phrase that also appears in the
        // withholding notice, which is how this assertion first passed
        // while testing nothing.
        assert!(seen.contains("prohibited thing"), "they get the evidence against them: {seen}");
        assert!(
            !seen.contains("I asked him to stop"),
            "and not the reporter's own words: {seen}"
        );
        assert!(seen.contains("[withheld"), "the gap is visible, so it can be asked about");
        // Nothing anywhere in the answer names the reporter.
        assert!(!accused_view.to_string().contains(&testing::key_reference(REPORTER_SEED)));

        // A moderator reviewing the same case sees all of it.
        let (_, moderator_view) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(moderator_view["assessment"]["document"]
            .as_str()
            .unwrap()
            .contains("I asked him to stop"));
    }

    /// A reporter on the case is a party — they can read the status —
    /// but the record the case was decided on includes the accused's
    /// own response, which is not theirs to read.
    #[tokio::test]
    async fn a_reporter_does_not_get_the_assessed_record() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        harness
            .state
            .store
            .put_assessment(&case_id, br#"{"outcome":"ban"}"#, "ban", &document.text, true)
            .unwrap();

        let (status, view) = harness.send(party_status_request(&case_id, REPORTER_SEED)).await;
        assert_eq!(status, StatusCode::OK, "a reporter is still a party");
        assert!(view["assessment"].is_null(), "but the record is not theirs");
    }


    /// The two appeal rules compose: a pending appeal may be
    /// supplemented — the accused may find more to say while waiting,
    /// and the first filing should not be their only chance — while a
    /// *decided* one is never re-opened by filing again. Supplementing
    /// must also not queue the case twice for the moderator.
    #[tokio::test]
    async fn a_pending_appeal_can_be_supplemented_but_a_decided_one_cannot() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let appeal = |statement: &str| {
            signed(
                json!({"caseId": case_id, "kind": "appeal", "statement": statement}),
                "signature",
                &[ACCUSED_SEED],
            )
        };

        let (status, _) =
            harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal("it was a quotation")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = harness
            .post(&format!("/v1/cases/{case_id}/appeal"), appeal("and here is the context"))
            .await;
        assert_eq!(status, StatusCode::OK, "a pending appeal may be supplemented");

        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().appeal_state,
            "pending"
        );
        assert_eq!(
            harness.state.store.cases_awaiting_appeal_review().unwrap().len(),
            1,
            "supplementing must not queue the case twice"
        );

        // Once reviewed, further filings are refused — otherwise the
        // record of the review that happened is erased.
        harness
            .state
            .store
            .set_appeal_state(&case_id, "upheld", None, None, "2026-08-09T00:00:00Z", "appeal_upheld", "hash:r")
            .unwrap();
        let (status, _) =
            harness.post(&format!("/v1/cases/{case_id}/appeal"), appeal("let me try again")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().appeal_state,
            "upheld",
            "the completed review stands"
        );
    }


    /// Redacting the document and then serving the model's prose beside
    /// it closes one channel and leaves the adjacent one open. Two
    /// published profiles ask the model to reason in the open, so its
    /// output can quote the field the document redaction just removed.
    #[tokio::test]
    async fn the_models_own_words_cannot_quote_the_reporter_back_to_the_accused() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let account = "he sent it right after I asked him to stop";
        let mut report = report_json(&reporter_mandate, "r-1");
        report["evidence"][0]["context"] = json!(account);
        let (status, response) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();

        // A model that reasons in the open, quoting what it was shown.
        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        let assessment = json!({
            "outcome": "no-decision",
            "rawOutput": format!("No. The report context says \"{account}\", which does not \
                                  establish the required elements."),
            "note": "score 0.1100 at or below the profile's dismissal threshold 0.2",
        });
        harness
            .state
            .store
            .put_assessment(
                &case_id,
                &serde_json::to_vec(&assessment).unwrap(),
                "no-decision",
                &document.text,
                true,
            )
            .unwrap();

        let (status, view) = harness.send(party_status_request(&case_id, ACCUSED_SEED)).await;
        assert_eq!(status, StatusCode::OK);

        // Nowhere in the answer — not the document, not the model's
        // words about it.
        assert!(
            !view.to_string().contains("asked him to stop"),
            "the reporter's account leaked: {view}"
        );
        let raw = view["assessment"]["rawOutput"].as_str().unwrap();
        assert!(raw.contains("[withheld"), "and the withholding is visible: {raw}");
        assert!(
            raw.contains("does not establish the required elements"),
            "the rest of the model's reasoning still reaches them: {raw}"
        );

        // The moderator reviewing the appeal sees all of it.
        let (_, panel) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(panel["assessment"]["rawOutput"].as_str().unwrap().contains("asked him to stop"));
    }


    /// `labels` was the one field the redaction did not cover. For a
    /// taxonomy read line by line every line after the first becomes a
    /// label — and on the unknown-code path the whole unreadable list
    /// is kept — so a model emitting `unsafe` followed by the
    /// reporter's account put it straight into the accused's copy.
    #[tokio::test]
    async fn labels_cannot_carry_the_reporters_account_to_the_accused() {
        let harness = Harness::new();
        register_mandate(&harness, ACCUSED_SEED).await;
        let reporter_mandate = register_mandate(&harness, REPORTER_SEED).await;

        let account = "he sent it right after I asked him to stop";
        let mut report = report_json(&reporter_mandate, "r-1");
        report["evidence"][0]["context"] = json!(account);
        let (status, response) =
            harness.post("/v1/reports", signed(report, "signature", &[REPORTER_SEED])).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let case_id = response["caseId"].as_str().unwrap().to_string();

        let case = harness.state.store.case(&case_id).unwrap().unwrap();
        let document = crate::casedoc::build(&harness.state.store, &case).unwrap();
        let assessment = json!({
            "outcome": "no-decision",
            "rawOutput": "unsafe",
            "note": "an output containing a code nobody can interpret is not an answer",
            "labels": [account, "S4"],
        });
        harness
            .state
            .store
            .put_assessment(
                &case_id,
                &serde_json::to_vec(&assessment).unwrap(),
                "no-decision",
                &document.text,
                true,
            )
            .unwrap();

        let (status, view) =
            harness.send(party_status_request(&case_id, ACCUSED_SEED)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !view.to_string().contains("asked him to stop"),
            "the account leaked through labels: {view}"
        );
        let labels = view["assessment"]["labels"].as_array().unwrap();
        assert!(labels.iter().any(|l| l.as_str() == Some("S4")), "real codes survive: {labels:?}");

        // The moderator reviewing the appeal still sees all of it.
        let (_, panel) = harness
            .send(
                Request::get(format!("/v1/cases/{case_id}/status"))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(panel["assessment"]["labels"].to_string().contains("asked him to stop"));
    }

    /// The read and the write are separate lock acquisitions, so
    /// concurrent first filings could each take the unbounded arm and
    /// overrun the cap the "pending" arm enforces. The state move is
    /// conditioned on `none`, so only one can win.
    #[tokio::test]
    async fn concurrent_first_appeals_cannot_overrun_the_cap() {
        let harness = Harness::new();
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        harness.decide(&case_id, ban_decision()).await;

        let appeal = |n: usize| {
            signed(
                json!({"caseId": case_id, "kind": "appeal", "statement": format!("filing {n}")}),
                "signature",
                &[ACCUSED_SEED],
            )
        };
        let path = format!("/v1/cases/{case_id}/appeal");
        let (a, b, c) = tokio::join!(
            harness.post(&path, appeal(1)),
            harness.post(&path, appeal(2)),
            harness.post(&path, appeal(3)),
        );
        for (status, body) in [a, b, c] {
            assert!(
                status == StatusCode::OK || status == StatusCode::CONFLICT,
                "unexpected {status}: {body}"
            );
        }

        let filings = harness
            .state
            .store
            .events(&case_id)
            .unwrap()
            .iter()
            .filter(|(_, kind, _)| kind == "appeal_filed")
            .count();
        assert!(filings <= MAX_APPEALS_PER_CASE, "{filings} filings exceeded the cap");
        assert_eq!(
            harness.state.store.case(&case_id).unwrap().unwrap().appeal_state,
            "pending"
        );
    }

    // ─── Device recovery claims ──────────────────────────────────────

    fn recovery_claim_json(grantee_seed: [u8; 32]) -> Value {
        json!({
            "grantee": testing::key_reference(grantee_seed),
            "contact": "holder@example.org",
            "statement": "Bought this iPad second-hand last week; previous owner unknown.",
            "timestamp": util::format_timestamp(OffsetDateTime::now_utc()),
        })
    }

    async fn file_claim(harness: &Harness, grantee_seed: [u8; 32]) -> String {
        let body = signed(recovery_claim_json(grantee_seed), "signature", &[grantee_seed]);
        let (status, response) = harness.post("/v1/recovery-claims", body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["claimId"].as_str().unwrap().to_string()
    }

    fn claim_status_request(claim_id: &str, seed: [u8; 32]) -> Request<Body> {
        let timestamp = util::format_timestamp(OffsetDateTime::now_utc());
        let message = format!("recovery-claim-status:{claim_id}:{timestamp}");
        Request::get(format!("/v1/recovery-claims/{claim_id}"))
            .header("x-onym-key", testing::key_reference(seed))
            .header("x-onym-timestamp", timestamp)
            .header("x-onym-signature", testing::sign(seed, message.as_bytes()))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_recovery_claim_is_filed_once_per_identity() {
        let harness = Harness::new();
        let claim_id = file_claim(&harness, STRANGER_SEED).await;
        assert!(claim_id.starts_with("claim-"));

        // Filing moves nothing and decides nothing.
        let claim = harness.state.store.recovery_claim(&claim_id).unwrap().unwrap();
        assert_eq!(claim.state, "open");
        assert!(claim.grant_raw.is_none());

        // A second open claim for the same key is spam, not signal.
        let body = signed(recovery_claim_json(STRANGER_SEED), "signature", &[STRANGER_SEED]);
        let (status, _) = harness.post("/v1/recovery-claims", body).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn a_recovery_claim_needs_the_grantees_signature_and_a_fresh_timestamp() {
        let harness = Harness::new();

        // Signed by a different key than the named grantee.
        let body = signed(recovery_claim_json(STRANGER_SEED), "signature", &[ACCUSED_SEED]);
        let (status, _) = harness.post("/v1/recovery-claims", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Correctly signed, but stale.
        let mut stale = recovery_claim_json(STRANGER_SEED);
        stale["timestamp"] = json!("2026-08-01T00:00:00Z");
        let body = signed(stale, "signature", &[STRANGER_SEED]);
        let (status, _) = harness.post("/v1/recovery-claims", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_recovery_claim_requires_contact_and_statement() {
        let harness = Harness::new();
        for (field, value) in [("contact", json!("   ")), ("statement", json!(""))] {
            let mut claim = recovery_claim_json(STRANGER_SEED);
            claim[field] = value;
            let body = signed(claim, "signature", &[STRANGER_SEED]);
            let (status, response) = harness.post("/v1/recovery-claims", body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {response}");
        }
    }

    #[tokio::test]
    async fn claim_status_answers_only_the_key_the_claim_names() {
        let harness = Harness::new();
        let claim_id = file_claim(&harness, STRANGER_SEED).await;

        let (status, response) =
            harness.send(claim_status_request(&claim_id, STRANGER_SEED)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["state"], "open");
        assert!(response["grant"].is_null());

        // Another key, an unknown claim, and no credential all get the
        // same not-found.
        let (status, _) = harness.send(claim_status_request(&claim_id, ACCUSED_SEED)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) =
            harness.send(claim_status_request("claim-none", STRANGER_SEED)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = harness
            .send(
                Request::get(format!("/v1/recovery-claims/{claim_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_granted_claim_serves_a_grant_that_verifies_against_the_operator_key() {
        use ed25519_dalek::Verifier;

        let harness = Harness::new();
        let claim_id = file_claim(&harness, STRANGER_SEED).await;

        // A decided case for the grant to name.
        let case_id = open_case(&harness).await;
        let mut case = harness.state.store.case(&case_id).unwrap().unwrap();
        case.response_deadline = "2020-01-01T00:00:00Z".into();
        harness.state.store.put_case(&case).unwrap();
        let (status, response) = harness.decide(&case_id, ban_decision()).await;
        assert_eq!(status, StatusCode::OK, "{response}");

        // The moderator grants (through the store + signer, as the
        // panel handler does — the handler's own auth is covered by
        // the admin tests).
        let issued = crate::recovery::issue_grant(
            &case_id,
            &testing::key_reference(STRANGER_SEED),
            &harness.state.config.manifest.component_id,
            OffsetDateTime::now_utc(),
            &harness.state.signing_key,
        )
        .unwrap();
        assert!(harness
            .state
            .store
            .grant_recovery_claim(&claim_id, Some(&case_id), "verified by phone", &issued.raw, &issued.grant_ref, "2026-08-09T15:00:00Z")
            .unwrap());

        // The claimant polls and receives the exact signed bytes.
        let (status, response) =
            harness.send(claim_status_request(&claim_id, STRANGER_SEED)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["state"], "granted");
        let served = util::base64_decode(response["grant"].as_str().unwrap()).unwrap();
        assert_eq!(served, issued.raw, "the grant travels verbatim");

        // And they verify against the operator key over the canonical
        // grant bytes — the exact check the interface performs.
        let grant: Value = serde_json::from_slice(&served).unwrap();
        assert_eq!(grant["caseId"], json!(case_id));
        assert_eq!(grant["grantee"], json!(testing::key_reference(STRANGER_SEED)));
        let signing_bytes = canonical::grant_signing_bytes(&served).unwrap();
        let raw_signature =
            util::base64_decode(grant["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&raw_signature).unwrap();
        harness
            .state
            .signing_key
            .verifying_key()
            .verify(&signing_bytes, &signature)
            .unwrap();

        // Granting is on the case's event ledger.
        let events = harness.state.store.recent_events(20).unwrap();
        assert!(events
            .iter()
            .any(|(event_case, _, kind, detail)| event_case == &case_id
                && kind == "recovery_grant_issued"
                && detail.contains(&claim_id)));

        // One decision per claim.
        assert!(!harness
            .state
            .store
            .grant_recovery_claim(&claim_id, Some(&case_id), "again", &issued.raw, &issued.grant_ref, "2026-08-09T16:00:00Z")
            .unwrap());
    }

    #[tokio::test]
    async fn a_refused_claim_reports_its_reasons_to_the_claimant() {
        let harness = Harness::new();
        let claim_id = file_claim(&harness, STRANGER_SEED).await;
        assert!(harness
            .state
            .store
            .refuse_recovery_claim(&claim_id, "could not verify the holder", "2026-08-09T15:00:00Z")
            .unwrap());

        let (status, response) =
            harness.send(claim_status_request(&claim_id, STRANGER_SEED)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["state"], "refused");
        assert_eq!(response["reasoning"], "could not verify the holder");
        assert!(response["grant"].is_null());
    }
}
