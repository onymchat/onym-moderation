//! HTTP surface.
//!
//! Three endpoints serve the iOS client's `EnforcementBackendClient`
//! seam; one receives verdicts from the designated authority; two are
//! for operators and auditors.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::canonical;
use crate::config::Config;
use crate::enforcement::Engine;
use crate::error::Error;
use crate::payload;
use crate::store::{MandateRecord, StoredVerdict};
use crate::types::*;
use crate::util;
use crate::verdict::{self, Outcome, ValidationInput};

pub struct AppState {
    pub config: Config,
    pub engine: Engine,
    pub signing_key: SigningKey,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/enroll", post(enroll))
        .route("/v1/mandates/countersign", post(countersign))
        .route("/v1/gate-check", post(gate_check))
        .route("/v1/verdicts", post(receive_verdict))
        .route("/v1/write-log", get(write_log))
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "deviceCheck": state.config.device_check_configured(),
        "enforceSignatures": state.config.enforce_signatures,
        "interface": state.config.interface_component_id,
        "interfaceKey": util::key_reference(state.signing_key.verifying_key().as_bytes()),
    }))
}

// ─── Session endpoints ───────────────────────────────────────────────

/// First-session enrollment. The (identity signature, device token)
/// pair presented together is the only token↔enrollment linkage the
/// profile permits.
async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<DeviceEnrollment>, Error> {
    let token = decode_optional_token(request.device_token.as_deref())?;
    let signed = payload::enrollment(token.as_deref(), &request.user_key, &request.timestamp);
    verify_user_signature(&request.user_key, &signed, &request.signature)?;
    claim_session(&state, &request.timestamp, &request.signature)?;

    // Establishing the linkage the profile describes means Apple has to
    // agree the token is real. Without this the "device" in
    // deviceBinding is only an assertion by whoever called us.
    if let Some(device_check) = state.engine.device_check.as_ref() {
        let Some(raw_token) = request.device_token.as_deref() else {
            return Err(Error::BadRequest(
                "deviceToken is required when DeviceCheck is configured".into(),
            ));
        };
        if device_check.query(raw_token).await?.is_none() {
            return Err(Error::SignatureInvalid(
                "Apple did not validate this device token".into(),
            ));
        }
    }

    let now = util::format_timestamp(OffsetDateTime::now_utc());
    let enrollment = state.engine.store.enrollment_for(&request.user_key, &now)?;
    Ok(Json(DeviceEnrollment { device_binding: enrollment.device_binding }))
}

/// Countersign the mandate the user signed — and return only the
/// signature. Handing back a whole mandate would let this service
/// alter a consented field behind the user's signature; the client
/// appends what we return to its own copy.
async fn countersign(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<InterfaceCountersignature>, Error> {
    let mandate: ModerationMandate = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed mandate: {e}")))?;

    if mandate.interface != state.config.interface_component_id {
        return Err(Error::BadRequest(format!(
            "mandate names interface {}, this is {}",
            mandate.interface, state.config.interface_component_id
        )));
    }

    // The user's own signature must verify before we add ours: a
    // countersignature asserts that this interface witnessed *that
    // user* consenting.
    let signing_bytes = canonical::mandate_signing_bytes(&body)?;
    // Exactly one signature: the user's. A mandate arriving with more
    // has already been countersigned, and `first()` would then be
    // verifying whichever signature happened to be at index 0.
    let user_signature = match mandate.signatures.as_slice() {
        [user_signature] => user_signature,
        [] => return Err(Error::BadRequest("mandate carries no user signature".into())),
        _ => {
            return Err(Error::BadRequest(
                "mandate is already countersigned; expected exactly the user's signature".into(),
            ))
        }
    };
    verify_user_signature(&mandate.user, &signing_bytes, user_signature)?;

    // The device binding must be one we issued to this identity.
    match state.engine.store.device_binding_for_user(&mandate.user)? {
        Some(binding) if binding == mandate.device_binding => {}
        Some(_) | None => {
            return Err(Error::BadRequest(
                "mandate deviceBinding was not issued to this identity".into(),
            ))
        }
    }

    let signature = state.signing_key.sign(&signing_bytes);
    let mandate_ref = util::sha256_hex(&signing_bytes);
    let now = util::format_timestamp(OffsetDateTime::now_utc());

    state.engine.store.put_mandate(
        &MandateRecord {
            mandate_ref,
            user_key: mandate.user.clone(),
            authority: mandate.authority.clone(),
            device_binding: mandate.device_binding.clone(),
            manifest_hash: mandate.manifest_hash.clone(),
            classes: mandate.classes.clone(),
        },
        &body,
        &now,
    )?;

    Ok(Json(InterfaceCountersignature {
        signature: util::base64_encode(&signature.to_bytes()),
    }))
}

async fn gate_check(
    State(state): State<Arc<AppState>>,
    Json(request): Json<GateCheckRequest>,
) -> Result<Json<GateCheckResult>, Error> {
    let token = decode_optional_token(request.device_token.as_deref())?;
    let signed = payload::gate_check(
        token.as_deref(),
        &request.user_key,
        request.mandate_ref.as_deref(),
        &request.timestamp,
    );
    verify_user_signature(&request.user_key, &signed, &request.signature)?;
    claim_session(&state, &request.timestamp, &request.signature)?;

    let result = state
        .engine
        .gate_check(
            request.device_token.as_deref(),
            &request.user_key,
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(Json(result))
}

// ─── Authority endpoint ──────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerdictAccepted {
    verdict_ref: String,
    /// `executed` once the marks are written, `stored` while a valid
    /// ban waits for its `executeAfter`, `queued` when the device has
    /// no live session to write through.
    status: &'static str,
}

/// The designated authority delivers a signed verdict. This service
/// validates its shape mechanically and never its wisdom, then either
/// executes it or queues it for the device's next session.
async fn receive_verdict(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<VerdictAccepted>, Error> {
    authorize_authority(&state, &headers)?;

    let submission: VerdictSubmission = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(format!("malformed submission: {e}")))?;

    let verdict_bytes = serde_json::to_vec(&submission.verdict)
        .map_err(|e| Error::Internal(format!("re-encode verdict: {e}")))?;
    let parsed: Verdict = serde_json::from_slice(&verdict_bytes)
        .map_err(|e| Error::BadRequest(format!("malformed verdict: {e}")))?;
    let signing_bytes = canonical::verdict_signing_bytes(&verdict_bytes)?;
    let verdict_ref = util::sha256_hex(&signing_bytes);

    let mandate = state
        .engine
        .store
        .mandate(&parsed.mandate_ref)?
        .ok_or(Error::NoMandate)?;

    // The consented manifest carries both the class terms this verdict
    // must respect and the operator key its signature is checked
    // against. Taking either from the request unchecked would make
    // enforcement circular — a caller could supply its own key, sign
    // with the matching private key, and pass. The mandate pins the
    // hash of the manifest the *user* consented to, so requiring the
    // supplied bytes to reproduce that hash is what makes the key
    // trustworthy.
    let manifest_raw = util::base64_decode(&submission.consented_manifest)
        .ok_or_else(|| Error::BadRequest("consentedManifest is not base64".into()))?;
    if util::sha256_hex(&manifest_raw) != mandate.manifest_hash {
        return Err(Error::VerdictInvalid(
            "consentedManifest does not hash to the manifest the mandate pinned".into(),
        ));
    }
    let manifest: AuthorityManifest = serde_json::from_slice(&manifest_raw)
        .map_err(|e| Error::BadRequest(format!("malformed consentedManifest: {e}")))?;
    if manifest.component_id != mandate.authority {
        return Err(Error::VerdictInvalid(
            "consentedManifest belongs to a different authority than the mandate".into(),
        ));
    }
    state
        .engine
        .store
        .attach_manifest(&parsed.mandate_ref, &manifest_raw)?;

    let violation_class = manifest.violation_class(&parsed.class_id).cloned();
    let operator_key = manifest.operator_key.clone();

    let outcome = verdict::validate(ValidationInput {
        verdict: &parsed,
        signing_bytes: &signing_bytes,
        mandate_authority: &mandate.authority,
        mandate_user: &mandate.user_key,
        mandate_device_binding: &mandate.device_binding,
        mandate_classes: &mandate.classes,
        authority_operator_key: &operator_key,
        violation_class: violation_class.as_ref(),
        now: OffsetDateTime::now_utc(),
        enforce_signature: state.config.enforce_signatures,
    })?;

    let now = util::format_timestamp(OffsetDateTime::now_utc());
    state.engine.store.put_verdict(
        &StoredVerdict {
            verdict_ref: verdict_ref.clone(),
            case_id: parsed.case_id.clone(),
            mandate_ref: parsed.mandate_ref.clone(),
            device_binding: mandate.device_binding.clone(),
            raw: verdict_bytes.clone(),
            disposition: match parsed.disposition {
                Disposition::OpenCase => "open-case".into(),
                Disposition::Dismiss => "dismiss".into(),
                Disposition::Ban => "ban".into(),
            },
            ban_expires: parsed.ban_expires.clone(),
            execute_after: parsed.execute_after.clone(),
            executed: false,
            superseded: false,
        },
        &now,
    )?;

    // A terminal verdict supersedes its case's interim open-case one.
    if !matches!(parsed.disposition, Disposition::OpenCase) {
        state.engine.store.supersede_open_case(&parsed.case_id)?;
    }

    // Writing needs a fresh token from the target device, which we do
    // not have here: the write executes at the device's next session
    // (profile §6). The identity refusal is in force meanwhile because
    // the verdict is already stored.
    let status = match outcome {
        Outcome::Execute => "queued",
        Outcome::StoreUntil(_) => "stored",
    };
    tracing::info!(%verdict_ref, case_id = %parsed.case_id, status, "verdict accepted");

    Ok(Json(VerdictAccepted { verdict_ref, status }))
}

// ─── Audit ───────────────────────────────────────────────────────────

/// The write log, plus the result of recomputing its hash chain. This
/// is what an audit-seat attestation reads.
async fn write_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    authorize_audit(&state, &headers)?;
    let entries = state.engine.store.write_log(1000)?;
    let broken_at = state.engine.store.verify_write_log()?;
    Ok(Json(json!({
        "chainIntact": broken_at.is_none(),
        "brokenAtSequence": broken_at,
        "entries": entries.iter().map(|e| json!({
            "sequence": e.sequence,
            "recordedAt": e.recorded_at,
            "deviceBinding": e.device_binding,
            "authorizedBy": e.authorized_by,
            "caseOpen": e.case_open,
            "banned": e.banned,
            "outcome": e.outcome,
            "previousHash": e.previous_hash,
            "entryHash": e.entry_hash,
        })).collect::<Vec<_>>(),
    })))
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// A signed session is fresh and single-use.
///
/// The signature covers a timestamp, so without a freshness check a
/// captured body is replayable forever. The window bounds that; taking
/// the signature single-use closes it entirely, since a replay inside
/// the window presents the same signature bytes.
fn claim_session(state: &AppState, timestamp: &str, signature: &str) -> Result<(), Error> {
    let stamped = util::parse_timestamp(timestamp)
        .map_err(|e| Error::BadRequest(format!("timestamp: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let skew = (now - stamped).whole_seconds().abs();
    if skew > state.config.session_max_skew_secs {
        return Err(Error::SignatureInvalid(format!(
            "session timestamp is {skew}s from now (limit {}s)",
            state.config.session_max_skew_secs
        )));
    }

    let retain_before =
        util::format_timestamp(now - time::Duration::seconds(state.config.session_max_skew_secs * 2));
    let fresh = state.engine.store.claim_signature(
        signature,
        &util::format_timestamp(now),
        &retain_before,
    )?;
    if !fresh {
        return Err(Error::SignatureInvalid("session signature already used".into()));
    }
    Ok(())
}

fn decode_optional_token(raw: Option<&str>) -> Result<Option<Vec<u8>>, Error> {
    match raw {
        None => Ok(None),
        Some(value) => util::base64_decode(value)
            .map(Some)
            .ok_or_else(|| Error::BadRequest("deviceToken is not base64".into())),
    }
}

/// Verify an Ed25519 signature made by the user's identity key, named
/// by its `onym:key:<hex>` reference.
fn verify_user_signature(user_key: &str, message: &[u8], signature: &str) -> Result<(), Error> {
    let key_bytes = util::key_bytes_from_reference(user_key)
        .ok_or_else(|| Error::BadRequest(format!("{user_key:?} is not an onym:key: reference")))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| Error::BadRequest("user key is not 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::BadRequest(format!("user key is not a valid Ed25519 key: {e}")))?;
    let raw = util::base64_decode(signature)
        .ok_or_else(|| Error::BadRequest("signature is not base64".into()))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|e| Error::BadRequest(format!("signature is malformed: {e}")))?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::SignatureInvalid("identity signature did not verify".into()))
}

/// Transport-level authentication for the authority endpoint. The
/// verdict's own signature is what authorizes a mark; this only keeps
/// the endpoint from being an open write to the store.
fn authorize_authority(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    let Some(expected) = state.config.authority_token.as_deref() else {
        // Fail closed. An unset token used to mean "open", which made
        // the verdict endpoint an unauthenticated write into the store
        // for anyone who found the host.
        if state.config.allow_unauthenticated_authority {
            tracing::warn!(
                "verdict accepted without authority authentication \
                 (MODERATION_ALLOW_UNAUTHENTICATED_AUTHORITY=true)"
            );
            return Ok(());
        }
        return Err(Error::SignatureInvalid(
            "MODERATION_AUTHORITY_TOKEN is not configured; the verdict endpoint is closed".into(),
        ));
    };
    require_bearer(headers, expected, "authority")
}

/// The write log names every device binding, verdict reference, and
/// mark transition. It is for the operator and the audit seat, not for
/// the internet, so an unset token closes it rather than opening it.
fn authorize_audit(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    let Some(expected) = state.config.audit_token.as_deref() else {
        return Err(Error::SignatureInvalid(
            "MODERATION_AUDIT_TOKEN is not configured; the write log is closed".into(),
        ));
    };
    require_bearer(headers, expected, "audit")
}

fn require_bearer(headers: &HeaderMap, expected: &str, label: &str) -> Result<(), Error> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        // Constant-time compare: these are shared secrets, and a
        // byte-by-byte early exit leaks their prefix.
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err(Error::SignatureInvalid(format!(
            "{label} bearer token missing or wrong"
        ))),
    }
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.iter().zip(rhs).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}
