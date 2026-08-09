//! HTTP surface.
//!
//! Four endpoints serve the iOS client's `EnforcementBackendClient`
//! seam; one receives verdicts from the designated authority; two are
//! for operators and auditors.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
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

const MAX_MANDATE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

pub struct AppState {
    pub config: Config,
    pub engine: Engine,
    pub countersigning: crate::countersigning::CountersigningKeys,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/enroll", post(enroll))
        .route("/v1/mandates/countersign", post(countersign))
        .route("/v1/gate-check", post(gate_check))
        .route("/v1/recover", post(recover))
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
        "interfaceKey": state.countersigning.root_reference(),
        "rotatedInterfaceKeys": state.countersigning.rotated().into_iter()
            .map(|(authority, (epoch, reference))| (authority.to_string(), serde_json::json!({"epoch": epoch, "key": reference})))
            .collect::<serde_json::Map<_, _>>(),
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
    validate_mandate_consent(&mandate.classes, &mandate.accepted_at, OffsetDateTime::now_utc())?;

    // The device binding must be one we issued to this identity.
    match state.engine.store.device_binding_for_user(&mandate.user)? {
        Some(binding) if binding == mandate.device_binding => {}
        Some(_) | None => {
            return Err(Error::BadRequest(
                "mandate deviceBinding was not issued to this identity".into(),
            ))
        }
    }

    // Keyed on the authority this mandate names, so rotating one
    // relationship does not invalidate the countersignatures held by
    // every other authority.
    let signature = state.countersigning.signing_key(&mandate.authority).sign(&signing_bytes);
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

fn validate_mandate_consent(
    classes: &[String],
    accepted_at: &str,
    now: OffsetDateTime,
) -> Result<(), Error> {
    if classes.is_empty() {
        return Err(Error::BadRequest("mandate must consent to at least one class".into()));
    }
    let accepted_at = util::parse_timestamp(accepted_at)
        .map_err(|e| Error::BadRequest(format!("acceptedAt: {e}")))?;
    if accepted_at > now + time::Duration::seconds(MAX_MANDATE_CLOCK_SKEW_SECONDS) {
        return Err(Error::BadRequest(
            "acceptedAt is too far in the future".into(),
        ));
    }
    Ok(())
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
    // Where the verdict is *stored* follows the record: if this case
    // was recovered onto a new enrollment, its verdicts live there now,
    // and a later one must fold into the recovered device rather than
    // the abandoned binding. The signature/binding check above still
    // ran against the mandate's (original) binding — only storage moves.
    let storage_binding = state
        .engine
        .store
        .binding_for_ingest(&parsed.case_id)?
        .unwrap_or_else(|| mandate.device_binding.clone());
    state.engine.store.put_verdict(
        &StoredVerdict {
            verdict_ref: verdict_ref.clone(),
            case_id: parsed.case_id.clone(),
            // The authority's own signed decision time. It is inside
            // the signing bytes, so it cannot be reordered in transit
            // — which is exactly why the fold uses it instead of the
            // moment this request happened to arrive.
            decided_at: parsed.decided_at.clone(),
            mandate_ref: parsed.mandate_ref.clone(),
            device_binding: storage_binding,
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

/// A holder presenting a moderator-issued recovery grant — there is
/// no self-serve unban: the claim, contact, and proof of new-holder
/// status went to the authority, a human decided, and the grant is
/// that decision, signed. The engine verifies the grant against the
/// consented operator key and answers on the stored verdicts'
/// authority; this handler only authenticates the session, binding it
/// to the exact grant bytes presented.
async fn recover(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RecoveryRequest>,
) -> Result<Json<RecoveryResult>, Error> {
    let token = decode_optional_token(request.device_token.as_deref())?;
    let grant_raw = util::base64_decode(&request.grant)
        .ok_or_else(|| Error::BadRequest("grant is not base64".into()))?;
    let grant_ref = util::sha256_hex(&canonical::grant_signing_bytes(&grant_raw)?);
    let signed = payload::recovery(
        token.as_deref(),
        &request.user_key,
        &grant_ref,
        &request.timestamp,
    );
    verify_user_signature(&request.user_key, &signed, &request.signature)?;
    claim_session(&state, &request.timestamp, &request.signature)?;

    let result = state
        .engine
        .recover(
            request.device_token.as_deref(),
            &request.user_key,
            &grant_raw,
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(Json(result))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Verifier};

    /// A signed-in-the-real-shape mandate and the state that will
    /// countersign it.
    ///
    /// Built through `countersign` itself rather than by calling the
    /// key derivation: a test that reaches for `CountersigningKeys`
    /// directly proves the derivation works and says nothing about
    /// whether the handler uses it — which is exactly the hole the
    /// first version of this had. Reverting the handler to a fixed key
    /// must fail *this* test.
    fn state_with(epochs: &[(&str, u32)]) -> Arc<AppState> {
        let config = Config {
            bind_addr: "127.0.0.1:0".into(),
            store_path: ":memory:".into(),
            p8_pem: None,
            key_id: None,
            team_id: None,
            environment: crate::devicecheck::Environment::Development,
            interface_signing_seed: [11u8; 32],
            interface_key_epochs: epochs
                .iter()
                .map(|(a, e)| ((*a).to_string(), *e))
                .collect(),
            interface_component_id: "onym:component:onym-ios".into(),
            enforce_signatures: true,
            authority_token: Some("token".into()),
            allow_unauthenticated_authority: false,
            audit_token: None,
            session_max_skew_secs: 300,
        };
        let countersigning = crate::countersigning::CountersigningKeys::new(
            config.interface_signing_seed,
            config.interface_key_epochs.clone(),
        );
        Arc::new(AppState {
            config,
            engine: crate::enforcement::Engine {
                store: crate::store::Store::in_memory().unwrap(),
                device_check: None,
            },
            countersigning,
        })
    }

    /// Ask the handler to countersign a mandate naming `authority`,
    /// and return the signature it produced over the same bytes the
    /// user signed.
    async fn countersigned_for(state: &Arc<AppState>, authority: &str) -> (Vec<u8>, Vec<u8>) {
        let user_key = SigningKey::from_bytes(&[5u8; 32]);
        let user = util::key_reference(user_key.verifying_key().as_bytes());
        // The binding must be one this interface issued to that identity.
        let binding = state.engine.store
            .enrollment_for(&user, "2026-08-08T00:00:00Z").unwrap().device_binding;

        let mut mandate = serde_json::json!({
            "mandateVersion": 1,
            "user": user,
            "interface": "onym:component:onym-ios",
            "authority": authority,
            "manifestHash": "0".repeat(64),
            "classes": ["csam"],
            "deviceBinding": binding,
            "acceptedAt": "2026-08-08T00:00:00Z",
        });
        let unsigned = serde_json::to_vec(&mandate).unwrap();
        let signing_bytes = crate::canonical::mandate_signing_bytes(&unsigned).unwrap();
        mandate["signatures"] =
            serde_json::json!([util::base64_encode(&user_key.sign(&signing_bytes).to_bytes())]);
        let body = serde_json::to_vec(&mandate).unwrap();

        let response = countersign(State(Arc::clone(state)), body.clone().into())
            .await
            .expect("the handler must countersign a well-formed mandate");
        let signature = util::base64_decode(&response.0.signature).expect("base64 signature");
        (crate::canonical::mandate_signing_bytes(&body).unwrap(), signature)
    }

    /// The wiring, exercised through the endpoint.
    ///
    /// A mandate naming a rotated authority must be countersigned with
    /// that authority's key and **not** the root — otherwise rotation
    /// is a derivation nothing calls.
    #[tokio::test]
    async fn the_handler_countersigns_with_the_named_authoritys_key() {
        let rotated = "onym:component:rotated";
        let untouched = "onym:component:untouched";
        let state = state_with(&[(rotated, 4)]);

        let root = SigningKey::from_bytes(&state.config.interface_signing_seed).verifying_key();
        let rotated_public =
            state.countersigning.signing_key(rotated).verifying_key();

        let (bytes, signature) = countersigned_for(&state, rotated).await;
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(
            rotated_public.verify(&bytes, &signature).is_ok(),
            "must be signed with the rotated authority's key"
        );
        assert!(
            root.verify(&bytes, &signature).is_err(),
            "and must not still verify under the root — that is what rotating means"
        );

        // An authority nobody rotated is still on the root, so it
        // notices nothing.
        let (bytes, signature) = countersigned_for(&state, untouched).await;
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(root.verify(&bytes, &signature).is_ok());
    }

    #[test]
    fn mandate_consent_rejects_empty_classes_and_future_timestamps() {
        let now = util::parse_timestamp("2026-08-08T12:00:00Z").unwrap();
        let classes = vec!["csam".to_string()];

        assert!(validate_mandate_consent(&classes, "2026-08-08T12:00:00Z", now).is_ok());
        assert!(validate_mandate_consent(&[], "2026-08-08T12:00:00Z", now).is_err());
        assert!(validate_mandate_consent(&classes, "2099-01-01T00:00:00Z", now).is_err());
    }

    // ─── POST /v1/recover ────────────────────────────────────────────
    //
    // The engine owns redemption; these exercise the handler's own
    // work, which the engine tests cannot reach: base64-decoding the
    // grant, and binding the session signature to *this grant's*
    // reference (its canonical-bytes hash) rather than to some other
    // payload. The device_check is unconfigured, so a request that
    // clears the handler lands on the engine's "attestation
    // unavailable" — which is exactly the signal that it cleared.

    fn recover_request(
        user: &SigningKey,
        grant_raw: &[u8],
        sign_over_ref: &str,
        timestamp: &str,
    ) -> RecoveryRequest {
        let user_ref = util::key_reference(user.verifying_key().as_bytes());
        let payload = crate::payload::recovery(None, &user_ref, sign_over_ref, timestamp);
        RecoveryRequest {
            device_token: None,
            user_key: user_ref,
            grant: util::base64_encode(grant_raw),
            timestamp: timestamp.to_string(),
            signature: util::base64_encode(&user.sign(&payload).to_bytes()),
        }
    }

    #[tokio::test]
    async fn recover_binds_the_session_signature_to_the_grant_reference() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let grant_raw = br#"{"grantVersion":1,"caseId":"c","grantee":"g","authority":"a","issuedAt":"t","signature":"s"}"#;
        let grant_ref = util::sha256_hex(&crate::canonical::grant_signing_bytes(grant_raw).unwrap());
        let now = util::format_timestamp(OffsetDateTime::now_utc());

        // Signed over the real grant reference: the handler accepts the
        // session and passes through to the engine, which — with no
        // DeviceCheck configured — refuses for want of attestation.
        let request = recover_request(&user, grant_raw, &grant_ref, &now);
        let result = recover(State(Arc::clone(&state)), Json(request)).await;
        assert!(
            matches!(&result, Err(Error::BadRequest(m)) if m.contains("attestation is unavailable")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn recover_rejects_a_session_signed_over_a_different_grant() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let grant_raw = br#"{"grantVersion":1,"caseId":"c","grantee":"g","authority":"a","issuedAt":"t","signature":"s"}"#;
        let now = util::format_timestamp(OffsetDateTime::now_utc());

        // Signed over some other reference: the handler reconstructs the
        // payload from the grant actually presented, so the signature
        // does not verify and the request is refused before the engine.
        let request = recover_request(&user, grant_raw, "a-different-grant-ref", &now);
        let result = recover(State(Arc::clone(&state)), Json(request)).await;
        assert!(matches!(&result, Err(Error::SignatureInvalid(_))), "{result:?}");
    }

    #[test]
    fn recovery_result_serializes_camelcase_fields() {
        // The client decodes camelCase; a struct-variant field must not
        // slip out snake_case. `rename_all_fields` is what guarantees it.
        let value = serde_json::to_value(RecoveryResult::MarkInForce {
            authority_contact: "appeals@a.org".into(),
            new_holder_url: Some("https://a.org/nh".into()),
            appeal_url: None,
        })
        .unwrap();
        assert_eq!(value["status"], "markInForce");
        assert_eq!(value["authorityContact"], "appeals@a.org");
        assert_eq!(value["newHolderUrl"], "https://a.org/nh");
        assert!(value.get("authority_contact").is_none());

        let unsettled =
            serde_json::to_value(RecoveryResult::CaseUnsettled { note: "n".into() }).unwrap();
        assert_eq!(unsettled["status"], "caseUnsettled");
    }

    #[tokio::test]
    async fn recover_rejects_a_grant_that_is_not_base64() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let now = util::format_timestamp(OffsetDateTime::now_utc());
        let user_ref = util::key_reference(user.verifying_key().as_bytes());
        let payload = crate::payload::recovery(None, &user_ref, "unused", &now);
        let request = RecoveryRequest {
            device_token: None,
            user_key: user_ref,
            grant: "not %% base64".into(),
            timestamp: now,
            signature: util::base64_encode(&user.sign(&payload).to_bytes()),
        };
        let result = recover(State(Arc::clone(&state)), Json(request)).await;
        assert!(
            matches!(&result, Err(Error::BadRequest(m)) if m.contains("grant is not base64")),
            "{result:?}"
        );
    }
}
