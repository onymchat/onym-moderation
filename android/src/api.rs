//! HTTP surface.
//!
//! Five endpoints serve the Android client's enforcement-backend seam
//! (challenge, enroll, countersign, gate-check, and the reserved
//! recover); one receives verdicts from the designated authority; two
//! are for operators and auditors.

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
    /// Fixed-window counter for the unauthenticated challenge
    /// endpoint: (window start, issues so far). See `challenge` for
    /// why the endpoint needs its own throttle at all.
    pub challenge_window: std::sync::Mutex<(OffsetDateTime, u32)>,
}

impl AppState {
    pub fn new(
        config: Config,
        engine: Engine,
        countersigning: crate::countersigning::CountersigningKeys,
    ) -> Self {
        Self {
            config,
            engine,
            countersigning,
            challenge_window: std::sync::Mutex::new((OffsetDateTime::UNIX_EPOCH, 0)),
        }
    }
}

/// Issues per fixed one-minute window before `/v1/challenge` answers
/// 429. Generous against real clients (one challenge per session; the
/// app's scheduler coalesces), tight against a loop hammering an
/// unauthenticated endpoint.
const MAX_CHALLENGES_PER_MINUTE: u32 = 600;

/// Unexpired, unconsumed challenges the store will hold before
/// issuance pauses. Bounds the table at cap × row size regardless of
/// request rate; legitimate load never approaches it (challenges live
/// `MODERATION_CHALLENGE_TTL_SECS` and are single-use).
const MAX_OUTSTANDING_CHALLENGES: i64 = 10_000;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/challenge", post(challenge))
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
        "playIntegrity": state.config.play_configured(),
        "packageName": state.config.play_package_name,
        "enforceSignatures": state.config.enforce_signatures,
        "interface": state.config.interface_component_id,
        "interfaceKey": state.countersigning.root_reference(),
        "rotatedInterfaceKeys": state.countersigning.rotated().into_iter()
            .map(|(authority, (epoch, reference))| (authority.to_string(), serde_json::json!({"epoch": epoch, "key": reference})))
            .collect::<serde_json::Map<_, _>>(),
    }))
}

// ─── Session endpoints ───────────────────────────────────────────────

// ─── Challenge ───────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ChallengeRequest {
    purpose: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuedChallenge {
    /// Base64 of 32 random bytes. The client folds the *raw bytes*
    /// into its signed payload and passes the payload's hash to Play
    /// Integrity as `requestHash`; it presents this base64 string back
    /// verbatim so the payload can be recomputed here.
    challenge: String,
    expires_at: String,
}

/// Issue a single-use challenge for an enroll or gate-check session.
/// Unauthenticated by design — a challenge authorizes nothing by
/// itself; it only lets the later signed request prove freshness and
/// give Play's `requestHash` something server-chosen to bind.
///
/// Unauthenticated also means abusable: without a bound, a loop grows
/// the challenges table at request-rate × TTL. Two caps close that —
/// a fixed-window issue rate (429, which the app treats as a
/// retryable backoff and the authority's delivery classifier already
/// files under retry), and a ceiling on outstanding rows so the table
/// stays bounded even if the window constant is ever raised.
async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<IssuedChallenge>, Error> {
    if !matches!(request.purpose.as_str(), "enroll" | "gate") {
        return Err(Error::BadRequest(format!(
            "unknown challenge purpose {:?} (expected enroll|gate)",
            request.purpose
        )));
    }
    claim_challenge_issue_slot(&state, OffsetDateTime::now_utc())?;
    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    let challenge = util::base64_encode(&raw);
    let now = OffsetDateTime::now_utc();
    let expires_at =
        util::format_timestamp(now + time::Duration::seconds(state.config.challenge_ttl_secs));
    state.engine.store.issue_challenge(
        &challenge,
        &request.purpose,
        &util::format_timestamp(now),
        &expires_at,
    )?;
    Ok(Json(IssuedChallenge { challenge, expires_at }))
}

/// First-session enrollment. The (identity signature, integrity token)
/// pair presented together — bound to one payload by the signature and
/// the echoed requestHash — is the only token↔enrollment linkage the
/// profile permits.
async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<DeviceEnrollment>, Error> {
    let challenge = decode_challenge(&request.challenge)?;
    let signed = payload::enrollment(&challenge, &request.user_key, &request.timestamp);
    verify_user_signature(&request.user_key, &signed, &request.signature)?;
    claim_session(&state, &request.timestamp, &request.signature)?;
    claim_challenge(&state, &request.challenge, "enroll")?;

    // Establishing the linkage the profile describes means Google has
    // to agree the token is real, fresh, and minted for exactly this
    // request. Without this the "device" in deviceBinding is only an
    // assertion by whoever called us.
    if let Some(play) = state.engine.play.as_ref() {
        let Some(token) = request.integrity_token.as_deref() else {
            return Err(Error::BadRequest(
                "integrityToken is required when Play Integrity is configured".into(),
            ));
        };
        let request_hash = payload::request_hash(&signed);
        let Some(bits) = state
            .engine
            .verified_bits(play, token, &request_hash, OffsetDateTime::now_utc())
            .await?
        else {
            return Err(Error::SignatureInvalid(
                "Google did not validate this integrity token".into(),
            ));
        };
        // A device already carrying the banned mark does not get a
        // fresh enrollment; the gate would refuse it anyway, and the
        // route out is the authority's re-identification/new-holder
        // procedure, not a new binding.
        if bits.banned {
            return Err(Error::BadRequest(
                "this device carries a banned mark; enrollment cannot proceed — contact \
                 the authority named in the verification screen"
                    .into(),
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
    let challenge = decode_challenge(&request.challenge)?;
    let signed = payload::gate_check(
        &challenge,
        &request.user_key,
        request.mandate_ref.as_deref(),
        &request.timestamp,
    );
    verify_user_signature(&request.user_key, &signed, &request.signature)?;
    claim_session(&state, &request.timestamp, &request.signature)?;
    claim_challenge(&state, &request.challenge, "gate")?;

    let request_hash = payload::request_hash(&signed);
    let result = state
        .engine
        .gate_check(
            request.integrity_token.as_deref(),
            &request_hash,
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
    // Without recovery there is no record movement: a case's verdicts
    // always live on the mandate's own binding. (Re-adding recovery
    // means reintroducing apple/'s `binding_for_ingest` routing here.)
    let storage_binding = mandate.device_binding.clone();
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

/// Device recovery is deliberately not implemented yet on this
/// profile. The path is reserved so the client contract keeps its
/// shape, and the answer routes the holder to a human rather than
/// silently bricking them (Moderation-Device-Recall.md §5.2 item 3):
/// the ban and check-required responses already carry the authority's
/// contact and new-holder routes.
async fn recover() -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "message": "device recovery is not yet available on this interface; \
                        contact the authority named in your ban or case notice",
        })),
    )
}

fn decode_challenge(raw: &str) -> Result<Vec<u8>, Error> {
    util::base64_decode(raw).ok_or_else(|| Error::BadRequest("challenge is not base64".into()))
}

/// One issue slot from the fixed window, plus the outstanding-rows
/// ceiling. Split from the handler so the arithmetic is testable with
/// an injected `now`.
fn claim_challenge_issue_slot(state: &AppState, now: OffsetDateTime) -> Result<(), Error> {
    {
        let mut window = state.challenge_window.lock().unwrap();
        if now - window.0 >= time::Duration::minutes(1) {
            *window = (now, 0);
        }
        if window.1 >= MAX_CHALLENGES_PER_MINUTE {
            return Err(Error::RateLimited(
                "challenge issuance is throttled; retry shortly".into(),
            ));
        }
        window.1 += 1;
    }
    let outstanding = state
        .engine
        .store
        .outstanding_challenges(&util::format_timestamp(now))?;
    if outstanding >= MAX_OUTSTANDING_CHALLENGES {
        return Err(Error::RateLimited(
            "too many unconsumed challenges outstanding; retry shortly".into(),
        ));
    }
    Ok(())
}

/// Consume the presented challenge. Refusal is retryable from the
/// client's side — it fetches a fresh challenge and re-signs — so this
/// is a 400, not a gate result.
fn claim_challenge(state: &AppState, challenge: &str, purpose: &str) -> Result<(), Error> {
    let now = util::format_timestamp(OffsetDateTime::now_utc());
    if !state.engine.store.claim_challenge(challenge, purpose, &now)? {
        return Err(Error::BadRequest(
            "challenge is unknown, expired, already used, or for a different purpose; \
             fetch a fresh one"
                .into(),
        ));
    }
    Ok(())
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
            play_sa_key: None,
            play_package_name: None,
            play_cert_sha256_digests: vec![],
            play_token_max_age_secs: 600,
            challenge_ttl_secs: 600,
            propagation_grace_secs: 60,
            interface_signing_seed: [11u8; 32],
            interface_key_epochs: epochs
                .iter()
                .map(|(a, e)| ((*a).to_string(), *e))
                .collect(),
            interface_component_id: "onym:component:onym-android".into(),
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
        Arc::new(AppState::new(
            config,
            crate::enforcement::Engine {
                store: crate::store::Store::in_memory().unwrap(),
                play: None,
                propagation_grace_secs: 60,
            },
            countersigning,
        ))
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
            "interface": "onym:component:onym-android",
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

    // ─── Challenge + session flow ────────────────────────────────────
    //
    // The engine owns token verification; with Play unconfigured these
    // exercise the handler's own work: challenge decode, signature over
    // the challenge bytes, and single-use/purpose-bound claiming.

    async fn issued_challenge(state: &Arc<AppState>, purpose: &str) -> IssuedChallenge {
        challenge(
            State(Arc::clone(state)),
            Json(ChallengeRequest { purpose: purpose.into() }),
        )
        .await
        .expect("a well-formed purpose must be issued a challenge")
        .0
    }

    fn enroll_request_with(
        user: &SigningKey,
        challenge_b64: &str,
        timestamp: &str,
    ) -> EnrollmentRequest {
        let user_ref = util::key_reference(user.verifying_key().as_bytes());
        let raw = util::base64_decode(challenge_b64).expect("challenge is base64");
        let payload = crate::payload::enrollment(&raw, &user_ref, timestamp);
        EnrollmentRequest {
            user_key: user_ref,
            timestamp: timestamp.to_string(),
            challenge: challenge_b64.to_string(),
            integrity_token: None,
            signature: util::base64_encode(&user.sign(&payload).to_bytes()),
        }
    }

    #[tokio::test]
    async fn an_unknown_challenge_purpose_is_refused() {
        let state = state_with(&[]);
        let result = challenge(
            State(Arc::clone(&state)),
            Json(ChallengeRequest { purpose: "recover".into() }),
        )
        .await;
        assert!(matches!(&result, Err(Error::BadRequest(m)) if m.contains("purpose")));
    }

    #[tokio::test]
    async fn a_challenge_is_single_use() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let issued = issued_challenge(&state, "enroll").await;

        let now = util::format_timestamp(OffsetDateTime::now_utc());
        let first = enroll(
            State(Arc::clone(&state)),
            Json(enroll_request_with(&user, &issued.challenge, &now)),
        )
        .await;
        assert!(first.is_ok(), "{first:?}");

        // A second presentation — fresh signature and timestamp, so the
        // session guards pass — must die on the spent challenge.
        let later =
            util::format_timestamp(OffsetDateTime::now_utc() + time::Duration::seconds(1));
        let second = enroll(
            State(Arc::clone(&state)),
            Json(enroll_request_with(&user, &issued.challenge, &later)),
        )
        .await;
        assert!(
            matches!(&second, Err(Error::BadRequest(m)) if m.contains("challenge")),
            "{second:?}"
        );
    }

    /// An enroll challenge presented at the gate (or vice versa) is
    /// refused: the purpose column, not just the payload context,
    /// separates the two flows.
    #[tokio::test]
    async fn a_challenge_is_purpose_bound() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let issued = issued_challenge(&state, "gate").await;

        let now = util::format_timestamp(OffsetDateTime::now_utc());
        let result = enroll(
            State(Arc::clone(&state)),
            Json(enroll_request_with(&user, &issued.challenge, &now)),
        )
        .await;
        assert!(
            matches!(&result, Err(Error::BadRequest(m)) if m.contains("challenge")),
            "{result:?}"
        );
    }

    /// The signature must cover the challenge bytes actually presented:
    /// signing over some other challenge is an invalid signature, not a
    /// challenge problem — the payload is reconstructed here.
    #[tokio::test]
    async fn the_signature_binds_the_presented_challenge() {
        let state = state_with(&[]);
        let user = SigningKey::from_bytes(&[7u8; 32]);
        let issued = issued_challenge(&state, "enroll").await;
        let other = issued_challenge(&state, "enroll").await;

        let now = util::format_timestamp(OffsetDateTime::now_utc());
        let mut request = enroll_request_with(&user, &other.challenge, &now);
        request.challenge = issued.challenge; // signed over `other`
        let result = enroll(State(Arc::clone(&state)), Json(request)).await;
        assert!(matches!(&result, Err(Error::SignatureInvalid(_))), "{result:?}");
    }

    /// The fixed window: the cap-plus-first refusal answers 429, and a
    /// fresh window opens slots again.
    #[test]
    fn challenge_issuance_is_throttled_per_window() {
        let state = state_with(&[]);
        let start = util::parse_timestamp("2026-08-08T12:00:00Z").unwrap();
        for _ in 0..MAX_CHALLENGES_PER_MINUTE {
            claim_challenge_issue_slot(&state, start).unwrap();
        }
        let refused = claim_challenge_issue_slot(&state, start);
        assert!(matches!(refused, Err(Error::RateLimited(_))), "{refused:?}");

        let next_window = start + time::Duration::seconds(61);
        assert!(claim_challenge_issue_slot(&state, next_window).is_ok());
    }

    /// The table ceiling: outstanding unconsumed rows pause issuance
    /// regardless of the window, so an attacker cannot grow the store
    /// past cap × row size.
    #[test]
    fn challenge_issuance_pauses_at_the_outstanding_ceiling() {
        let state = state_with(&[]);
        let now = "2026-08-08T12:00:00Z";
        for i in 0..MAX_OUTSTANDING_CHALLENGES {
            state
                .engine
                .store
                .issue_challenge(&format!("challenge-{i}"), "gate", now, "2026-08-08T12:10:00Z")
                .unwrap();
        }
        let refused =
            claim_challenge_issue_slot(&state, util::parse_timestamp(now).unwrap());
        assert!(matches!(refused, Err(Error::RateLimited(_))), "{refused:?}");
    }

    #[test]
    fn mandate_consent_rejects_empty_classes_and_future_timestamps() {
        let now = util::parse_timestamp("2026-08-08T12:00:00Z").unwrap();
        let classes = vec!["csam".to_string()];

        assert!(validate_mandate_consent(&classes, "2026-08-08T12:00:00Z", now).is_ok());
        assert!(validate_mandate_consent(&[], "2026-08-08T12:00:00Z", now).is_err());
        assert!(validate_mandate_consent(&classes, "2099-01-01T00:00:00Z", now).is_err());
    }
}
