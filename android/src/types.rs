//! Wire types for the Android client's enforcement-backend seam, plus
//! the moderation objects from the contract (Moderation.md §5).
//!
//! The session shapes are this profile's own (Moderation-Device-Recall.md
//! §1 registers platform-scoped schema ids): camelCase fields, base64
//! bytes, RFC 3339 timestamps, absent-not-null optionals, and an
//! internally `status`-tagged gate result — deliberately *not* the
//! Swift-Codable single-key `{"banned":{"_0":…}}` accident the iOS
//! profile carries. The contract objects (mandate, verdict, manifest)
//! keep the cross-platform spellings (`operator`, `case-open`,
//! `final`), reproduced with `#[serde(rename)]`.
//!
//! Some fields exist only to pin the wire shape and are never read on
//! this side — that's the contract being complete, not dead weight, so
//! dead-code analysis is relaxed for this module alone.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ─── Session requests ────────────────────────────────────────────────

/// First-session enrollment. Every field the signature covers is
/// transmitted, so `payload::enrollment` can be recomputed here and
/// actually verified — the client deliberately sends the timestamp and
/// challenge for this reason. The integrity token is outside the
/// signed payload (it does not exist until after the requestHash is
/// computed); it binds to the same payload through the echoed hash.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRequest {
    pub user_key: String,
    pub timestamp: String,
    /// Base64 of the backend-issued challenge bytes, single-use.
    pub challenge: String,
    /// The Play Integrity token for this session, as Google returned
    /// it. Absent only when the device has no usable Play environment —
    /// the client never fabricates one.
    #[serde(default)]
    pub integrity_token: Option<String>,
    /// Base64 Ed25519 signature over `payload::enrollment`.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEnrollment {
    pub device_binding: String,
}

/// One gate check: a fresh integrity token and an identity signature
/// in the same session — the profile's only permitted
/// token↔enrollment linkage (Moderation-Device-Recall.md §5.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateCheckRequest {
    pub user_key: String,
    #[serde(default)]
    pub mandate_ref: Option<String>,
    pub timestamp: String,
    pub challenge: String,
    #[serde(default)]
    pub integrity_token: Option<String>,
    pub signature: String,
}

/// Just the signature: the client appends it to its own copy of the
/// mandate, so this round-trip cannot alter a consented field.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceCountersignature {
    pub signature: String,
}

// ─── Gate check result ───────────────────────────────────────────────

/// Why a successful check still refuses to let the app operate.
///
/// The last three are decided by the client's local grace arithmetic
/// rather than by this service — they're part of the shared vocabulary
/// so both ends name the same states, which is why the compiler sees
/// them as unconstructed here.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub enum CheckRequiredReason {
    TokenInvalid,
    AttestationUnavailable,
    ReidentificationRequired,
    OfflineGraceExpired,
    NeverChecked,
    ClockRollback,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BanState {
    pub verdict_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    pub authority_contact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_holder_url: Option<String>,
}

/// Internally tagged on `status` — the Android profile's own result
/// schema (`onym-moderation-google-device-recall-gate-result-v1`):
/// `{"status":"clear"}`, `{"status":"banned","ban":{...}}`, and so on.
/// The vocabulary (reasons, `BanState`, `CaseNotice` fields) is shared
/// with the iOS profile; only the envelope differs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum GateCheckResult {
    Clear,
    CaseOpen { notices: Vec<CaseNotice> },
    Banned { ban: BanState },
    CheckRequired { reason: CheckRequiredReason },
}

impl GateCheckResult {
    pub fn clear() -> Self {
        GateCheckResult::Clear
    }
    pub fn case_open(notices: Vec<CaseNotice>) -> Self {
        GateCheckResult::CaseOpen { notices }
    }
    pub fn banned(state: BanState) -> Self {
        GateCheckResult::Banned { ban: state }
    }
    pub fn check_required(reason: CheckRequiredReason) -> Self {
        GateCheckResult::CheckRequired { reason }
    }
}

// ─── Contract objects ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseNotice {
    #[serde(default = "one")]
    pub notice_version: u32,
    pub case_id: String,
    pub authority: String,
    pub accused: String,
    pub mandate_ref: String,
    pub class_id: String,
    pub evidence_summary: String,
    pub response_deadline: String,
    pub decision_deadline: String,
    pub signature: String,
}

fn one() -> u32 {
    1
}

/// The two device-mark states (Moderation.md §5.7), as verdicts spell
/// them. Spec JSON keys are `case-open` / `banned`. (The platform
/// mapping to `bitFirst`/`bitSecond` lives in `play_integrity::Bits`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marks {
    #[serde(rename = "case-open")]
    pub case_open: bool,
    pub banned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    OpenCase,
    Dismiss,
    Ban,
}

/// A signed verdict (Moderation.md §5.6) — the only object that moves
/// device marks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    #[serde(default = "one")]
    pub verdict_version: u32,
    pub case_id: String,
    pub authority: String,
    pub mandate_ref: String,
    pub accused_keys: Vec<String>,
    pub device_binding: String,
    pub class_id: String,
    pub disposition: Disposition,
    pub marks: Marks,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban_expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_after: Option<String>,
    pub reasoning: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_deadline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_holder_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_contact: Option<String>,
    pub decided_at: String,
    pub signature: String,
    #[serde(rename = "final")]
    pub is_final: bool,
}

/// The consent artifact (Moderation.md §5.3). Deserialized from the
/// client's JSON for countersigning; the raw bytes are what actually
/// get hashed, so this type is only used for its fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerationMandate {
    #[serde(default = "one")]
    pub mandate_version: u32,
    pub user: String,
    pub interface: String,
    pub authority: String,
    pub manifest_hash: String,
    pub classes: Vec<String>,
    pub device_binding: String,
    pub accepted_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

/// What an authority POSTs to `/v1/verdicts`.
///
/// The manifest travels as **base64 of its exact bytes**, not as a
/// nested object: the mandate pins `SHA-256` of the bytes the user
/// consented to, and only the original bytes can reproduce that hash.
/// Re-serializing a parsed manifest would not, which is precisely what
/// lets the hash bind the manifest — and therefore bind the operator
/// key a verdict signature is checked against.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictSubmission {
    pub verdict: serde_json::Value,
    pub consented_manifest: String,
}

/// A violation class's consented terms, as the authority's manifest
/// declares them. The backend needs these to validate a verdict's
/// derived deadlines (§5.6 constraint 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationClass {
    pub class_id: String,
    pub response_window: String,
    pub decision_deadline: String,
    /// `"permanent"` or a `P<n>D` duration.
    pub ban_term: String,
    pub appeal_window: String,
    /// `"suspensive"` or `"non-suspensive"`.
    pub appeal_effect: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityManifest {
    pub component_id: String,
    #[serde(rename = "operator")]
    pub operator_key: String,
    pub violation_classes: Vec<ViolationClass>,
}

impl AuthorityManifest {
    pub fn violation_class(&self, class_id: &str) -> Option<&ViolationClass> {
        self.violation_classes.iter().find(|c| c.class_id == class_id)
    }
}
