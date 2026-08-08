//! Wire types shared with the iOS client's `EnforcementBackendClient`
//! seam (`Packages/OnymModeration` in onym-ios), plus the moderation
//! objects from the contract (Moderation.md §5).
//!
//! Field names here must match the Swift `Codable` types exactly — the
//! client encodes with its property names except where a `CodingKeys`
//! maps them (`operator`, `case-open`, `final`), and those exceptions
//! are reproduced with `#[serde(rename)]`.
//!
//! Some fields exist only to pin the wire shape and are never read on
//! this side — that's the contract being complete, not dead weight, so
//! dead-code analysis is relaxed for this module alone.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ─── Session requests ────────────────────────────────────────────────

/// First-session enrollment. Every field the signature covers is
/// transmitted, so `signed_payload` can be recomputed here and actually
/// verified — the client deliberately sends the timestamp for this
/// reason.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRequest {
    /// Base64 `DCDevice` token, or absent when attestation is
    /// unavailable (simulator, enterprise build). The client never
    /// fabricates one.
    #[serde(default)]
    pub device_token: Option<String>,
    pub user_key: String,
    pub timestamp: String,
    /// Base64 Ed25519 signature over `payload::enrollment`.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEnrollment {
    pub device_binding: String,
}

/// One gate check: a fresh device token and an identity signature in
/// the same session — the profile's only permitted token↔enrollment
/// linkage (Moderation-DeviceCheck.md §5).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateCheckRequest {
    #[serde(default)]
    pub device_token: Option<String>,
    pub user_key: String,
    #[serde(default)]
    pub mandate_ref: Option<String>,
    pub timestamp: String,
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

/// Mirrors the Swift enum's synthesized `Codable` form: a single-key
/// object whose key is the case name and whose value is the payload
/// (`{"clear":{}}`, `{"banned":{"_0":{...}}}`). Swift encodes payloads
/// under `_0` for single-associated-value cases.
#[derive(Debug, Clone, Serialize)]
pub enum GateCheckResult {
    #[serde(rename = "clear")]
    Clear {},
    #[serde(rename = "caseOpen")]
    CaseOpen { _0: Vec<CaseNotice> },
    #[serde(rename = "banned")]
    Banned { _0: BanState },
    #[serde(rename = "checkRequired")]
    CheckRequired { _0: CheckRequiredReason },
}

impl GateCheckResult {
    pub fn clear() -> Self {
        GateCheckResult::Clear {}
    }
    pub fn case_open(notices: Vec<CaseNotice>) -> Self {
        GateCheckResult::CaseOpen { _0: notices }
    }
    pub fn banned(state: BanState) -> Self {
        GateCheckResult::Banned { _0: state }
    }
    pub fn check_required(reason: CheckRequiredReason) -> Self {
        GateCheckResult::CheckRequired { _0: reason }
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

/// The two device-mark states (Moderation.md §5.7). Spec JSON keys are
/// `case-open` / `banned`.
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
