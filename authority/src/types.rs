//! The contract's boundary objects (Moderation.md §5), as this
//! authority receives and emits them.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ─── Manifest (§5.2) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationClass {
    pub class_id: String,
    /// Content address of the exact prohibited-content definition the
    /// user consented to. Immutable once consented.
    pub definition: String,
    pub response_window: String,
    pub decision_deadline: String,
    /// `"permanent"` or a `P<n>D` duration.
    pub ban_term: String,
    pub appeal_window: String,
    /// `"suspensive"` or `"non-suspensive"`.
    pub appeal_effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lawful_reporting: Option<String>,
}

/// The model profile a manifest declares: which published profile
/// document, by id and digest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelProfileReference {
    pub id: String,
    /// SHA-256 of the published profile document.
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityManifest {
    pub version: u32,
    pub component_id: String,
    pub seat: String,
    #[serde(rename = "operator")]
    pub operator_key: String,
    pub moderation_profile_id: String,
    /// The model profile this authority decides under, if it publishes
    /// one. Which model, prompt, adapter and thresholds decide a case
    /// is consented policy — the reference policy is explicit that it
    /// "may not be silently replaced" — so it belongs in the bytes a
    /// mandate pins, not in the environment of whichever process
    /// happens to be running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile: Option<ModelProfileReference>,
    pub violation_classes: Vec<ViolationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_rules: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_holder_appeal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appellate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidentiality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statistics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offers: Option<Vec<String>>,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl AuthorityManifest {
    pub fn violation_class(&self, class_id: &str) -> Option<&ViolationClass> {
        self.violation_classes.iter().find(|c| c.class_id == class_id)
    }

    /// Validate every term the case lifecycle later relies on. Policy
    /// errors are configuration failures, not per-report server errors:
    /// an authority must not start if it cannot honor its own manifest.
    pub fn validate_class_terms(&self) -> Result<(), String> {
        for class in &self.violation_classes {
            for (field, value) in [
                ("responseWindow", class.response_window.as_str()),
                ("decisionDeadline", class.decision_deadline.as_str()),
                ("appealWindow", class.appeal_window.as_str()),
            ] {
                crate::util::parse_days(value).map_err(|error| {
                    format!("class {:?} has invalid {field}: {error}", class.class_id)
                })?;
            }

            if class.ban_term != "permanent" {
                crate::util::parse_days(&class.ban_term).map_err(|error| {
                    format!("class {:?} has invalid banTerm: {error}", class.class_id)
                })?;
            }

            if !matches!(class.appeal_effect.as_str(), "suspensive" | "non-suspensive") {
                return Err(format!(
                    "class {:?} has invalid appealEffect {:?}; expected suspensive or \
                     non-suspensive",
                    class.class_id, class.appeal_effect
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    fn manifest() -> AuthorityManifest {
        serde_json::from_str(crate::testing::MANIFEST_JSON).unwrap()
    }

    #[test]
    fn every_declared_class_term_is_validated_before_serving() {
        assert!(manifest().validate_class_terms().is_ok());

        for (field, invalid) in [
            ("responseWindow", "PT1H"),
            ("decisionDeadline", "P0D"),
            ("appealWindow", "thirty days"),
            ("banTerm", "forever"),
        ] {
            let mut manifest = manifest();
            let class = &mut manifest.violation_classes[0];
            match field {
                "responseWindow" => class.response_window = invalid.into(),
                "decisionDeadline" => class.decision_deadline = invalid.into(),
                "appealWindow" => class.appeal_window = invalid.into(),
                "banTerm" => class.ban_term = invalid.into(),
                _ => unreachable!(),
            }
            let error = manifest.validate_class_terms().unwrap_err();
            assert!(error.contains(field), "{error}");
        }

        let mut manifest = manifest();
        manifest.violation_classes[0].appeal_effect = "sometimes-suspensive".into();
        let error = manifest.validate_class_terms().unwrap_err();
        assert!(error.contains("appealEffect"), "{error}");
    }
}

// ─── Mandate (§5.3) ──────────────────────────────────────────────────

/// Registered with this authority by the interface (`accept-mandate`).
/// Jurisdiction is signed consent: without one of these naming us, we
/// have no power over the user at all.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerationMandate {
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

// ─── Report (§5.4) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceItem {
    /// The specific message or media, from the reporter's own device.
    pub disclosed_content: String,
    /// Sender signature or envelope commitment binding the content to
    /// the accused's key. Without it this is a complaint.
    pub authenticity_proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub report_version: u32,
    pub report_id: String,
    pub reporter: String,
    /// Hash of the reporter's own mandate — standing follows it.
    pub reporter_mandate: String,
    pub accused: String,
    pub class_id: String,
    pub evidence: Vec<EvidenceItem>,
    pub filed_at: String,
    #[serde(default)]
    pub signature: String,
}

// ─── Response / appeal ───────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseResponse {
    /// The case this answers. Inside the signed bytes on purpose: a
    /// response that named no case could be lifted from one case and
    /// replayed onto another, so an innocuous "that wasn't me" would
    /// register as an answer to an accusation the signer never saw.
    pub case_id: String,
    pub statement: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceItem>,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppealSubmission {
    /// The case appealed. Signed, for the same replay reason as
    /// `CaseResponse::case_id`.
    pub case_id: String,
    /// `"appeal"` or `"new-holder-claim"`. The latter is the device's
    /// new owner, which §5.7 makes a mandatory class with expedited
    /// review — the device is not the person.
    pub kind: String,
    pub statement: String,
    #[serde(default)]
    pub signature: String,
}

// ─── Verdict (§5.6) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marks {
    #[serde(rename = "case-open")]
    pub case_open: bool,
    pub banned: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub verdict_version: u32,
    pub case_id: String,
    pub authority: String,
    pub mandate_ref: String,
    pub accused_keys: Vec<String>,
    pub device_binding: String,
    pub class_id: String,
    /// `open-case` | `dismiss` | `ban`
    pub disposition: String,
    pub marks: Marks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execute_after: Option<String>,
    /// Content address of the findings. Mandatory on every
    /// disposition — an unexplained sanction is nonconforming.
    pub reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal_deadline: Option<String>,
    pub decided_at: String,
    pub signature: String,
    #[serde(rename = "final")]
    pub is_final: bool,
}

/// What this authority POSTs to the interface's enforcement backend.
/// The manifest travels as base64 of its exact bytes so the backend can
/// check it against the hash the user's mandate pinned.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictSubmission {
    pub verdict: serde_json::Value,
    pub consented_manifest: String,
}
