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

    /// The manifest this deployment actually publishes, loaded the way
    /// the service loads it.
    ///
    /// It is a file mounted into the container, so nothing else in the
    /// build would notice it going malformed — and the failure would
    /// be a service that refuses to start, discovered at deploy time.
    /// Absence is a failure too: a test that cannot find what it checks
    /// has not checked anything.
    #[test]
    fn the_published_manifest_loads_and_conforms() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("manifest")
            .join("manifest.json");
        let raw = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let manifest: AuthorityManifest = serde_json::from_slice(&raw)
            .unwrap_or_else(|e| panic!("{} is not a valid authority manifest: {e}", path.display()));

        manifest.validate_class_terms().expect("published class terms must validate");

        // Every class must be one the canonical rules cover. An
        // unmapped class is not an error in general — an authority may
        // publish its own — but this manifest deliberately tracks the
        // reference policy, and a class with no rule behind it is one a
        // human reviewer has nothing exact to apply on appeal.
        for class in &manifest.violation_classes {
            assert!(
                crate::policy::rule_for_class(&class.class_id).is_some(),
                "class {:?} has no canonical rule; either add one or say so in the published \
                 documents, because an appeal is decided against the rule",
                class.class_id
            );
        }

        // Each class's definition is its own document, named for the
        // class. One page with `#csam` style fragments does not work:
        // the manifest's URLs are what a consent screen links to, and a
        // fragment addresses an HTML element, so a reader following the
        // link would land at the top of a multi-class page. Pinning the
        // correspondence here is what stops a class from ending up
        // pointing at another class's terms.
        for class in &manifest.violation_classes {
            let definition = class.definition.as_str();
            let expected = format!("/policy/{}", class.class_id);
            assert!(
                definition.ends_with(&expected),
                "class {:?} points at {definition:?}, which is not its own document \
                 ({expected}); a reader following that link does not arrive at these terms",
                class.class_id
            );
            assert!(
                !definition.contains('#'),
                "class {:?} points at a fragment ({definition:?}); the documents are Markdown \
                 and a fragment resolves to nothing in one",
                class.class_id
            );
        }

        // A permanent ban is valid only while an independent appellate
        // can hear an appeal against it (reference policy §6, §8). The
        // two fields therefore travel together: publishing `permanent`
        // without `appellate` promises a sanction the interface is
        // required to clear.
        let permanent: Vec<&str> = manifest
            .violation_classes
            .iter()
            .filter(|class| class.ban_term == "permanent")
            .map(|class| class.class_id.as_str())
            .collect();
        assert!(
            permanent.is_empty() || manifest.appellate.is_some(),
            "classes {permanent:?} carry a permanent ban with no `appellate` declared; that is a \
             sanction the interface must clear, so it is a promise rather than a term"
        );
    }

    /// `published/` is a **serving root**, not a folder of sources.
    /// Caddy maps it onto `authority.onym.app/policy/`, so every file
    /// in it is a public URL whether or not the manifest links to it.
    ///
    /// That is how a `README.md` saying "these are drafts and need
    /// sign-off before publication" came to be served at
    /// `/policy/README` — on the host where people go to read the terms
    /// before consenting. Nothing listed it and nothing linked it; it
    /// was reachable by guessing, which is the kind of thing found by
    /// the wrong person rather than by us.
    ///
    /// So the directory must hold exactly the documents the manifest
    /// points at. Both directions are checked: an extra file is
    /// something published that nobody agreed to read, and a missing
    /// one is a term that 404s at the moment someone tries to read it.
    #[test]
    fn the_published_directory_is_exactly_what_the_manifest_links_to() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read(root.join("manifest").join("manifest.json")).expect("manifest");
        let manifest: serde_json::Value = serde_json::from_slice(&raw).expect("manifest parses");

        // Every `/policy/<name>` the manifest mentions, anywhere in the
        // document — walking the JSON rather than naming the fields, so
        // a link added later cannot be forgotten here.
        const PREFIX: &str = "/policy/";
        let mut linked = std::collections::BTreeSet::new();
        let mut stack = vec![&manifest];
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::String(text) => {
                    if let Some(at) = text.find(PREFIX) {
                        let tail = &text[at + PREFIX.len()..];
                        let name =
                            tail.split(['#', '?']).next().unwrap_or("").trim_end_matches('/');
                        if !name.is_empty() {
                            linked.insert(name.to_string());
                        }
                    }
                }
                serde_json::Value::Array(items) => stack.extend(items.iter()),
                serde_json::Value::Object(fields) => stack.extend(fields.values()),
                _ => {}
            }
        }
        assert!(!linked.is_empty(), "the manifest links to no policy documents at all");

        let present: std::collections::BTreeSet<String> =
            std::fs::read_dir(root.join("published"))
                .expect("published/")
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".md"))
                .map(|name| name.trim_end_matches(".md").to_string())
                .collect();

        let unpublishable: Vec<&String> = present.difference(&linked).collect();
        assert!(
            unpublishable.is_empty(),
            "published/ holds {unpublishable:?}, which the manifest does not link to. That \
             directory is served at /policy/, so anything in it is public. Notes about the \
             documents belong in authority/PUBLISHING.md, outside the serving root."
        );

        let missing: Vec<&String> = linked.difference(&present).collect();
        assert!(
            missing.is_empty(),
            "the manifest links to {missing:?}, which published/ does not hold; those terms 404 \
             at the moment someone tries to read them before consenting"
        );
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
