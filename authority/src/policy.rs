//! The canonical rules a model is asked to apply.
//!
//! These are transcribed from the Onym Reference Moderation Policy
//! §2.1, whose exact bytes hash to [`REFERENCE_POLICY_SHA256`]. They
//! are here as data rather than as prose in a prompt string because
//! they are **consented policy**: a user agreed to a manifest that
//! incorporated these exact rules, and the model must be asked about
//! the rule they agreed to, not a paraphrase of it that drifted.
//!
//! A rule is not the same thing as a violation class. The class is what
//! the manifest declares and the mandate consents to; the rule is the
//! text handed to a model that supports a custom policy. Profiles using
//! a model's *native* taxonomy get no rule text at all — their mapping
//! is disclosed in the profile instead, along with the mismatch it
//! carries.

/// SHA-256 of the reference policy's canonical UTF-8 bytes, as every
/// published model profile states it. A deployment can hand the
/// document to `AUTHORITY_POLICY_PATH` and have this checked at boot;
/// see `Config`.
pub const REFERENCE_POLICY_SHA256: &str =
    "8609e064f9615e29fad4fb97e3feed533dd4a01986f9fc73e3a2d3fd60f4c08b";

/// One canonical rule, in the three parts the policy states it in.
///
/// The parts are separate because the third is the one that matters
/// most: a model told only what a violation *is* will find violations
/// everywhere, and the required-context clause is what makes an absent
/// or ambiguous element resolve to "no violation" rather than to a
/// guess.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalRule {
    pub rule_id: &'static str,
    pub violation: &'static str,
    pub not_a_violation: &'static str,
    pub required_context: &'static str,
}

impl CanonicalRule {
    /// The rule as a model sees it. One shape for every profile, so
    /// two profiles asked about the same class are asked the same
    /// question.
    pub fn as_prompt_text(&self) -> String {
        format!(
            "{id}\n\n\
             Violation: {violation}\n\n\
             Not a violation merely because of its subject: {not_a_violation}\n\n\
             Required context: {required_context}",
            id = self.rule_id,
            violation = self.violation,
            not_a_violation = self.not_a_violation,
            required_context = self.required_context,
        )
    }
}

pub const R_CSAM: CanonicalRule = CanonicalRule {
    rule_id: "R-CSAM",
    violation: "the authenticated material depicts, describes, solicits, distributes, or \
                facilitates sexual material involving a person under 18.",
    not_a_violation: "a good-faith safety report, victim-support communication, lawful evidence \
                      handling, news report, documentary, or medical discussion.",
    required_context: "the model must have evidence supporting both the sexual nature of the \
                       material and that the person is under 18. If either is absent, ambiguous, \
                       or rests only on an unsupported assertion, the model must return no \
                       violation.",
};

pub const R_VIOLENCE: CanonicalRule = CanonicalRule {
    rule_id: "R-VIOLENCE",
    violation: "a specific threat, incitement, or operational instruction for physical violence \
                where the authenticated words and available context make the risk of harm \
                reasonably credible.",
    not_a_violation: "news, documentary, fictional, defensive, historical, or good-faith safety \
                      discussion.",
    required_context: "violent language without a target, act, instruction, or credible context \
                       is not enough. Quotation and satire are not threats merely because their \
                       words would be threatening if asserted directly.",
};

pub const R_PORN: CanonicalRule = CanonicalRule {
    rule_id: "R-PORN",
    violation: "the authenticated material shows an intentional transmission of explicit sexual \
                material to a recipient who had not consented to receive it.",
    not_a_violation: "a consensual exchange or non-explicit educational, medical, documentary, or \
                      safety material.",
    required_context: "explicitness alone is not enough. The evidence must support transmission, \
                       intent, and absence of recipient consent.",
};

/// The reference policy's class → rule correspondence.
///
/// Returns `None` for a class the reference policy does not define,
/// which is not an error: an authority may publish its own classes.
/// What it must not do is hand a model *some other* rule and call the
/// answer a decision about this class, so an unmapped class ends in no
/// decision rather than in a default.
pub fn rule_for_class(class_id: &str) -> Option<CanonicalRule> {
    match class_id {
        "csam" => Some(R_CSAM),
        "credible-violence" => Some(R_VIOLENCE),
        "unsolicited-pornography" => Some(R_PORN),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reference_class_has_a_rule() {
        for class in ["csam", "credible-violence", "unsolicited-pornography"] {
            assert!(rule_for_class(class).is_some(), "{class}");
        }
    }

    /// A class the reference policy does not define gets no rule, and
    /// the caller must treat that as "cannot decide" rather than
    /// substituting a neighbouring rule.
    #[test]
    fn an_unknown_class_gets_no_rule() {
        assert!(rule_for_class("spam").is_none());
        assert!(rule_for_class("").is_none());
    }

    /// The required-context clause is the part that makes an absent
    /// element resolve against a finding of violation. A rule that lost
    /// it would still read sensibly and would classify far more
    /// harshly, so it is pinned.
    #[test]
    fn every_rule_states_what_happens_when_an_element_is_missing() {
        for rule in [R_CSAM, R_VIOLENCE, R_PORN] {
            let text = rule.as_prompt_text();
            assert!(text.contains(rule.rule_id));
            assert!(text.contains("Required context:"), "{}", rule.rule_id);
            assert!(
                text.contains("not enough")
                    || text.contains("absent")
                    || text.contains("must support"),
                "{} does not say what an unproved element means",
                rule.rule_id
            );
        }
    }
}
