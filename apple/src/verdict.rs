//! Mechanical verdict validation (Moderation.md §5.6), server side.
//!
//! The interface "validates verdict shape … never the verdict's
//! wisdom" (§5.7). This is the same rule set the iOS client applies to
//! verdicts it displays, applied here before anything reaches Apple —
//! because here it is load-bearing: a verdict that passes gets written
//! to a device.

use ed25519_dalek::{Signature, VerifyingKey};
use time::OffsetDateTime;

use crate::error::Error;
use crate::types::{Disposition, Marks, ViolationClass, Verdict};
use crate::util::{self, key_bytes_from_reference};

/// Whether the verdict's marks may be written now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Write the marks.
    Execute,
    /// A valid ban whose `executeAfter` has not arrived: stored, not
    /// executed. Writing its mark early is nonconforming.
    StoreUntil(OffsetDateTime),
}

/// Derived deadlines are compared with a one-second tolerance. Manifest
/// windows are whole days, but an authority computing them in another
/// language or timezone can land a second off; demanding exact equality
/// would reject conforming verdicts over rounding, while a second of
/// slack moves no consented bound.
const TOLERANCE_SECONDS: i64 = 1;

/// A signed decision may be a few minutes ahead of the interface's
/// clock, but it may not live arbitrarily far in the future. The
/// interface uses `decidedAt` as the causal order for marks, so a
/// future value would outrank every honest correction until that time.
const MAX_DECISION_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

pub struct ValidationInput<'a> {
    pub verdict: &'a Verdict,
    /// The exact bytes the authority signed over (signature field
    /// removed structurally).
    pub signing_bytes: &'a [u8],
    /// From the mandate this vendor countersigned.
    pub mandate_authority: &'a str,
    pub mandate_user: &'a str,
    pub mandate_device_binding: &'a str,
    pub mandate_classes: &'a [String],
    /// The consented manifest's operator key reference
    /// (`onym:key:<hex>`), which is what a verdict signature must
    /// verify against.
    pub authority_operator_key: &'a str,
    /// The consented terms for the verdict's class.
    pub violation_class: Option<&'a ViolationClass>,
    pub now: OffsetDateTime,
    /// Soft mode accepts an unverifiable signature with a warning, as
    /// the client's `ModerationTrust` does, so a deployment can run
    /// before authorities publish real signing keys. Production
    /// deployments MUST enable enforcement.
    pub enforce_signature: bool,
}

pub fn validate(input: ValidationInput<'_>) -> Result<Outcome, Error> {
    let v = input.verdict;

    validate_signature(&input)?;

    // This is checked for every disposition, not only bans. A
    // dismissal/reversal with an unreadable timestamp cannot reliably
    // clear the verdict it supersedes, and a far-future verdict would
    // dominate the causal fold indefinitely.
    let decided_at = util::parse_timestamp(&v.decided_at)
        .map_err(|e| Error::VerdictInvalid(format!("decidedAt: {e}")))?;
    if decided_at > input.now + time::Duration::seconds(MAX_DECISION_CLOCK_SKEW_SECONDS) {
        return Err(Error::VerdictNotYetValid(
            "decidedAt is too far in the future".into(),
        ));
    }

    // Mandate binding: the verdict must name the mandate's authority,
    // device, user, and a class within it.
    if v.authority != input.mandate_authority {
        return Err(Error::VerdictInvalid(format!(
            "authority {} is not the mandated authority",
            v.authority
        )));
    }
    if v.device_binding != input.mandate_device_binding {
        return Err(Error::VerdictInvalid("deviceBinding outside the mandate".into()));
    }
    if !v.accused_keys.iter().any(|k| k == input.mandate_user) {
        return Err(Error::VerdictInvalid(
            "accusedKeys does not include the mandated user".into(),
        ));
    }
    if !input.mandate_classes.iter().any(|c| c == &v.class_id) {
        return Err(Error::ClassOutsideMandate(v.class_id.clone()));
    }

    // Reasoning is mandatory on every disposition — an unexplained
    // sanction (or case opening) is nonconforming.
    if v.reasoning.trim().is_empty() {
        return Err(Error::VerdictInvalid("missing reasoning".into()));
    }

    match v.disposition {
        Disposition::OpenCase => validate_open_case(v),
        Disposition::Dismiss => validate_dismissal(v),
        Disposition::Ban => {
            let class = input.violation_class.ok_or_else(|| {
                Error::VerdictInvalid(format!(
                    "class {} missing from the consented manifest",
                    v.class_id
                ))
            })?;
            validate_ban(v, class, decided_at, input.now)
        }
    }
}

/// §5.6 constraint 7: the interim object's only permitted effect is the
/// case-open mark; it carries no sanction fields and is never final.
fn validate_open_case(v: &Verdict) -> Result<Outcome, Error> {
    if v.marks != (Marks { case_open: true, banned: false }) {
        return Err(Error::VerdictInvalid(
            "open-case marks inconsistent with disposition".into(),
        ));
    }
    if v.ban_expires.is_some() || v.execute_after.is_some() || v.appeal_deadline.is_some() || v.is_final
    {
        return Err(Error::VerdictInvalid(
            "open-case verdict carries sanction fields".into(),
        ));
    }
    Ok(Outcome::Execute)
}

/// Dismissals clear both marks (§5.6 constraint 6).
fn validate_dismissal(v: &Verdict) -> Result<Outcome, Error> {
    if v.marks != (Marks { case_open: false, banned: false }) {
        return Err(Error::VerdictInvalid(
            "dismissal marks inconsistent with disposition".into(),
        ));
    }
    Ok(Outcome::Execute)
}

/// §5.6 constraints 3–4, plus the consented-term bounds: the sanction a
/// user can receive is the one they read before signing.
fn validate_ban(
    v: &Verdict,
    class: &ViolationClass,
    decided_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Outcome, Error> {
    if v.marks != (Marks { case_open: false, banned: true }) {
        return Err(Error::VerdictInvalid("ban marks inconsistent with disposition".into()));
    }

    // The appeal window is a consented term, so the deadline is
    // derived, not declared — otherwise an authority could set
    // appealDeadline == decidedAt and offer zero appeal on a class the
    // user consented to with P30D.
    let appeal_deadline = v
        .appeal_deadline
        .as_deref()
        .ok_or_else(|| Error::VerdictInvalid("ban missing appealDeadline".into()))?;
    let appeal_deadline = util::parse_timestamp(appeal_deadline)
        .map_err(|e| Error::VerdictInvalid(format!("appealDeadline: {e}")))?;
    let appeal_window = util::parse_days(&class.appeal_window)
        .map_err(|e| Error::VerdictInvalid(format!("manifest appealWindow: {e}")))?;
    let consented_appeal_deadline = decided_at + time::Duration::days(appeal_window);
    if !within_tolerance(appeal_deadline, consented_appeal_deadline) {
        return Err(Error::VerdictInvalid(format!(
            "appealDeadline must equal decidedAt + the consented appealWindow ({})",
            class.appeal_window
        )));
    }

    let execute_after = v
        .execute_after
        .as_deref()
        .ok_or_else(|| Error::VerdictInvalid("ban missing executeAfter".into()))?;
    let execute_after = util::parse_timestamp(execute_after)
        .map_err(|e| Error::VerdictInvalid(format!("executeAfter: {e}")))?;

    match class.appeal_effect.as_str() {
        "non-suspensive" => {
            if !within_tolerance(execute_after, decided_at) {
                return Err(Error::VerdictInvalid(
                    "non-suspensive executeAfter must equal decidedAt".into(),
                ));
            }
        }
        "suspensive" => {
            if !within_tolerance(execute_after, appeal_deadline) {
                return Err(Error::VerdictInvalid(
                    "suspensive executeAfter must equal appealDeadline".into(),
                ));
            }
        }
        other => {
            return Err(Error::VerdictInvalid(format!(
                "manifest appealEffect {other:?} is neither suspensive nor non-suspensive"
            )))
        }
    }

    // The served term is the consented banTerm measured from execution
    // (§5.6 constraint 3) — otherwise a P90D class could carry a
    // ten-year expiry and still validate.
    if class.ban_term == "permanent" {
        if v.ban_expires.is_some() {
            return Err(Error::VerdictInvalid("permanent class carries banExpires".into()));
        }
    } else {
        let term_days = util::parse_days(&class.ban_term)
            .map_err(|e| Error::VerdictInvalid(format!("manifest banTerm: {e}")))?;
        let ban_expires = v
            .ban_expires
            .as_deref()
            .ok_or_else(|| Error::VerdictInvalid("ban missing banExpires on non-permanent class".into()))?;
        let ban_expires = util::parse_timestamp(ban_expires)
            .map_err(|e| Error::VerdictInvalid(format!("banExpires: {e}")))?;
        let consented_expiry = execute_after + time::Duration::days(term_days);
        if !within_tolerance(ban_expires, consented_expiry) {
            return Err(Error::VerdictInvalid(format!(
                "banExpires must equal executeAfter + the consented banTerm ({})",
                class.ban_term
            )));
        }
    }

    if execute_after > now {
        return Ok(Outcome::StoreUntil(execute_after));
    }
    Ok(Outcome::Execute)
}

fn within_tolerance(lhs: OffsetDateTime, rhs: OffsetDateTime) -> bool {
    (lhs - rhs).whole_seconds().abs() <= TOLERANCE_SECONDS
}

fn validate_signature(input: &ValidationInput<'_>) -> Result<(), Error> {
    let verified = (|| -> Option<bool> {
        let key_bytes = key_bytes_from_reference(input.authority_operator_key)?;
        let key = VerifyingKey::from_bytes(&key_bytes.try_into().ok()?).ok()?;
        let raw = util::base64_decode(&input.verdict.signature)?;
        let signature = Signature::from_slice(&raw).ok()?;
        Some(key.verify_strict(input.signing_bytes, &signature).is_ok())
    })()
    .unwrap_or(false);

    if verified {
        return Ok(());
    }
    if input.enforce_signature {
        return Err(Error::VerdictInvalid("authority signature did not verify".into()));
    }
    tracing::warn!(
        case_id = %input.verdict.case_id,
        "verdict signature did not verify; accepting anyway (MODERATION_ENFORCE_SIGNATURES=false)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Marks;

    fn class(ban_term: &str, appeal_effect: &str) -> ViolationClass {
        ViolationClass {
            class_id: "unsolicited-pornography".into(),
            response_window: "P7D".into(),
            decision_deadline: "P14D".into(),
            ban_term: ban_term.into(),
            appeal_window: "P30D".into(),
            appeal_effect: appeal_effect.into(),
        }
    }

    /// Decided 40 days ago, P30D appeal window lapsed 10 days ago,
    /// execution began there, expiry is execution + the consented P90D.
    fn suspensive_ban(now: OffsetDateTime) -> Verdict {
        let decided = now - time::Duration::days(40);
        let appeal = decided + time::Duration::days(30);
        Verdict {
            verdict_version: 1,
            case_id: "case-1".into(),
            authority: "onym:component:authority".into(),
            mandate_ref: "aa".into(),
            accused_keys: vec!["onym:key:user".into()],
            device_binding: "enrollment-1".into(),
            class_id: "unsolicited-pornography".into(),
            disposition: Disposition::Ban,
            marks: Marks { case_open: false, banned: true },
            ban_expires: Some(util::format_timestamp(appeal + time::Duration::days(90))),
            execute_after: Some(util::format_timestamp(appeal)),
            reasoning: "hash:findings".into(),
            appeal_deadline: Some(util::format_timestamp(appeal)),
            appeal_url: None,
            new_holder_url: None,
            authority_contact: None,
            decided_at: util::format_timestamp(decided),
            signature: "unverifiable".into(),
            is_final: false,
        }
    }

    fn validate_with(v: &Verdict, class: &ViolationClass, now: OffsetDateTime) -> Result<Outcome, Error> {
        let classes = vec!["unsolicited-pornography".to_string(), "csam".to_string()];
        validate(ValidationInput {
            verdict: v,
            signing_bytes: b"",
            mandate_authority: "onym:component:authority",
            mandate_user: "onym:key:user",
            mandate_device_binding: "enrollment-1",
            mandate_classes: &classes,
            authority_operator_key: "onym:key:00",
            violation_class: Some(class),
            now,
            enforce_signature: false,
        })
    }

    #[test]
    fn conforming_suspensive_ban_executes() {
        let now = OffsetDateTime::now_utc();
        let v = suspensive_ban(now);
        assert_eq!(validate_with(&v, &class("P90D", "suspensive"), now).unwrap(), Outcome::Execute);
    }

    #[test]
    fn expiry_beyond_the_consented_term_is_refused() {
        let now = OffsetDateTime::now_utc();
        let mut v = suspensive_ban(now);
        v.ban_expires = Some(util::format_timestamp(now + time::Duration::days(3650)));
        assert!(validate_with(&v, &class("P90D", "suspensive"), now).is_err());
    }

    #[test]
    fn zero_appeal_window_is_refused() {
        let now = OffsetDateTime::now_utc();
        let mut v = suspensive_ban(now);
        v.appeal_deadline = Some(v.decided_at.clone());
        v.execute_after = Some(v.decided_at.clone());
        assert!(validate_with(&v, &class("P90D", "suspensive"), now).is_err());
    }

    #[test]
    fn ban_before_execute_after_is_stored_not_executed() {
        let now = OffsetDateTime::now_utc();
        // Decided now: a suspensive ban executes only after its appeal
        // window, which is 30 days out.
        let decided = now;
        let appeal = decided + time::Duration::days(30);
        let mut v = suspensive_ban(now);
        v.decided_at = util::format_timestamp(decided);
        v.appeal_deadline = Some(util::format_timestamp(appeal));
        v.execute_after = Some(util::format_timestamp(appeal));
        v.ban_expires = Some(util::format_timestamp(appeal + time::Duration::days(90)));
        assert!(matches!(
            validate_with(&v, &class("P90D", "suspensive"), now).unwrap(),
            Outcome::StoreUntil(_)
        ));
    }

    #[test]
    fn accused_keys_must_include_the_mandated_user() {
        let now = OffsetDateTime::now_utc();
        let mut v = suspensive_ban(now);
        v.accused_keys = vec!["onym:key:someone-else".into()];
        assert!(validate_with(&v, &class("P90D", "suspensive"), now).is_err());
    }

    #[test]
    fn open_case_carrying_sanction_fields_is_refused() {
        let now = OffsetDateTime::now_utc();
        let mut v = suspensive_ban(now);
        v.disposition = Disposition::OpenCase;
        v.marks = Marks { case_open: true, banned: false };
        assert!(validate_with(&v, &class("P90D", "suspensive"), now).is_err());
    }

    /// Every disposition participates in the causal fold, so every one
    /// needs a usable and reasonably current ordering key.
    #[test]
    fn every_disposition_requires_a_bounded_decision_time() {
        let now = OffsetDateTime::now_utc();
        for disposition in [Disposition::OpenCase, Disposition::Dismiss, Disposition::Ban] {
            let mut v = suspensive_ban(now);
            v.disposition = disposition;
            match disposition {
                Disposition::OpenCase => {
                    v.marks = Marks { case_open: true, banned: false };
                    v.ban_expires = None;
                    v.execute_after = None;
                    v.appeal_deadline = None;
                    v.is_final = false;
                }
                Disposition::Dismiss => {
                    v.marks = Marks { case_open: false, banned: false };
                    v.ban_expires = None;
                    v.execute_after = None;
                    v.appeal_deadline = None;
                    v.is_final = true;
                }
                Disposition::Ban => {}
            }

            v.decided_at = "not-a-time".into();
            let malformed = validate_with(&v, &class("P90D", "suspensive"), now)
                .expect_err("an unreadable causal key must be refused");
            assert!(malformed.to_string().contains("decidedAt"));

            v.decided_at = util::format_timestamp(
                now + time::Duration::seconds(MAX_DECISION_CLOCK_SKEW_SECONDS + 1),
            );
            let future = validate_with(&v, &class("P90D", "suspensive"), now)
                .expect_err("a future causal key must be refused");
            assert!(matches!(future, Error::VerdictNotYetValid(_)));
        }
    }

    #[test]
    fn permanent_class_carrying_expiry_is_refused() {
        let now = OffsetDateTime::now_utc();
        let mut v = suspensive_ban(now);
        v.ban_expires = Some(util::format_timestamp(now));
        assert!(validate_with(&v, &class("permanent", "suspensive"), now).is_err());
    }
}
