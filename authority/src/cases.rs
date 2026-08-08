//! Case lifecycle and verdict construction (Moderation.md §5.5–§5.6,
//! §10).
//!
//! Every verdict this authority emits is built here, which is why the
//! derived deadlines live here too: `appealDeadline` is
//! `decidedAt + appealWindow` and a duration ban's `banExpires` is
//! `executeAfter + banTerm`, both taken from the class the user
//! consented to. The interface re-checks all of it and refuses
//! anything that doesn't add up — that mutual check is the point, so
//! this side computes rather than accepts.

use ed25519_dalek::{Signer, SigningKey};
use time::OffsetDateTime;

use crate::canonical;
use crate::error::Error;
use crate::store::CaseRecord;
use crate::types::{Marks, Verdict, ViolationClass};
use crate::util;

pub struct Issued {
    pub verdict_ref: String,
    pub disposition: String,
    /// The signed verdict, serialized — the exact bytes delivered to
    /// the interface and stored.
    pub raw: Vec<u8>,
}

/// The interim object issued at case opening (§5.6 constraint 7). Its
/// only permitted effect is the case-open mark: procedural state, not a
/// sanction, and the interface must not degrade service on it.
pub fn open_case_verdict(
    case: &CaseRecord,
    authority: &str,
    intake_basis: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<Issued, Error> {
    let verdict = Verdict {
        verdict_version: 1,
        case_id: case.case_id.clone(),
        authority: authority.to_string(),
        mandate_ref: case.mandate_ref.clone(),
        accused_keys: vec![case.accused.clone()],
        device_binding: case.device_binding.clone(),
        class_id: case.class_id.clone(),
        disposition: "open-case".into(),
        marks: Marks { case_open: true, banned: false },
        ban_expires: None,
        execute_after: None,
        // Required, and it states the intake basis — the verified
        // reports the case rests on.
        reasoning: intake_basis.to_string(),
        appeal_deadline: None,
        decided_at: util::format_timestamp(now),
        signature: String::new(),
        is_final: false,
    };
    sign(verdict, key)
}

/// Dismissal — on the record, or by the decision deadline. Clears both
/// marks. "Undecided is dismissal": the worst-case authority is an
/// absent one, never an omnipotent one.
pub fn dismissal_verdict(
    case: &CaseRecord,
    authority: &str,
    reasoning: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<Issued, Error> {
    let verdict = Verdict {
        verdict_version: 1,
        case_id: case.case_id.clone(),
        authority: authority.to_string(),
        mandate_ref: case.mandate_ref.clone(),
        accused_keys: vec![case.accused.clone()],
        device_binding: case.device_binding.clone(),
        class_id: case.class_id.clone(),
        disposition: "dismiss".into(),
        marks: Marks { case_open: false, banned: false },
        ban_expires: None,
        execute_after: None,
        reasoning: reasoning.to_string(),
        appeal_deadline: None,
        decided_at: util::format_timestamp(now),
        signature: String::new(),
        // A dismissal ends the case; there is nothing left to appeal.
        is_final: true,
    };
    sign(verdict, key)
}

/// A ban, with every derived bound the class dictates.
pub fn ban_verdict(
    case: &CaseRecord,
    class: &ViolationClass,
    authority: &str,
    reasoning: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<Issued, Error> {
    let appeal_window = util::parse_days(&class.appeal_window)
        .map_err(|e| Error::Internal(format!("manifest appealWindow: {e}")))?;
    let appeal_deadline = now + time::Duration::days(appeal_window);

    // §5.6 constraint 4: a non-suspensive ban executes at decidedAt; a
    // suspensive one only when the appeal window lapses unused.
    let execute_after = match class.appeal_effect.as_str() {
        "non-suspensive" => now,
        "suspensive" => appeal_deadline,
        other => {
            return Err(Error::Internal(format!(
                "manifest appealEffect {other:?} is neither suspensive nor non-suspensive"
            )))
        }
    };

    // §5.6 constraint 3: the served term runs from execution, never
    // from decision.
    let ban_expires = if class.ban_term == "permanent" {
        None
    } else {
        let term = util::parse_days(&class.ban_term)
            .map_err(|e| Error::Internal(format!("manifest banTerm: {e}")))?;
        Some(util::format_timestamp(execute_after + time::Duration::days(term)))
    };

    let verdict = Verdict {
        verdict_version: 1,
        case_id: case.case_id.clone(),
        authority: authority.to_string(),
        mandate_ref: case.mandate_ref.clone(),
        accused_keys: vec![case.accused.clone()],
        device_binding: case.device_binding.clone(),
        class_id: case.class_id.clone(),
        disposition: "ban".into(),
        marks: Marks { case_open: false, banned: true },
        ban_expires,
        execute_after: Some(util::format_timestamp(execute_after)),
        reasoning: reasoning.to_string(),
        appeal_deadline: Some(util::format_timestamp(appeal_deadline)),
        decided_at: util::format_timestamp(now),
        signature: String::new(),
        // Not final until the appeal deadline passes or a declared
        // appeal concludes.
        is_final: false,
    };
    sign(verdict, key)
}

/// A reversal on appeal — including a successful new-holder claim. It
/// is a *new verdict* that clears marks, never an edit: verdicts are
/// immutable, and corrections travel through the declared path (§12).
pub fn reversal_verdict(
    case: &CaseRecord,
    authority: &str,
    reasoning: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<Issued, Error> {
    dismissal_verdict(case, authority, reasoning, now, key)
}

fn sign(mut verdict: Verdict, key: &SigningKey) -> Result<Issued, Error> {
    let unsigned = serde_json::to_vec(&verdict)
        .map_err(|e| Error::Internal(format!("encode verdict: {e}")))?;
    let signing_bytes = canonical::verdict_signing_bytes(&unsigned)?;
    verdict.signature = util::base64_encode(&key.sign(&signing_bytes).to_bytes());

    let raw = serde_json::to_vec(&verdict)
        .map_err(|e| Error::Internal(format!("encode signed verdict: {e}")))?;
    Ok(Issued {
        verdict_ref: util::sha256_hex(&signing_bytes),
        disposition: verdict.disposition.clone(),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn case() -> CaseRecord {
        CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "unsolicited-pornography".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-08T00:00:00Z".into(),
            decision_deadline: "2026-08-15T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
        }
    }

    fn class(ban_term: &str, appeal_effect: &str) -> ViolationClass {
        ViolationClass {
            class_id: "unsolicited-pornography".into(),
            definition: "hash:def".into(),
            response_window: "P7D".into(),
            decision_deadline: "P14D".into(),
            ban_term: ban_term.into(),
            appeal_window: "P30D".into(),
            appeal_effect: appeal_effect.into(),
            lawful_reporting: None,
        }
    }

    fn decode(issued: &Issued) -> serde_json::Value {
        serde_json::from_slice(&issued.raw).unwrap()
    }

    #[test]
    fn suspensive_ban_derives_every_bound_from_the_consented_class() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let issued = ban_verdict(&case(), &class("P90D", "suspensive"), "a", "hash:why", now, &key()).unwrap();
        let v = decode(&issued);

        let appeal = util::parse_timestamp(v["appealDeadline"].as_str().unwrap()).unwrap();
        let execute = util::parse_timestamp(v["executeAfter"].as_str().unwrap()).unwrap();
        let expires = util::parse_timestamp(v["banExpires"].as_str().unwrap()).unwrap();

        assert_eq!(appeal, now + time::Duration::days(30));
        // Suspensive: nothing executes until the appeal window lapses.
        assert_eq!(execute, appeal);
        // And the term runs from execution, not from decision.
        assert_eq!(expires, execute + time::Duration::days(90));
        assert_eq!(v["final"], false);
    }

    #[test]
    fn non_suspensive_ban_executes_at_decision() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let issued =
            ban_verdict(&case(), &class("P90D", "non-suspensive"), "a", "hash:why", now, &key()).unwrap();
        let v = decode(&issued);
        assert_eq!(util::parse_timestamp(v["executeAfter"].as_str().unwrap()).unwrap(), now);
        assert_eq!(
            util::parse_timestamp(v["banExpires"].as_str().unwrap()).unwrap(),
            now + time::Duration::days(90)
        );
    }

    #[test]
    fn permanent_class_carries_no_expiry() {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let issued =
            ban_verdict(&case(), &class("permanent", "non-suspensive"), "a", "hash:why", now, &key()).unwrap();
        assert!(decode(&issued).get("banExpires").is_none());
    }

    /// The interim object's only permitted effect is the case-open
    /// mark; it carries no sanction fields and is never final.
    #[test]
    fn open_case_verdict_carries_no_sanction_fields() {
        let now = OffsetDateTime::now_utc();
        let issued = open_case_verdict(&case(), "onym:component:a", "hash:intake", now, &key()).unwrap();
        let v = decode(&issued);
        assert_eq!(v["disposition"], "open-case");
        assert_eq!(v["marks"]["case-open"], true);
        assert_eq!(v["marks"]["banned"], false);
        assert!(v.get("banExpires").is_none());
        assert!(v.get("executeAfter").is_none());
        assert!(v.get("appealDeadline").is_none());
        assert_eq!(v["final"], false);
        assert!(!v["reasoning"].as_str().unwrap().is_empty());
    }

    #[test]
    fn dismissal_clears_both_marks_and_is_final() {
        let now = OffsetDateTime::now_utc();
        let issued = dismissal_verdict(&case(), "onym:component:a", "hash:why", now, &key()).unwrap();
        let v = decode(&issued);
        assert_eq!(v["marks"]["case-open"], false);
        assert_eq!(v["marks"]["banned"], false);
        assert_eq!(v["final"], true);
    }

    /// The signature must verify over exactly the bytes the interface
    /// will reconstruct — signature field removed, keys sorted.
    #[test]
    fn signature_verifies_over_the_canonical_bytes() {
        use ed25519_dalek::{Signature, Verifier};
        let now = OffsetDateTime::now_utc();
        let issued = dismissal_verdict(&case(), "onym:component:a", "hash:why", now, &key()).unwrap();

        let signing_bytes = canonical::verdict_signing_bytes(&issued.raw).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&issued.raw).unwrap();
        let raw_sig = util::base64_decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = Signature::from_slice(&raw_sig).unwrap();

        key().verifying_key().verify(&signing_bytes, &signature).unwrap();
        // And the reference is the hash of those same bytes.
        assert_eq!(issued.verdict_ref, util::sha256_hex(&signing_bytes));
    }
}
