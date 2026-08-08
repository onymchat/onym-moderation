//! The enforcement engine: what a gate check answers, and the lazy
//! reconciliation that clears marks on expiry, reversal, and the
//! decision-deadline default (Moderation-DeviceCheck.md §5–§6).
//!
//! Two rules govern everything here:
//!
//! 1. **Reading is stateless.** The bits are the state the refusal
//!    consults, which is what survives reinstall. A device whose `bit1`
//!    is set is refused whether or not we can resolve its enrollment.
//! 2. **Marks move only on verdicts, and defaults only ever clear.**
//!    Nothing but a validated verdict sets a mark; expiry, reversal,
//!    and the decision deadline can only clear one.

use time::OffsetDateTime;

use crate::devicecheck::{Bits, DeviceCheck};
use crate::error::Error;
use crate::store::{Store, StoredVerdict};
use crate::types::{BanState, CheckRequiredReason, GateCheckResult, Verdict};
use crate::util;

pub struct Engine {
    pub store: Store,
    pub device_check: Option<DeviceCheck>,
}

/// What the stored verdict record says the marks *should* be, and which
/// verdict (or rule) authorizes that.
struct Intended {
    bits: Bits,
    authorized_by: String,
    ban: Option<(String, Verdict)>,
    /// Verdicts whose marks this write realizes, so they can be flagged
    /// executed once Apple accepts it.
    realizes: Vec<String>,
    /// Whether the ban in force has already been written to a device.
    ban_executed: bool,
}

impl Engine {
    /// Answer a gate check for a device.
    ///
    /// The honesty rule the client's stub could not implement: a
    /// request with no device token, or one Apple refuses to validate,
    /// never yields `clear`. There is no way to know the device is
    /// clean without asking Apple, and guessing in the permissive
    /// direction is exactly the bypass this seat exists to prevent.
    pub async fn gate_check(
        &self,
        device_token: Option<&str>,
        user_key: &str,
        now: OffsetDateTime,
    ) -> Result<GateCheckResult, Error> {
        let Some(device_check) = self.device_check.as_ref() else {
            // No Apple credentials configured: we cannot read bits, so
            // we cannot clear anyone.
            return Ok(GateCheckResult::check_required(
                CheckRequiredReason::AttestationUnavailable,
            ));
        };
        let Some(device_token) = device_token else {
            return Ok(GateCheckResult::check_required(
                CheckRequiredReason::AttestationUnavailable,
            ));
        };

        let Some(bits) = device_check.query(device_token).await? else {
            return Ok(GateCheckResult::check_required(CheckRequiredReason::TokenInvalid));
        };

        // Session-mediated reconciliation: with a live token in hand,
        // bring Apple's bits in line with what the verdict record now
        // implies, before answering.
        let binding = self.store.device_binding_for_user(user_key)?;
        let intended = match binding.as_deref() {
            Some(binding) => self.intended_marks(binding, now)?,
            None => None,
        };

        if let Some(intended) = intended.as_ref() {
            if intended.bits != bits {
                // A ban we have already branded onto a device, meeting
                // a device whose bits are clean, is a *different piece
                // of hardware* presenting the same identity — someone
                // who moved to a new phone. DeviceCheck tokens are
                // unlinkable, so this is the only signal available, and
                // branding on it would mark a device the verdict never
                // named, quite possibly someone else's.
                //
                // The contract already says what to do: the identity
                // refusal covers the named keys on every surface, while
                // device marks reach only the devices the verdict names
                // (§5.3 constraint 4). So refuse the identity below,
                // and leave this device's bits alone.
                let would_brand_another_device =
                    intended.bits.banned && !bits.banned && intended.ban_executed;

                if would_brand_another_device {
                    tracing::warn!(
                        binding = %binding.as_deref().unwrap_or("unresolved"),
                        "banned identity presented a device with clean bits; refusing the \
                         identity without marking this device"
                    );
                } else {
                    self.write_bits(
                        device_check,
                        device_token,
                        binding.as_deref().unwrap_or("unresolved"),
                        intended.bits,
                        &intended.authorized_by,
                        now,
                    )
                    .await?;
                    // Only now — after Apple accepted the write — are
                    // the verdicts behind it actually executed.
                    for verdict_ref in &intended.realizes {
                        self.store.mark_executed(verdict_ref)?;
                    }
                }
            }
        }

        let effective = intended.as_ref().map(|i| i.bits).unwrap_or(bits);

        if effective.banned {
            // A set banned bit refuses service even when the session
            // identity resolves nothing — that is what survives a
            // reinstall or an identity wipe. When we can't name the
            // governing verdict, the holder is routed to
            // re-identification instead of being shown a blank wall.
            return Ok(match intended.as_ref().and_then(|i| i.ban.as_ref()) {
                Some((verdict_ref, verdict)) => {
                    GateCheckResult::banned(self.ban_state(verdict_ref, verdict))
                }
                None => GateCheckResult::check_required(
                    CheckRequiredReason::ReidentificationRequired,
                ),
            });
        }

        if effective.case_open {
            let notices = binding
                .as_deref()
                .map(|b| self.open_case_notices(b))
                .transpose()?
                .unwrap_or_default();
            return Ok(GateCheckResult::case_open(notices));
        }

        Ok(GateCheckResult::clear())
    }

    /// Fold this device's verdicts into the marks they currently
    /// authorize.
    ///
    /// **The fold is per case**, and that is the whole of the
    /// difficulty. A device can carry several cases at once — they are
    /// different classes, opened by different reports — and each has
    /// its own verdict history. Folding them into one running pair of
    /// bits made the newest verdict in *any* case overwrite the state
    /// of every other: dismissing case B cleared case A's case-open
    /// mark, which silently stopped the accused being served a notice
    /// for a case they are still expected to answer, and worse, cleared
    /// an in-force ban from case A, since a reversal and an unrelated
    /// dismissal are the same disposition on the wire and only the case
    /// id tells them apart.
    ///
    /// So: take the latest surviving verdict of each case, then ask
    /// what the set of them implies. Within a case, later still wins.
    fn intended_marks(
        &self,
        device_binding: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Intended>, Error> {
        let verdicts = self.store.verdicts_for_device(device_binding)?;
        if verdicts.is_empty() {
            return Ok(None);
        }

        // Oldest first, so a later verdict for the same case replaces
        // the earlier one. `order` keeps cases in the sequence their
        // latest verdict arrived, which is what "newest" means below.
        let mut latest: std::collections::HashMap<String, (&StoredVerdict, Verdict)> =
            Default::default();
        let mut order: Vec<String> = Vec::new();
        for stored in verdicts.iter().rev() {
            if stored.superseded {
                continue;
            }
            let verdict: Verdict = match serde_json::from_slice(&stored.raw) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(verdict_ref = %stored.verdict_ref, error = %e, "stored verdict unparseable");
                    continue;
                }
            };
            latest.insert(stored.case_id.clone(), (stored, verdict));
            order.retain(|case_id| case_id != &stored.case_id);
            order.push(stored.case_id.clone());
        }
        if latest.is_empty() {
            return Ok(None);
        }

        let mut open_cases: Vec<String> = Vec::new();
        let mut governing_ban: Option<(String, Verdict, bool)> = None;
        let mut newest_terminal: Option<String> = None;
        let mut realizes: Vec<String> = Vec::new();

        for case_id in &order {
            let Some((stored, verdict)) = latest.get(case_id) else { continue };
            match verdict.disposition {
                crate::types::Disposition::OpenCase => {
                    open_cases.push(stored.verdict_ref.clone());
                    realizes.push(stored.verdict_ref.clone());
                }
                crate::types::Disposition::Dismiss => {
                    // Clears *this* case only — its interim mark, or
                    // its own ban when this is a reversal on appeal.
                    newest_terminal = Some(stored.verdict_ref.clone());
                    realizes.push(stored.verdict_ref.clone());
                }
                crate::types::Disposition::Ban => {
                    if Self::ban_in_force(stored, now) {
                        governing_ban =
                            Some((stored.verdict_ref.clone(), verdict.clone(), stored.executed));
                        newest_terminal = Some(stored.verdict_ref.clone());
                        realizes.push(stored.verdict_ref.clone());
                    } else if Self::ban_expired(stored, now) {
                        // The verdict's own authority clears it; no
                        // further object is needed, and nothing new is
                        // realized by the clearing.
                        newest_terminal = Some("expiry".into());
                    }
                    // Otherwise: decided, but not yet at executeAfter.
                    // It authorizes nothing yet — and the case-open
                    // mark does not survive it either, because the case
                    // is no longer undecided.
                }
            }
        }

        // Whichever verdict actually accounts for the bits being
        // written. A ban in force is the reason the banned bit is set,
        // so it names the write even when some later dismissal in
        // another case arrived afterwards — the write log should not
        // attribute a banned device to a dismissal.
        let authorized_by = match (&governing_ban, open_cases.last(), &newest_terminal) {
            (Some((verdict_ref, _, _)), _, _) => verdict_ref.clone(),
            (None, Some(verdict_ref), _) => verdict_ref.clone(),
            (None, None, Some(verdict_ref)) => verdict_ref.clone(),
            (None, None, None) => String::from("reconciliation"),
        };

        let ban_executed = governing_ban.as_ref().map(|(_, _, executed)| *executed).unwrap_or(false);
        let ban = governing_ban.map(|(verdict_ref, verdict, _)| (verdict_ref, verdict));

        Ok(Some(Intended {
            bits: Bits { case_open: !open_cases.is_empty(), banned: ban.is_some() },
            authorized_by,
            ban,
            realizes,
            ban_executed,
        }))
    }

    /// A ban is in force when execution has begun and expiry hasn't
    /// passed. The interface clears the banned mark at expiry on the
    /// verdict's own authority — no further object is needed
    /// (Moderation.md §5.6 constraint 3).
    fn ban_in_force(stored: &StoredVerdict, now: OffsetDateTime) -> bool {
        let executed = stored
            .execute_after
            .as_deref()
            .and_then(|t| util::parse_timestamp(t).ok())
            .map(|t| t <= now)
            .unwrap_or(false);
        if !executed {
            return false;
        }
        !Self::ban_expired(stored, now)
    }

    fn ban_expired(stored: &StoredVerdict, now: OffsetDateTime) -> bool {
        match stored.ban_expires.as_deref() {
            // No expiry on a ban means the consented term is permanent.
            None => false,
            Some(raw) => util::parse_timestamp(raw).map(|t| t <= now).unwrap_or(false),
        }
    }

    fn ban_state(&self, verdict_ref: &str, verdict: &Verdict) -> BanState {
        BanState {
            verdict_ref: verdict_ref.to_string(),
            authority_contact: format!("{} (see the authority's published manifest)", verdict.authority),
            ban_expires: verdict.ban_expires.clone(),
            appeal_url: None,
            new_holder_url: None,
            verdict: Some(verdict.clone()),
        }
    }

    /// Notices for cases still open against this device. The client
    /// displays these; the case-open mark must not degrade service.
    ///
    /// The deadlines are *derived from the consented manifest* — the
    /// response window and decision deadline the user agreed to,
    /// counted from the case's opening. A notice whose manifest we
    /// don't hold yet is omitted rather than served with invented
    /// dates: these are shown to an accused person deciding when to
    /// respond, and a plausible wrong date is worse than none.
    fn open_case_notices(&self, device_binding: &str) -> Result<Vec<crate::types::CaseNotice>, Error> {
        let verdicts = self.store.verdicts_for_device(device_binding)?;
        let mut notices = Vec::new();
        for stored in verdicts {
            if stored.superseded || stored.disposition != "open-case" {
                continue;
            }
            let Ok(verdict) = serde_json::from_slice::<Verdict>(&stored.raw) else {
                continue;
            };
            let Some(manifest_raw) = self.store.manifest_for_mandate(&verdict.mandate_ref)? else {
                continue;
            };
            let Ok(manifest) = serde_json::from_slice::<crate::types::AuthorityManifest>(&manifest_raw)
            else {
                continue;
            };
            let Some(class) = manifest.violation_class(&verdict.class_id) else {
                continue;
            };
            let Ok(decided_at) = util::parse_timestamp(&verdict.decided_at) else {
                continue;
            };
            let (Ok(response_days), Ok(decision_days)) = (
                util::parse_days(&class.response_window),
                util::parse_days(&class.decision_deadline),
            ) else {
                continue;
            };

            notices.push(crate::types::CaseNotice {
                notice_version: 1,
                case_id: verdict.case_id.clone(),
                authority: verdict.authority.clone(),
                accused: verdict.accused_keys.first().cloned().unwrap_or_default(),
                mandate_ref: verdict.mandate_ref.clone(),
                class_id: verdict.class_id.clone(),
                evidence_summary: verdict.reasoning.clone(),
                response_deadline: util::format_timestamp(
                    decided_at + time::Duration::days(response_days),
                ),
                decision_deadline: util::format_timestamp(
                    decided_at + time::Duration::days(decision_days),
                ),
                signature: verdict.signature.clone(),
            });
        }
        Ok(notices)
    }

    /// The single choke point for `update_two_bits`. Every call is
    /// logged against the verdict (or rule) that authorized it, whether
    /// Apple accepted it or not.
    pub async fn write_bits(
        &self,
        device_check: &DeviceCheck,
        device_token: &str,
        device_binding: &str,
        bits: Bits,
        authorized_by: &str,
        now: OffsetDateTime,
    ) -> Result<(), Error> {
        let stamp = util::format_timestamp(now);
        let result = device_check.update(device_token, bits).await;
        let outcome = match &result {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("failed: {e}"),
        };
        self.store.append_write_log(
            device_binding,
            authorized_by,
            bits.case_open,
            bits.banned,
            &outcome,
            &stamp,
        )?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn engine() -> Engine {
        // No DeviceCheck credentials: these exercise the fold, which is
        // where the reasoning lives. Writing bits is Apple's side.
        Engine { store: Store::in_memory().unwrap(), device_check: None }
    }

    fn at(stamp: &str) -> OffsetDateTime {
        util::parse_timestamp(stamp).unwrap()
    }

    /// One stored verdict for `case_id`. `received_at` is the caller's
    /// ordering handle — the fold's whole premise is that later
    /// verdicts within a case win.
    fn verdict(
        engine: &Engine,
        verdict_ref: &str,
        case_id: &str,
        disposition: &str,
        received_at: &str,
        adjust: impl FnOnce(&mut serde_json::Value, &mut StoredVerdict),
    ) {
        let mut body = serde_json::json!({
            "verdictVersion": 1,
            "caseId": case_id,
            "authority": "onym:component:test-authority",
            "mandateRef": "m1",
            "accusedKeys": ["onym:key:acc"],
            "deviceBinding": "device-1",
            "classId": "csam",
            "disposition": disposition,
            "marks": {
                "case-open": disposition == "open-case",
                "banned": disposition == "ban",
            },
            "reasoning": "hash:findings",
            "decidedAt": received_at,
            "signature": "c2ln",
            "final": disposition != "open-case",
        });
        let mut stored = StoredVerdict {
            verdict_ref: verdict_ref.into(),
            case_id: case_id.into(),
            mandate_ref: "m1".into(),
            device_binding: "device-1".into(),
            raw: Vec::new(),
            disposition: disposition.into(),
            ban_expires: None,
            execute_after: None,
            executed: false,
            superseded: false,
        };
        adjust(&mut body, &mut stored);
        stored.raw = serde_json::to_vec(&body).unwrap();
        engine.store.put_verdict(&stored, received_at).unwrap();
    }

    fn plain(_: &mut serde_json::Value, _: &mut StoredVerdict) {}

    fn ban_from<'a>(
        execute_after: &'a str,
        expires: Option<&'a str>,
    ) -> impl FnOnce(&mut serde_json::Value, &mut StoredVerdict) + 'a {
        move |body: &mut serde_json::Value, stored: &mut StoredVerdict| {
            body["executeAfter"] = serde_json::json!(execute_after);
            stored.execute_after = Some(execute_after.into());
            if let Some(expires) = expires {
                body["banExpires"] = serde_json::json!(expires);
                stored.ban_expires = Some(expires.into());
            }
        }
    }

    fn marks(engine: &Engine, now: &str) -> Intended {
        engine.intended_marks("device-1", at(now)).unwrap().expect("verdicts on file")
    }

    /// The bug this fold exists to prevent. Two cases open at once —
    /// different classes, different reports. Dismissing one must not
    /// clear the other's case-open mark, because notice delivery is
    /// gated on that bit: the accused would silently stop being served
    /// a notice for a case they are still expected to answer.
    #[test]
    fn dismissing_one_case_leaves_another_open_case_marked() {
        let engine = engine();
        verdict(&engine, "v-a-open", "case-a", "open-case", "2026-08-01T00:00:00Z", plain);
        verdict(&engine, "v-b-open", "case-b", "open-case", "2026-08-02T00:00:00Z", plain);
        verdict(&engine, "v-b-dismiss", "case-b", "dismiss", "2026-08-03T00:00:00Z", plain);
        engine.store.supersede_open_case("case-b").unwrap();

        let intended = marks(&engine, "2026-08-04T00:00:00Z");
        assert!(intended.bits.case_open, "case A is still open and still owed its notice");
        assert!(!intended.bits.banned);
        assert_eq!(intended.authorized_by, "v-a-open");
    }

    /// Worse version of the same fold: a reversal and an unrelated
    /// dismissal are the same disposition on the wire, and only the
    /// case id separates them. Dismissing case B must not lift case
    /// A's ban.
    #[test]
    fn dismissing_one_case_does_not_lift_another_cases_ban() {
        let engine = engine();
        verdict(&engine, "v-a-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", Some("2026-12-01T00:00:00Z")));
        verdict(&engine, "v-b-open", "case-b", "open-case", "2026-08-02T00:00:00Z", plain);
        verdict(&engine, "v-b-dismiss", "case-b", "dismiss", "2026-08-03T00:00:00Z", plain);
        engine.store.supersede_open_case("case-b").unwrap();

        let intended = marks(&engine, "2026-08-04T00:00:00Z");
        assert!(intended.bits.banned, "the ban in case A is untouched by case B's dismissal");
        assert_eq!(intended.ban.as_ref().unwrap().0, "v-a-ban");
    }

    /// And the reversal that *is* about this case does lift it.
    #[test]
    fn a_reversal_in_the_same_case_lifts_its_ban() {
        let engine = engine();
        verdict(&engine, "v-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", Some("2026-12-01T00:00:00Z")));
        verdict(&engine, "v-reversal", "case-a", "dismiss", "2026-08-05T00:00:00Z", plain);

        let intended = marks(&engine, "2026-08-06T00:00:00Z");
        assert!(!intended.bits.banned);
        assert!(!intended.bits.case_open);
        assert_eq!(intended.authorized_by, "v-reversal");
    }

    /// The write log must not attribute a banned device to a
    /// dismissal. An auditor reading "banned bits, authorized by a
    /// dismissal" has no way to tell a bug from a forgery.
    #[test]
    fn a_banned_write_is_attributed_to_the_ban_not_a_later_dismissal() {
        let engine = engine();
        verdict(&engine, "v-a-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", Some("2026-12-01T00:00:00Z")));
        verdict(&engine, "v-b-dismiss", "case-b", "dismiss", "2026-08-03T00:00:00Z", plain);

        let intended = marks(&engine, "2026-08-04T00:00:00Z");
        assert!(intended.bits.banned);
        assert_eq!(intended.authorized_by, "v-a-ban");
    }

    /// Within one case, later still wins.
    #[test]
    fn within_a_case_the_latest_verdict_governs() {
        let engine = engine();
        verdict(&engine, "v-open", "case-a", "open-case", "2026-08-01T00:00:00Z", plain);
        verdict(&engine, "v-ban", "case-a", "ban", "2026-08-04T00:00:00Z",
                ban_from("2026-08-04T00:00:00Z", Some("2026-12-01T00:00:00Z")));
        engine.store.supersede_open_case("case-a").unwrap();

        let intended = marks(&engine, "2026-08-05T00:00:00Z");
        assert!(intended.bits.banned);
        assert!(!intended.bits.case_open, "a decided case is no longer an open one");
    }

    /// A ban waiting on its `executeAfter` — the suspensive appeal
    /// window — authorizes nothing yet, and does not leave the case
    /// looking open either: it is decided, just not yet in force.
    #[test]
    fn a_ban_before_its_execute_after_authorizes_nothing() {
        let engine = engine();
        verdict(&engine, "v-open", "case-a", "open-case", "2026-08-01T00:00:00Z", plain);
        verdict(&engine, "v-ban", "case-a", "ban", "2026-08-04T00:00:00Z",
                ban_from("2026-09-04T00:00:00Z", Some("2026-12-01T00:00:00Z")));
        engine.store.supersede_open_case("case-a").unwrap();

        let intended = marks(&engine, "2026-08-05T00:00:00Z");
        assert!(!intended.bits.banned);
        assert!(!intended.bits.case_open);
        assert!(
            !intended.realizes.iter().any(|r| r == "v-ban"),
            "a pending ban must not be flagged executed by an unrelated write"
        );
    }

    /// Expiry clears on the verdict's own authority, with no further
    /// object from the authority.
    #[test]
    fn an_expired_ban_clears_itself() {
        let engine = engine();
        verdict(&engine, "v-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", Some("2026-08-10T00:00:00Z")));

        assert!(marks(&engine, "2026-08-05T00:00:00Z").bits.banned);
        let after = marks(&engine, "2026-08-11T00:00:00Z");
        assert!(!after.bits.banned);
        assert_eq!(after.authorized_by, "expiry");
    }

    /// A ban with no expiry is a consented permanent term, not a
    /// missing field to be defaulted away.
    #[test]
    fn a_permanent_ban_does_not_expire() {
        let engine = engine();
        verdict(&engine, "v-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", None));
        assert!(marks(&engine, "2030-01-01T00:00:00Z").bits.banned);
    }

    /// Two bans, one expired: the live one still governs.
    #[test]
    fn an_expired_ban_does_not_clear_a_live_one() {
        let engine = engine();
        verdict(&engine, "v-a-ban", "case-a", "ban", "2026-08-01T00:00:00Z",
                ban_from("2026-08-01T00:00:00Z", Some("2026-08-10T00:00:00Z")));
        verdict(&engine, "v-b-ban", "case-b", "ban", "2026-08-02T00:00:00Z",
                ban_from("2026-08-02T00:00:00Z", Some("2026-12-01T00:00:00Z")));

        let intended = marks(&engine, "2026-08-11T00:00:00Z");
        assert!(intended.bits.banned);
        assert_eq!(intended.ban.as_ref().unwrap().0, "v-b-ban");
    }

    /// A superseded interim verdict is out of the fold entirely.
    #[test]
    fn superseded_verdicts_are_ignored() {
        let engine = engine();
        verdict(&engine, "v-open", "case-a", "open-case", "2026-08-01T00:00:00Z", plain);
        engine.store.supersede_open_case("case-a").unwrap();
        assert!(engine.intended_marks("device-1", at("2026-08-02T00:00:00Z")).unwrap().is_none());
    }

    #[test]
    fn a_device_with_no_verdicts_intends_nothing() {
        let engine = engine();
        assert!(engine.intended_marks("device-1", at("2026-08-02T00:00:00Z")).unwrap().is_none());
    }
}
