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
    /// authorize. Later verdicts win; expiry and supersession clear.
    fn intended_marks(
        &self,
        device_binding: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Intended>, Error> {
        let verdicts = self.store.verdicts_for_device(device_binding)?;
        if verdicts.is_empty() {
            return Ok(None);
        }

        // The case-open bit is aggregate — one bit for the device, not
        // one per case — and that is exactly why it has to be derived
        // from the set of cases still open rather than from whichever
        // terminal verdict arrived last. A device can carry several
        // cases at once, and clearing the bit on case B's dismissal
        // takes case A's notice down with it: `gate_check` only serves
        // notices when the bit is set, so the accused would stop being
        // told about a case they are still expected to answer.
        let mut open_cases: Vec<(String, String)> = Vec::new();
        // More than one consented class can produce a live ban on the
        // same device. Keep them by case while folding so a dismissal
        // reverses only the case it names rather than clearing an
        // unrelated sanction.
        let mut bans: Vec<(String, Verdict, bool)> = Vec::new();
        let mut authorized_by = String::from("reconciliation");
        let mut realizes: Vec<String> = Vec::new();

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
            // `realizes` collects only verdicts whose marks this write
            // actually puts into effect — a ban still waiting on its
            // executeAfter must not be flagged executed because some
            // unrelated write succeeded.
            match verdict.disposition {
                crate::types::Disposition::OpenCase => {
                    if !open_cases.iter().any(|(case_id, _)| case_id == &verdict.case_id) {
                        open_cases.push((verdict.case_id.clone(), stored.verdict_ref.clone()));
                        realizes.push(stored.verdict_ref.clone());
                    }
                    authorized_by = stored.verdict_ref.clone();
                }
                crate::types::Disposition::Dismiss => {
                    // Terminal for its own case, and only its own:
                    // this case stops contributing to the aggregate
                    // bit, and the dismissal is a ban reversal only
                    // here.
                    Self::close_open_case(&mut open_cases, &mut realizes, &verdict.case_id);
                    let mut removed_refs = Vec::new();
                    bans.retain(|(verdict_ref, active, _)| {
                        if active.case_id == verdict.case_id {
                            removed_refs.push(verdict_ref.clone());
                            false
                        } else {
                            true
                        }
                    });
                    realizes.retain(|verdict_ref| !removed_refs.contains(verdict_ref));
                    authorized_by = stored.verdict_ref.clone();
                    realizes.push(stored.verdict_ref.clone());
                }
                crate::types::Disposition::Ban => {
                    // Decided, so no longer an open case — whatever
                    // else is true of the ban. A ban waiting on its
                    // `executeAfter` used to `continue` before this,
                    // so for the whole of a suspensive appeal window
                    // the device kept the aggregate case-open bit set
                    // while the verdict itself declares
                    // `case-open: false`. The mark and the document
                    // authorizing it have to agree.
                    Self::close_open_case(&mut open_cases, &mut realizes, &verdict.case_id);

                    if !Self::ban_in_force(stored, now) {
                        // Either not yet at executeAfter, or expired.
                        // A pending replacement does not end an
                        // already-active ban for the same case. An
                        // expired verdict does.
                        if Self::ban_expired(stored, now) {
                            let mut removed_refs = Vec::new();
                            bans.retain(|(verdict_ref, active, _)| {
                                if active.case_id == verdict.case_id {
                                    removed_refs.push(verdict_ref.clone());
                                    false
                                } else {
                                    true
                                }
                            });
                            realizes.retain(|verdict_ref| !removed_refs.contains(verdict_ref));
                            authorized_by = "expiry".into();
                        }
                        continue;
                    }

                    // A later in-force verdict for the same case
                    // replaces the earlier one; other cases remain
                    // independently in force.
                    let mut removed_refs = Vec::new();
                    bans.retain(|(verdict_ref, active, _)| {
                        if active.case_id == verdict.case_id {
                            removed_refs.push(verdict_ref.clone());
                            false
                        } else {
                            true
                        }
                    });
                    realizes.retain(|verdict_ref| !removed_refs.contains(verdict_ref));

                    bans.push((stored.verdict_ref.clone(), verdict, stored.executed));
                    authorized_by = stored.verdict_ref.clone();
                    realizes.push(stored.verdict_ref.clone());
                }
            }
        }

        // The bit is aggregate, while the refusal response can carry
        // one governing verdict. Show the newest ban still in force;
        // clearing it later reveals the next active case rather than
        // clearing the device.
        let ban = bans
            .last()
            .map(|(verdict_ref, verdict, _)| (verdict_ref.clone(), verdict.clone()));
        // Only an executed ban still in force indicates that the
        // current banned bit should already exist on this identity's
        // device. An expired or reversed ban was deliberately cleared;
        // remembering it here would prevent every later ban from ever
        // writing its mark.
        let ban_executed = bans.iter().any(|(_, _, executed)| *executed);

        // A ban in force is the reason the banned bit is set, so it
        // names the write even when a dismissal in some other case
        // arrived afterwards. Otherwise the write log reads "banned
        // bits, authorized by a dismissal", and an auditor has no way
        // to tell that from a forgery.
        if let Some((verdict_ref, _, _)) = bans.last() {
            authorized_by = verdict_ref.clone();
        }

        Ok(Some(Intended {
            bits: Bits { case_open: !open_cases.is_empty(), banned: !bans.is_empty() },
            authorized_by,
            ban,
            realizes,
            ban_executed,
        }))
    }

    fn close_open_case(
        open_cases: &mut Vec<(String, String)>,
        realizes: &mut Vec<String>,
        case_id: &str,
    ) {
        let removed_refs: Vec<String> = open_cases
            .iter()
            .filter(|(open_case_id, _)| open_case_id == case_id)
            .map(|(_, verdict_ref)| verdict_ref.clone())
            .collect();
        open_cases.retain(|(open_case_id, _)| open_case_id != case_id);
        realizes.retain(|verdict_ref| !removed_refs.contains(verdict_ref));
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
    use crate::types::{Disposition, Marks};

    const DEVICE: &str = "device-1";
    const MANDATE: &str = "mandate-1";

    fn verdict(case_id: &str, disposition: Disposition, class_id: &str) -> Verdict {
        let banned = disposition == Disposition::Ban;
        Verdict {
            verdict_version: 1,
            case_id: case_id.into(),
            authority: "onym:component:authority".into(),
            mandate_ref: MANDATE.into(),
            accused_keys: vec!["onym:key:accused".into()],
            device_binding: DEVICE.into(),
            class_id: class_id.into(),
            disposition,
            marks: Marks {
                case_open: false,
                banned,
            },
            ban_expires: None,
            execute_after: banned.then(|| "2026-08-08T00:00:00Z".into()),
            reasoning: "reasoning-ref".into(),
            appeal_deadline: banned.then(|| "2026-09-07T00:00:00Z".into()),
            decided_at: "2026-08-08T00:00:00Z".into(),
            signature: "signature".into(),
            is_final: !banned,
        }
    }

    fn store_verdict(store: &Store, verdict_ref: &str, verdict: Verdict, received_at: &str) {
        let raw = serde_json::to_vec(&verdict).unwrap();
        let disposition = match verdict.disposition {
            Disposition::OpenCase => "open-case",
            Disposition::Dismiss => "dismiss",
            Disposition::Ban => "ban",
        };
        store
            .put_verdict(
                &StoredVerdict {
                    verdict_ref: verdict_ref.into(),
                    case_id: verdict.case_id,
                    mandate_ref: MANDATE.into(),
                    device_binding: DEVICE.into(),
                    raw,
                    disposition: disposition.into(),
                    ban_expires: verdict.ban_expires,
                    execute_after: verdict.execute_after,
                    executed: true,
                    superseded: false,
                },
                received_at,
            )
            .unwrap();
    }

    fn engine() -> Engine {
        Engine {
            store: Store::in_memory().unwrap(),
            device_check: None,
        }
    }

    fn now() -> OffsetDateTime {
        util::parse_timestamp("2026-08-09T00:00:00Z").unwrap()
    }

    #[test]
    fn dismissal_does_not_clear_a_ban_from_another_case() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "ban-csam",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-violence",
            verdict("case-violence", Disposition::Dismiss, "credible-violence"),
            "2026-08-08T01:00:00Z",
        );

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned);
        assert_eq!(intended.ban.unwrap().1.case_id, "case-csam");
    }

    #[test]
    fn dismissal_clears_only_its_case_when_two_bans_are_live() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "ban-csam",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "ban-violence",
            verdict("case-violence", Disposition::Ban, "credible-violence"),
            "2026-08-08T01:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-violence",
            verdict("case-violence", Disposition::Dismiss, "credible-violence"),
            "2026-08-08T02:00:00Z",
        );

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned);
        assert_eq!(intended.ban.unwrap().1.case_id, "case-csam");
    }

    #[test]
    fn dismissal_clears_a_ban_from_the_same_case() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "ban-csam",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-csam",
            verdict("case-csam", Disposition::Dismiss, "csam"),
            "2026-08-08T01:00:00Z",
        );

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(!intended.bits.banned);
        assert!(intended.ban.is_none());
    }

    #[test]
    fn a_terminal_verdict_does_not_realize_its_superseded_open_case_ref() {
        let engine = engine();
        let open = verdict("case-csam", Disposition::OpenCase, "csam");
        let dismiss = verdict("case-csam", Disposition::Dismiss, "csam");
        for (verdict_ref, value, received_at) in [
            ("open-csam", open, "2026-08-08T00:00:00Z"),
            ("dismiss-csam", dismiss, "2026-08-08T01:00:00Z"),
        ] {
            let raw = serde_json::to_vec(&value).unwrap();
            engine
                .store
                .put_verdict(
                    &StoredVerdict {
                        verdict_ref: verdict_ref.into(),
                        case_id: value.case_id,
                        mandate_ref: MANDATE.into(),
                        device_binding: DEVICE.into(),
                        raw,
                        disposition: match value.disposition {
                            Disposition::OpenCase => "open-case",
                            Disposition::Dismiss => "dismiss",
                            Disposition::Ban => "ban",
                        }
                        .into(),
                        ban_expires: value.ban_expires,
                        execute_after: value.execute_after,
                        executed: false,
                        superseded: false,
                    },
                    received_at,
                )
                .unwrap();
        }

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(!intended.realizes.iter().any(|reference| reference == "open-csam"));
        assert!(intended.realizes.iter().any(|reference| reference == "dismiss-csam"));
    }

    /// The other half of the same fold. Two cases open at once — they
    /// are different classes, opened by different reports — and the
    /// case-open bit is aggregate. Dismissing one must not clear it
    /// while the other is still running: `gate_check` only serves
    /// notices when the bit is set, so the accused would silently stop
    /// being told about a case they are still expected to answer.
    #[test]
    fn dismissal_leaves_the_case_open_bit_set_while_another_case_runs() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "open-csam",
            verdict("case-csam", Disposition::OpenCase, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "open-violence",
            verdict("case-violence", Disposition::OpenCase, "credible-violence"),
            "2026-08-08T01:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-violence",
            verdict("case-violence", Disposition::Dismiss, "credible-violence"),
            "2026-08-08T02:00:00Z",
        );
        engine.store.supersede_open_case("case-violence").unwrap();

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.case_open, "case-csam is still open and still owed its notice");
        assert!(!intended.bits.banned);
    }

    /// And the last one closing does clear it.
    #[test]
    fn the_case_open_bit_clears_when_the_last_case_closes() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "open-csam",
            verdict("case-csam", Disposition::OpenCase, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-csam",
            verdict("case-csam", Disposition::Dismiss, "csam"),
            "2026-08-08T02:00:00Z",
        );
        engine.store.supersede_open_case("case-csam").unwrap();

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(!intended.bits.case_open);
    }

    /// A ban in one case does not close another case either — and when
    /// it expires, the still-open case is still marked.
    #[test]
    fn a_ban_in_one_case_does_not_close_another() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "open-csam",
            verdict("case-csam", Disposition::OpenCase, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "ban-violence",
            verdict("case-violence", Disposition::Ban, "credible-violence"),
            "2026-08-08T01:00:00Z",
        );

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned);
        assert!(intended.bits.case_open, "the csam case is still awaiting its response");
    }

    /// The write log must not attribute a banned device to a
    /// dismissal. An auditor reading that has no way to tell a bug
    /// from a forgery.
    #[test]
    fn a_banned_write_is_attributed_to_the_ban_not_a_later_dismissal() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "ban-csam",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "dismiss-violence",
            verdict("case-violence", Disposition::Dismiss, "credible-violence"),
            "2026-08-08T02:00:00Z",
        );

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned);
        assert_eq!(intended.authorized_by, "ban-csam");
    }


    /// The moved-device check reads `ban_executed`. With two live bans
    /// where the older was written to a device and the newer has not
    /// been yet, taking only the newest answered "never branded" — and
    /// the engine would then write bits onto a device presenting clean
    /// ones, which is exactly the hardware that may have changed hands.
    #[test]
    fn any_executed_ban_counts_as_having_branded_a_device() {
        let engine = engine();
        // Older ban, already written.
        store_verdict(
            &engine.store,
            "ban-csam",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        // Newer ban in another case, not yet written.
        let mut fresh = StoredVerdict {
            verdict_ref: "ban-violence".into(),
            case_id: "case-violence".into(),
            mandate_ref: MANDATE.into(),
            device_binding: DEVICE.into(),
            raw: serde_json::to_vec(&verdict(
                "case-violence",
                Disposition::Ban,
                "credible-violence",
            ))
            .unwrap(),
            disposition: "ban".into(),
            ban_expires: None,
            execute_after: Some("2026-08-08T00:00:00Z".into()),
            executed: false,
            superseded: false,
        };
        fresh.executed = false;
        engine.store.put_verdict(&fresh, "2026-08-08T01:00:00Z").unwrap();

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned);
        assert!(
            intended.ban_executed,
            "an earlier ban was already branded onto a device; this identity has been marked"
        );
    }

    /// Once an executed ban expires and reconciliation clears its bit,
    /// it must not prevent a later independent ban from executing.
    #[test]
    fn an_expired_executed_ban_does_not_block_a_later_ban() {
        let engine = engine();

        let mut expired = verdict("case-csam", Disposition::Ban, "csam");
        expired.ban_expires = Some("2026-08-08T12:00:00Z".into());
        store_verdict(
            &engine.store,
            "expired-ban",
            expired,
            "2026-08-08T00:00:00Z",
        );

        let active = verdict("case-violence", Disposition::Ban, "credible-violence");
        let active_raw = serde_json::to_vec(&active).unwrap();
        engine
            .store
            .put_verdict(
                &StoredVerdict {
                    verdict_ref: "active-ban".into(),
                    case_id: active.case_id,
                    mandate_ref: MANDATE.into(),
                    device_binding: DEVICE.into(),
                    raw: active_raw,
                    disposition: "ban".into(),
                    ban_expires: active.ban_expires,
                    execute_after: active.execute_after,
                    executed: false,
                    superseded: false,
                },
                "2026-08-08T13:00:00Z",
            )
            .unwrap();

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(intended.bits.banned, "the newer ban is still active");
        assert!(
            !intended.ban_executed,
            "the active ban has not executed; the expired ban was already cleared"
        );
    }

    /// At-least-once delivery may submit the same verdict again after
    /// it has executed. The retry must preserve execution state and
    /// must not make the old verdict newest by resetting receivedAt.
    #[test]
    fn duplicate_verdict_delivery_preserves_execution_and_order() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "first-ban",
            verdict("case-csam", Disposition::Ban, "csam"),
            "2026-08-08T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "later-ban",
            verdict("case-violence", Disposition::Ban, "credible-violence"),
            "2026-08-08T01:00:00Z",
        );

        let stored = engine.store.verdicts_for_device(DEVICE).unwrap();
        let mut retry = stored
            .iter()
            .find(|v| v.verdict_ref == "first-ban")
            .unwrap()
            .clone();
        retry.executed = false;
        engine.store.put_verdict(&retry, "2026-08-08T02:00:00Z").unwrap();

        let after = engine.store.verdicts_for_device(DEVICE).unwrap();
        assert_eq!(after[0].verdict_ref, "later-ban");
        assert!(
            after
                .iter()
                .find(|v| v.verdict_ref == "first-ban")
                .unwrap()
                .executed,
            "a retry cannot turn an executed verdict back into pending"
        );
    }


    /// A suspensive ban waits out its appeal window before executing.
    /// For that whole period the case is *decided*, so the case-open
    /// bit must be clear — the verdict itself says `case-open: false`,
    /// and the mark has to agree with the document authorizing it.
    #[test]
    fn a_ban_awaiting_its_execute_after_closes_its_case() {
        let engine = engine();
        store_verdict(
            &engine.store,
            "open-csam",
            verdict("case-csam", Disposition::OpenCase, "csam"),
            "2026-08-08T00:00:00Z",
        );
        let mut pending = StoredVerdict {
            verdict_ref: "ban-csam".into(),
            case_id: "case-csam".into(),
            mandate_ref: MANDATE.into(),
            device_binding: DEVICE.into(),
            raw: serde_json::to_vec(&verdict("case-csam", Disposition::Ban, "csam")).unwrap(),
            disposition: "ban".into(),
            ban_expires: None,
            // Executes a month out: the consented appeal window.
            execute_after: Some("2026-09-08T00:00:00Z".into()),
            executed: false,
            superseded: false,
        };
        pending.executed = false;
        engine.store.put_verdict(&pending, "2026-08-08T01:00:00Z").unwrap();
        engine.store.supersede_open_case("case-csam").unwrap();

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(!intended.bits.banned, "the ban has not begun");
        assert!(!intended.bits.case_open, "but the case is decided, not open");
    }

}
