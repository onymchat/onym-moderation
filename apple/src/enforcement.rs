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

        let mut case_open = false;
        let mut ban: Option<(String, Verdict)> = None;
        let mut authorized_by = String::from("reconciliation");
        let mut realizes: Vec<String> = Vec::new();
        let mut ban_executed = false;

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
                    case_open = true;
                    authorized_by = stored.verdict_ref.clone();
                    realizes.push(stored.verdict_ref.clone());
                }
                crate::types::Disposition::Dismiss => {
                    // Dismissal clears the case-open mark, and a
                    // reversal on appeal clears a ban.
                    case_open = false;
                    ban = None;
                    authorized_by = stored.verdict_ref.clone();
                    realizes.push(stored.verdict_ref.clone());
                }
                crate::types::Disposition::Ban => {
                    if !Self::ban_in_force(stored, now) {
                        // Either not yet at executeAfter, or expired.
                        // Both mean: not banned right now.
                        if Self::ban_expired(stored, now) {
                            authorized_by = "expiry".into();
                            ban = None;
                        }
                        continue;
                    }
                    case_open = false;
                    ban = Some((stored.verdict_ref.clone(), verdict));
                    authorized_by = stored.verdict_ref.clone();
                    realizes.push(stored.verdict_ref.clone());
                    ban_executed = stored.executed;
                }
            }
        }

        Ok(Some(Intended {
            bits: Bits { case_open, banned: ban.is_some() },
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
