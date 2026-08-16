//! The enforcement engine: what a gate check answers, and the lazy
//! reconciliation that clears marks on expiry, reversal, and the
//! decision-deadline default (Moderation-Device-Recall.md §5–§6).
//!
//! Two rules govern everything here:
//!
//! 1. **Reading is platform-state-first.** The recall values are the
//!    durable state the refusal consults, which is what survives
//!    reinstall. A device whose `bitSecond` is set is refused whether
//!    or not we can resolve its enrollment.
//! 2. **Marks move only on verdicts, and defaults only ever clear.**
//!    Nothing but a validated verdict sets a mark; expiry, reversal,
//!    and the decision deadline can only clear one.

use time::OffsetDateTime;

use crate::classifier::{self, Expected};
use crate::error::Error;
use crate::play_integrity::{Bits, PlayIntegrity, RecallChanges};
use crate::store::{Store, StoredVerdict};
use crate::types::{BanState, CheckRequiredReason, GateCheckResult, Verdict};
use crate::util;

/// The Play side of the engine: the API client plus the policy a
/// trustworthy token must satisfy. Absent when credentials are not
/// configured — the gate then answers `checkRequired` for everyone,
/// degraded toward blocking, never toward unmoderated operation.
pub struct PlayEnforcement {
    pub client: PlayIntegrity,
    /// The package name a token's requestDetails/appIntegrity must name.
    pub package_name: String,
    /// Accepted signing-certificate SHA-256 digests, Google's spelling.
    pub cert_sha256_digests: Vec<String>,
    /// Freshness window for `requestDetails.timestampMillis`, seconds.
    pub token_max_age_secs: i64,
}

pub struct Engine {
    pub store: Store,
    pub play: Option<PlayEnforcement>,
    /// How long after an accepted write a stale read is attributed to
    /// Google's documented up-to-30s propagation lag rather than
    /// re-written (profile §4 requirement 5).
    pub propagation_grace_secs: i64,
}

/// What the stored verdict record says the marks *should* be, and which
/// verdict (or rule) authorizes that.
struct Intended {
    bits: Bits,
    authorized_by: String,
    ban: Option<(String, Verdict)>,
    /// Verdicts whose marks this write realizes, so they can be flagged
    /// executed once Google accepts it.
    realizes: Vec<String>,
    /// Whether the ban in force has already been written to a device.
    ban_executed: bool,
}

impl Engine {
    /// Decode and classify an integrity token into trusted mark state.
    ///
    /// `Ok(None)` means "no trustworthy answer" — Google rejected the
    /// token, or a classifier prerequisite failed — which callers must
    /// map to `checkRequired`, never to clean. Answering `clear` to an
    /// unverifiable token would let anyone bypass the gate by sending
    /// garbage (profile §5.2).
    pub async fn verified_bits(
        &self,
        play: &PlayEnforcement,
        integrity_token: &str,
        request_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Bits>, Error> {
        let Some(decoded) = play.client.decode(integrity_token).await? else {
            return Ok(None);
        };
        let expected = Expected {
            package_name: &play.package_name,
            cert_sha256_digests: &play.cert_sha256_digests,
            request_hash,
            now_millis: (now.unix_timestamp_nanos() / 1_000_000) as i64,
            max_age_millis: play.token_max_age_secs * 1000,
        };
        match classifier::classify(&decoded, &expected) {
            Ok(bits) => {
                // The disclosed §8-gap-6 ambiguity: a technically
                // unavailable recall result that passes every
                // prerequisite is indistinguishable from a clean
                // never-written device. This event is the mandated
                // monitoring signal for empty-result anomalies.
                let recall = decoded.device_integrity.device_recall.as_ref();
                if bits == Bits::default()
                    && recall.is_some_and(|r| {
                        r.write_dates.yyyymm_first.is_none()
                            && r.write_dates.yyyymm_second.is_none()
                            && r.write_dates.yyyymm_third.is_none()
                    })
                {
                    // info!, not debug!: this is the §8-gap-6
                    // monitoring signal the profile mandates, and the
                    // deployment pins RUST_LOG=info — at debug it
                    // would never fire in production.
                    tracing::info!(monitor = "recall_empty_result", "recall object present and empty");
                }
                Ok(Some(bits))
            }
            Err(failure) => {
                tracing::warn!(reason = failure.describe(), "integrity token failed the classifier");
                Ok(None)
            }
        }
    }

    /// Answer a gate check for a device. The caller has already
    /// verified the identity signature, claimed the session and
    /// challenge, and recomputed `request_hash` from the signed
    /// payload; this decodes the token, classifies it, and reconciles.
    pub async fn gate_check(
        &self,
        integrity_token: Option<&str>,
        request_hash: &str,
        user_key: &str,
        now: OffsetDateTime,
    ) -> Result<GateCheckResult, Error> {
        let Some(play) = self.play.as_ref() else {
            // No Play credentials configured: we cannot read values, so
            // we cannot clear anyone.
            return Ok(GateCheckResult::check_required(
                CheckRequiredReason::AttestationUnavailable,
            ));
        };
        let Some(integrity_token) = integrity_token else {
            return Ok(GateCheckResult::check_required(
                CheckRequiredReason::AttestationUnavailable,
            ));
        };

        let Some(bits) = self.verified_bits(play, integrity_token, request_hash, now).await? else {
            return Ok(GateCheckResult::check_required(CheckRequiredReason::TokenInvalid));
        };
        self.reconcile(play, integrity_token, user_key, bits, now).await
    }

    /// Session-mediated reconciliation: with a live verified token in
    /// hand, bring the recall values in line with what the verdict
    /// record now implies, before answering.
    async fn reconcile(
        &self,
        play: &PlayEnforcement,
        integrity_token: &str,
        user_key: &str,
        bits: Bits,
        now: OffsetDateTime,
    ) -> Result<GateCheckResult, Error> {
        let binding = self.store.device_binding_for_user(user_key)?;
        let intended = match binding.as_deref() {
            Some(binding) => self.intended_marks(binding, now)?,
            None => None,
        };

        if let Some(intended) = intended.as_ref() {
            if intended.bits != bits {
                // A ban we have already branded onto a device, meeting
                // a device whose values are clean, is a *different
                // piece of hardware* presenting the same identity —
                // someone who moved to a new phone. Integrity tokens
                // are request artifacts, not device identifiers, so
                // this is the only signal available, and branding on it
                // would mark a device the verdict never named, quite
                // possibly someone else's.
                //
                // The contract already says what to do: the identity
                // refusal covers the named keys on every surface, while
                // device marks reach only the devices the verdict names
                // (§5.3 constraint 4). So refuse the identity below,
                // and leave this device's values alone.
                let would_brand_another_device =
                    intended.bits.banned && !bits.banned && intended.ban_executed;

                // A read that merely lags a write Google already
                // accepted is propagation, not divergence: re-writing
                // the same state every session until the cache catches
                // up would spend quota to say nothing. Serve the
                // intended state and let the window pass (profile §4
                // requirement 5).
                let within_propagation_window = match binding.as_deref() {
                    Some(b) => self.store.last_recall_write(b)?.is_some_and(
                        |(case_open, banned, written_at)| {
                            Bits { case_open, banned } == intended.bits
                                && util::parse_timestamp(&written_at).is_ok_and(|written| {
                                    now - written
                                        <= time::Duration::seconds(self.propagation_grace_secs)
                                })
                        },
                    ),
                    None => false,
                };

                if would_brand_another_device {
                    tracing::warn!(
                        binding = %binding.as_deref().unwrap_or("unresolved"),
                        "banned identity presented a device with clean values; refusing the \
                         identity without marking this device"
                    );
                } else if within_propagation_window {
                    tracing::debug!(
                        binding = %binding.as_deref().unwrap_or("unresolved"),
                        "read lags an accepted write inside the propagation window; not rewriting"
                    );
                } else {
                    self.write_bits(
                        play,
                        integrity_token,
                        binding.as_deref().unwrap_or("unresolved"),
                        bits,
                        intended.bits,
                        &intended.authorized_by,
                        now,
                    )
                    .await?;
                    // Only now — after Google accepted the write — are
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
                        authorized_by = stored.verdict_ref.clone();
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
        } else if let Some((_, verdict_ref)) = open_cases.last() {
            // With no ban in force, an active case is the reason the
            // aggregate case-open bit is set. A later dismissal for a
            // different case must not be named as its authorizer.
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
            authority_contact: verdict.authority_contact.clone().unwrap_or_else(|| {
                format!("{} (see the authority's published manifest)", verdict.authority)
            }),
            ban_expires: verdict.ban_expires.clone(),
            appeal_url: verdict.appeal_url.clone(),
            new_holder_url: verdict.new_holder_url.clone(),
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
    ///
    /// **One notice per case, the latest.** The authority issues a
    /// fresh `open-case` verdict for every report joined to a case, and
    /// none of them supersede each other — they are all notices of the
    /// same live case. Serving all of them handed the accused several
    /// notices for one case, each with `responseDeadline` counted from
    /// its own `decidedAt`, so the earlier ones showed windows that had
    /// already lapsed while the authority was enforcing only the
    /// newest. That is the invented-date failure the paragraph above
    /// warns about, arrived at from the other direction: every date was
    /// correctly derived, and all but one described a deadline nobody
    /// was working to.
    ///
    /// `verdicts_for_device` already returns newest-first under a total
    /// order, so the first `open-case` row seen for a case is the one
    /// in force. Taking the dedupe from that ordering rather than
    /// re-deriving "latest" here keeps this agreeing with the causal
    /// fold that decides the marks.
    fn open_case_notices(&self, device_binding: &str) -> Result<Vec<crate::types::CaseNotice>, Error> {
        let verdicts = self.store.verdicts_for_device(device_binding)?;
        let mut seen_cases = std::collections::HashSet::new();
        let mut notices = Vec::new();
        for stored in verdicts {
            if stored.superseded || stored.disposition != "open-case" {
                continue;
            }
            // Claimed on the stored row, before the verdict is parsed
            // and before any of the render checks below. A case whose
            // newest notice cannot be rendered — no consented manifest
            // on file yet, an unreadable class — must serve *nothing*,
            // not fall back to an older notice carrying a lapsed
            // deadline. Falling back is the same bug wearing the
            // omission rule as a disguise.
            if !seen_cases.insert(stored.case_id.clone()) {
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

    /// The single choke point for `deviceRecall:write`. Every call is
    /// logged against the verdict (or rule) that authorized it, whether
    /// Google accepted it or not — and the log records exactly which
    /// values the request specified, because the write itself must name
    /// only what changes: `bitThird` is structurally absent from
    /// `RecallChanges`, and unchanged values are omitted (profile §4
    /// requirements 1 and 3).
    #[allow(clippy::too_many_arguments)]
    pub async fn write_bits(
        &self,
        play: &PlayEnforcement,
        integrity_token: &str,
        device_binding: &str,
        current: Bits,
        intended: Bits,
        authorized_by: &str,
        now: OffsetDateTime,
    ) -> Result<(), Error> {
        let changes = RecallChanges::diff(current, intended);
        if changes.is_empty() {
            return Ok(());
        }
        let fields_written = serde_json::to_string(&changes)
            .map_err(|e| Error::Internal(format!("serialize fields_written: {e}")))?;

        let stamp = util::format_timestamp(now);
        let result = play.client.write_recall(integrity_token, changes).await;
        let outcome = match &result {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("failed: {e}"),
        };
        self.store.append_write_log(
            device_binding,
            authorized_by,
            intended.case_open,
            intended.banned,
            &fields_written,
            &outcome,
            &stamp,
        )?;
        if result.is_ok() {
            // The propagation guard's memory: what Google now holds,
            // and when it started counting toward the read-visible
            // window.
            self.store.record_recall_write(
                device_binding,
                intended.case_open,
                intended.banned,
                &stamp,
            )?;
        }
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
            appeal_url: None,
            new_holder_url: None,
            authority_contact: None,
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
                    case_id: verdict.case_id.clone(),
                    decided_at: verdict.decided_at.clone(),
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
            play: None,
            propagation_grace_secs: 60,
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
                        case_id: value.case_id.clone(),
                        decided_at: value.decided_at.clone(),
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
        assert_eq!(intended.authorized_by, "open-csam");
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
            decided_at: "2026-08-08T01:00:00Z".into(),
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
                    case_id: active.case_id.clone(),
                    decided_at: active.decided_at.clone(),
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
        // verdictRef addresses signing bytes, not the signature
        // envelope. Re-signing the same decision is still a retry.
        let mut envelope: serde_json::Value = serde_json::from_slice(&retry.raw).unwrap();
        envelope["signature"] = serde_json::json!("replacement-signature");
        retry.raw = serde_json::to_vec(&envelope).unwrap();
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
            decided_at: "2026-08-08T01:00:00Z".into(),
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
        assert_eq!(intended.authorized_by, "ban-csam");
    }


    /// Delivery is at-least-once and not single-flight, so the
    /// authority can commit a ban and then its reversal while the ban
    /// is still queued — and the reversal can arrive first. Folding by
    /// arrival made the ban the newest input when it finally landed,
    /// and it reinstated itself *after* the reversal that lifted it.
    ///
    /// Causality belongs to the authority that decided. `decidedAt` is
    /// inside the signing bytes, so it cannot be reordered in transit.
    #[test]
    fn a_late_arriving_ban_does_not_undo_the_reversal_that_lifted_it() {
        let engine = engine();

        // The reversal is decided second and arrives first.
        let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
        reversal.decided_at = "2026-08-08T02:00:00Z".into();
        store_verdict(&engine.store, "reversal", reversal, "2026-08-08T10:00:00Z");

        // The ban was decided first and lands late.
        let mut ban = verdict("case-csam", Disposition::Ban, "csam");
        ban.decided_at = "2026-08-08T01:00:00Z".into();
        store_verdict(&engine.store, "ban", ban, "2026-08-08T11:00:00Z");

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(
            !intended.bits.banned,
            "a ban decided before the reversal that lifted it must not come back by arriving late"
        );
    }

    #[test]
    fn same_second_reversal_has_terminal_precedence_over_a_late_ban() {
        let engine = engine();

        let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
        reversal.decided_at = "2026-08-08T01:00:00Z".into();
        store_verdict(&engine.store, "reversal", reversal, "2026-08-08T10:00:00Z");

        let mut ban = verdict("case-csam", Disposition::Ban, "csam");
        ban.decided_at = "2026-08-08T01:00:00Z".into();
        store_verdict(&engine.store, "ban", ban, "2026-08-08T11:00:00Z");

        assert!(!engine.intended_marks(DEVICE, now()).unwrap().unwrap().bits.banned);
    }

    /// 09:00-05:00 is 14:00Z, so this reversal at 14:30Z is later even
    /// though its RFC 3339 wire string sorts below the ban's.
    #[test]
    fn decision_order_normalizes_rfc3339_offsets() {
        let engine = engine();

        let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
        reversal.decided_at = "2026-08-08T14:30:00Z".into();
        store_verdict(&engine.store, "reversal", reversal, "2026-08-08T10:00:00Z");

        let mut ban = verdict("case-csam", Disposition::Ban, "csam");
        ban.decided_at = "2026-08-08T09:00:00-05:00".into();
        store_verdict(&engine.store, "ban", ban, "2026-08-08T11:00:00Z");

        assert!(!engine.intended_marks(DEVICE, now()).unwrap().unwrap().bits.banned);
    }

    /// The same shape, one disposition over: a stale `open-case`
    /// landing after the dismissal that closed its case must not
    /// reopen it and re-mark the device.
    #[test]
    fn a_late_arriving_notice_does_not_reopen_a_dismissed_case() {
        let engine = engine();

        let mut dismissal = verdict("case-csam", Disposition::Dismiss, "csam");
        dismissal.decided_at = "2026-08-08T02:00:00Z".into();
        store_verdict(&engine.store, "dismissal", dismissal, "2026-08-08T10:00:00Z");

        let mut notice = verdict("case-csam", Disposition::OpenCase, "csam");
        notice.decided_at = "2026-08-08T01:00:00Z".into();
        store_verdict(&engine.store, "notice", notice, "2026-08-08T11:00:00Z");

        let intended = engine.intended_marks(DEVICE, now()).unwrap().unwrap();
        assert!(!intended.bits.case_open, "the case was closed before that notice was written");
        assert!(!intended.bits.banned);
    }

    /// And in-order delivery still behaves: a reversal decided after a
    /// ban lifts it.
    #[test]
    fn a_reversal_decided_after_a_ban_still_lifts_it() {
        let engine = engine();

        let mut ban = verdict("case-csam", Disposition::Ban, "csam");
        ban.decided_at = "2026-08-08T01:00:00Z".into();
        store_verdict(&engine.store, "ban", ban, "2026-08-08T01:00:00Z");
        assert!(engine.intended_marks(DEVICE, now()).unwrap().unwrap().bits.banned);

        let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
        reversal.decided_at = "2026-08-08T02:00:00Z".into();
        store_verdict(&engine.store, "reversal", reversal, "2026-08-08T02:00:00Z");

        assert!(!engine.intended_marks(DEVICE, now()).unwrap().unwrap().bits.banned);
    }

    // ─── Notices ─────────────────────────────────────────────────────

    /// A mandate with its consented manifest attached, so notices can
    /// be rendered from real class terms rather than invented dates.
    fn mandate_with_manifest(store: &Store, mandate_ref: &str) {
        let manifest = serde_json::json!({
            "componentId": "onym:component:authority",
            "operator": "onym:key:operator",
            "violationClasses": [{
                "classId": "csam",
                "responseWindow": "P3D",
                "decisionDeadline": "P7D",
                "banTerm": "permanent",
                "appealWindow": "P30D",
                "appealEffect": "non-suspensive",
            }],
        });
        let raw = serde_json::to_vec(&manifest).unwrap();
        store
            .put_mandate(
                &crate::store::MandateRecord {
                    mandate_ref: mandate_ref.into(),
                    user_key: "onym:key:accused".into(),
                    authority: "onym:component:authority".into(),
                    device_binding: DEVICE.into(),
                    manifest_hash: util::sha256_hex(&raw),
                    classes: vec!["csam".into()],
                },
                b"{}",
                "2026-08-01T00:00:00Z",
            )
            .unwrap();
        store.attach_manifest(mandate_ref, &raw).unwrap();
    }

    fn open_case_at(case_id: &str, decided_at: &str) -> Verdict {
        let mut verdict = verdict(case_id, Disposition::OpenCase, "csam");
        verdict.decided_at = decided_at.into();
        verdict.marks = Marks { case_open: true, banned: false };
        verdict
    }

    /// The authority issues one `open-case` verdict per report joined
    /// to a case, and none supersede each other. Serving all of them
    /// handed the accused three notices for one case, two of which
    /// carried a `responseDeadline` that had already lapsed — while the
    /// authority was working to the newest. Telling someone their time
    /// to answer is gone when it is not is the worst version of the
    /// invented-date failure this function exists to avoid.
    #[test]
    fn a_re_noticed_case_serves_one_notice_the_latest() {
        let engine = engine();
        mandate_with_manifest(&engine.store, MANDATE);

        for (reference, decided_at) in [
            ("notice-1", "2026-08-01T00:00:00Z"),
            ("notice-2", "2026-08-04T00:00:00Z"),
            ("notice-3", "2026-08-07T00:00:00Z"),
        ] {
            store_verdict(&engine.store, reference, open_case_at("case-csam", decided_at), decided_at);
        }

        let notices = engine.open_case_notices(DEVICE).unwrap();

        assert_eq!(notices.len(), 1, "one live case, one notice");
        let notice = &notices[0];
        assert_eq!(notice.case_id, "case-csam");
        // Counted from the newest `decidedAt`: 2026-08-07 + P3D.
        assert_eq!(notice.response_deadline, "2026-08-10T00:00:00Z");
        assert_eq!(notice.decision_deadline, "2026-08-14T00:00:00Z");
    }

    /// Deduping per case must not collapse *different* cases.
    #[test]
    fn separate_cases_each_keep_their_notice() {
        let engine = engine();
        mandate_with_manifest(&engine.store, MANDATE);

        store_verdict(
            &engine.store,
            "notice-a",
            open_case_at("case-a", "2026-08-01T00:00:00Z"),
            "2026-08-01T00:00:00Z",
        );
        store_verdict(
            &engine.store,
            "notice-b",
            open_case_at("case-b", "2026-08-02T00:00:00Z"),
            "2026-08-02T00:00:00Z",
        );

        let mut served: Vec<String> =
            engine.open_case_notices(DEVICE).unwrap().into_iter().map(|n| n.case_id).collect();
        served.sort();
        assert_eq!(served, vec!["case-a".to_string(), "case-b".to_string()]);
    }

    /// The case is claimed before the render checks, so a case whose
    /// *newest* notice cannot be rendered serves nothing rather than
    /// falling back to an older one. The fallback would satisfy the
    /// omission rule's letter while doing exactly what it forbids:
    /// showing a lapsed deadline as though it were live.
    #[test]
    fn a_case_whose_latest_notice_cannot_be_rendered_serves_nothing() {
        let engine = engine();
        // The older notice's mandate has a manifest; the newer one's
        // does not — the authority has not yet delivered a verdict
        // carrying those bytes.
        mandate_with_manifest(&engine.store, MANDATE);

        store_verdict(
            &engine.store,
            "notice-old",
            open_case_at("case-csam", "2026-08-01T00:00:00Z"),
            "2026-08-01T00:00:00Z",
        );
        let mut newer = open_case_at("case-csam", "2026-08-07T00:00:00Z");
        newer.mandate_ref = "mandate-unknown".into();
        let raw = serde_json::to_vec(&newer).unwrap();
        engine
            .store
            .put_verdict(
                &StoredVerdict {
                    verdict_ref: "notice-new".into(),
                    case_id: "case-csam".into(),
                    decided_at: newer.decided_at.clone(),
                    mandate_ref: "mandate-unknown".into(),
                    device_binding: DEVICE.into(),
                    raw,
                    disposition: "open-case".into(),
                    ban_expires: None,
                    execute_after: None,
                    executed: true,
                    superseded: false,
                },
                "2026-08-07T00:00:00Z",
            )
            .unwrap();

        let notices = engine.open_case_notices(DEVICE).unwrap();
        assert!(
            notices.is_empty(),
            "a stale notice is not a safe substitute for the one in force: {notices:?}"
        );
    }

    /// A superseded notice is not served even when it is the newest
    /// row for its case — the pre-existing filter still applies ahead
    /// of the dedupe.
    #[test]
    fn a_superseded_notice_does_not_claim_its_case() {
        let engine = engine();
        mandate_with_manifest(&engine.store, MANDATE);

        store_verdict(
            &engine.store,
            "notice-live",
            open_case_at("case-csam", "2026-08-01T00:00:00Z"),
            "2026-08-01T00:00:00Z",
        );
        let newer = open_case_at("case-csam", "2026-08-07T00:00:00Z");
        let raw = serde_json::to_vec(&newer).unwrap();
        engine
            .store
            .put_verdict(
                &StoredVerdict {
                    verdict_ref: "notice-superseded".into(),
                    case_id: "case-csam".into(),
                    decided_at: newer.decided_at.clone(),
                    mandate_ref: MANDATE.into(),
                    device_binding: DEVICE.into(),
                    raw,
                    disposition: "open-case".into(),
                    ban_expires: None,
                    execute_after: None,
                    executed: true,
                    superseded: true,
                },
                "2026-08-07T00:00:00Z",
            )
            .unwrap();

        let notices = engine.open_case_notices(DEVICE).unwrap();
        assert_eq!(notices.len(), 1);
        // The live one, counted from its own decidedAt.
        assert_eq!(notices[0].response_deadline, "2026-08-04T00:00:00Z");
    }

    /// End-to-end reconciliation against a local stand-in for Google's
    /// Play Integrity API: decode, classify, fold, diff-write.
    mod reconciliation {
        use super::*;
        use std::sync::{Arc, Mutex};

        use crate::google_auth::{self, GoogleAuth};
        use crate::play_integrity::PlayIntegrity;

        const PACKAGE: &str = "app.onym.android";
        const REQUEST_HASH: &str = "expected-hash";
        const USER: &str = "onym:key:aabb";

        struct FakePlay {
            /// The tokenPayloadExternal served to every decode.
            payload: serde_json::Value,
            /// Raw bodies of every deviceRecall:write received.
            writes: Vec<serde_json::Value>,
            fail_writes: bool,
        }

        async fn spawn_fake_play(payload: serde_json::Value) -> (String, Arc<Mutex<FakePlay>>) {
            let shared = Arc::new(Mutex::new(FakePlay {
                payload,
                writes: Vec::new(),
                fail_writes: false,
            }));
            let state = Arc::clone(&shared);
            // The real paths contain a colon (`{package}:decodeIntegrityToken`),
            // which axum's router can't pattern-match — dispatch on the
            // raw path instead.
            let app = axum::Router::new()
                .route(
                    "/token",
                    axum::routing::post(|| async {
                        axum::Json(serde_json::json!({
                            "access_token": "ya29.test", "expires_in": 3600,
                        }))
                    }),
                )
                .fallback(move |request: axum::extract::Request| {
                    let state = Arc::clone(&state);
                    async move {
                        let path = request.uri().path().to_string();
                        let body = axum::body::to_bytes(request.into_body(), 1 << 20)
                            .await
                            .unwrap_or_default();
                        if path.ends_with(":decodeIntegrityToken") {
                            let payload = state.lock().unwrap().payload.clone();
                            return axum::Json(
                                serde_json::json!({"tokenPayloadExternal": payload}),
                            )
                            .into_response();
                        }
                        if path.ends_with("/deviceRecall:write") {
                            let mut fake = state.lock().unwrap();
                            let parsed: serde_json::Value =
                                serde_json::from_slice(&body).unwrap_or_default();
                            fake.writes.push(parsed);
                            if fake.fail_writes {
                                return (
                                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                                    "quota",
                                )
                                    .into_response();
                            }
                            return axum::Json(serde_json::json!({})).into_response();
                        }
                        (axum::http::StatusCode::NOT_FOUND, "no such fixture route")
                            .into_response()
                    }
                });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (base, shared)
        }

        use axum::response::IntoResponse;

        /// A token payload that passes every classifier prerequisite,
        /// fresh relative to `now()`, carrying the given values map.
        fn conforming_payload(values: serde_json::Value) -> serde_json::Value {
            let now_millis = now().unix_timestamp() * 1000;
            serde_json::json!({
                "requestDetails": {
                    "requestPackageName": PACKAGE,
                    "requestHash": REQUEST_HASH,
                    "timestampMillis": (now_millis - 5_000).to_string(),
                },
                "appIntegrity": {
                    "appRecognitionVerdict": "PLAY_RECOGNIZED",
                    "packageName": PACKAGE,
                    "certificateSha256Digest": ["expected-digest"],
                },
                "deviceIntegrity": {
                    "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    "deviceRecall": {"values": values, "writeDates": {}},
                },
                "accountDetails": {"appLicensingVerdict": "LICENSED"},
            })
        }

        async fn engine_with_play(
            payload: serde_json::Value,
        ) -> (Engine, Arc<Mutex<FakePlay>>) {
            let (base, shared) = spawn_fake_play(payload).await;
            let auth =
                GoogleAuth::new(google_auth::tests::test_key(format!("{base}/token"))).unwrap();
            let client =
                PlayIntegrity::with_base_url(auth, PACKAGE.to_string(), base).unwrap();
            let engine = Engine {
                store: Store::in_memory().unwrap(),
                play: Some(PlayEnforcement {
                    client,
                    package_name: PACKAGE.to_string(),
                    cert_sha256_digests: vec!["expected-digest".to_string()],
                    token_max_age_secs: 600,
                }),
                propagation_grace_secs: 60,
            };
            (engine, shared)
        }

        /// Enroll the fixture identity and bind a verdict to it.
        fn enroll_and_store(
            engine: &Engine,
            verdict_ref: &str,
            mut v: Verdict,
            executed: bool,
        ) -> String {
            let binding = engine
                .store
                .enrollment_for(USER, "2026-08-08T00:00:00Z")
                .unwrap()
                .device_binding;
            v.device_binding = binding.clone();
            let raw = serde_json::to_vec(&v).unwrap();
            let disposition = match v.disposition {
                Disposition::OpenCase => "open-case",
                Disposition::Dismiss => "dismiss",
                Disposition::Ban => "ban",
            };
            engine
                .store
                .put_verdict(
                    &StoredVerdict {
                        verdict_ref: verdict_ref.into(),
                        case_id: v.case_id.clone(),
                        decided_at: v.decided_at.clone(),
                        mandate_ref: MANDATE.into(),
                        device_binding: binding.clone(),
                        raw,
                        disposition: disposition.into(),
                        ban_expires: v.ban_expires,
                        execute_after: v.execute_after,
                        executed,
                        superseded: false,
                    },
                    "2026-08-08T00:30:00Z",
                )
                .unwrap();
            binding
        }

        #[tokio::test]
        async fn a_queued_ban_executes_and_writes_only_the_changed_value() {
            let (engine, fake) = engine_with_play(conforming_payload(serde_json::json!({}))).await;
            enroll_and_store(&engine, "ban-1", verdict("case-1", Disposition::Ban, "csam"), false);

            let result = engine
                .gate_check(Some("token"), REQUEST_HASH, USER, now())
                .await
                .unwrap();
            assert!(matches!(result, GateCheckResult::Banned { .. }), "{result:?}");

            let writes = fake.lock().unwrap().writes.clone();
            assert_eq!(writes.len(), 1);
            let body = serde_json::to_string(&writes[0]).unwrap();
            assert!(!body.contains("bitThird"), "{body}");
            assert!(
                !body.contains("bitFirst"),
                "case-open did not change and must be omitted: {body}"
            );
            assert_eq!(writes[0]["newValues"]["bitSecond"], true);

            // The verdict is executed only after Google accepted.
            let stored = engine.store.verdicts_for_device(
                &engine.store.device_binding_for_user(USER).unwrap().unwrap(),
            ).unwrap();
            assert!(stored[0].executed);

            // And the write is on the audited log, naming its fields.
            let log = engine.store.write_log(10).unwrap();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0].authorized_by, "ban-1");
            assert_eq!(log[0].fields_written, r#"{"bitSecond":true}"#);
        }

        /// A read lagging an accepted write inside the propagation
        /// window is Google's documented cache, not divergence: served
        /// from intended state, without a second write. Past the
        /// window, the rewrite happens.
        #[tokio::test]
        async fn a_lagging_read_is_not_rewritten_inside_the_propagation_window() {
            let (engine, fake) = engine_with_play(conforming_payload(serde_json::json!({}))).await;
            enroll_and_store(&engine, "ban-1", verdict("case-1", Disposition::Ban, "csam"), false);

            let first = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(matches!(first, GateCheckResult::Banned { .. }));
            assert_eq!(fake.lock().unwrap().writes.len(), 1);

            // Same stale read a moment later: still banned, no rewrite.
            let second = engine
                .gate_check(Some("token"), REQUEST_HASH, USER, now() + time::Duration::seconds(30))
                .await
                .unwrap();
            assert!(matches!(second, GateCheckResult::Banned { .. }));
            assert_eq!(fake.lock().unwrap().writes.len(), 1, "no rewrite inside the window");

            // Still stale after the grace: the ban is executed, so a
            // clean read now falls to the foreign-hardware guard — the
            // identity stays refused and the device is never re-marked
            // (Google accepted the original write; only the read lags,
            // and re-branding on an unlinkable token could mark someone
            // else's device). The fixture clock must stay inside the
            // token freshness window, so re-serve a fresh payload.
            let later = now() + time::Duration::seconds(200);
            fake.lock().unwrap().payload = serde_json::json!({
                "requestDetails": {
                    "requestPackageName": PACKAGE,
                    "requestHash": REQUEST_HASH,
                    "timestampMillis": ((later.unix_timestamp() * 1000) - 5_000).to_string(),
                },
                "appIntegrity": {
                    "appRecognitionVerdict": "PLAY_RECOGNIZED",
                    "packageName": PACKAGE,
                    "certificateSha256Digest": ["expected-digest"],
                },
                "deviceIntegrity": {
                    "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    "deviceRecall": {"values": {}, "writeDates": {}},
                },
                "accountDetails": {"appLicensingVerdict": "LICENSED"},
            });
            let third = engine.gate_check(Some("token"), REQUEST_HASH, USER, later).await.unwrap();
            assert!(matches!(third, GateCheckResult::Banned { .. }));
            assert_eq!(
                fake.lock().unwrap().writes.len(),
                1,
                "an executed ban meeting clean values is never re-branded"
            );
        }

        #[tokio::test]
        async fn an_expired_ban_clears_with_a_single_false_write() {
            let (engine, fake) =
                engine_with_play(conforming_payload(serde_json::json!({"bitSecond": true}))).await;
            let mut expired = verdict("case-1", Disposition::Ban, "csam");
            expired.ban_expires = Some("2026-08-08T12:00:00Z".into()); // before now()
            enroll_and_store(&engine, "ban-1", expired, true);

            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(matches!(result, GateCheckResult::Clear), "{result:?}");

            let writes = fake.lock().unwrap().writes.clone();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0]["newValues"]["bitSecond"], false);
            assert!(!serde_json::to_string(&writes[0]).unwrap().contains("bitFirst"));
            let log = engine.store.write_log(10).unwrap();
            assert_eq!(log[0].authorized_by, "expiry");
        }

        /// Marked values behind a failed prerequisite are never read,
        /// and nothing is ever written on an untrusted token.
        #[tokio::test]
        async fn a_classifier_failure_answers_check_required_and_never_writes() {
            let mut payload = conforming_payload(serde_json::json!({"bitSecond": true}));
            payload["accountDetails"]["appLicensingVerdict"] = "UNLICENSED".into();
            let (engine, fake) = engine_with_play(payload).await;
            enroll_and_store(&engine, "ban-1", verdict("case-1", Disposition::Ban, "csam"), false);

            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(
                matches!(
                    result,
                    GateCheckResult::CheckRequired { reason: CheckRequiredReason::TokenInvalid }
                ),
                "{result:?}"
            );
            assert!(fake.lock().unwrap().writes.is_empty());
        }

        /// A valid ban whose executeAfter is still ahead is stored, not
        /// executed — the suspensive appeal window (profile §6.1).
        #[tokio::test]
        async fn a_ban_before_execute_after_is_stored_not_written() {
            let (engine, fake) = engine_with_play(conforming_payload(serde_json::json!({}))).await;
            let mut queued = verdict("case-1", Disposition::Ban, "csam");
            queued.execute_after = Some("2026-09-01T00:00:00Z".into()); // after now()
            enroll_and_store(&engine, "ban-1", queued, false);

            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(matches!(result, GateCheckResult::Clear), "{result:?}");
            assert!(fake.lock().unwrap().writes.is_empty());
        }

        /// A ban already branded onto a device, meeting clean values, is
        /// different hardware presenting the same identity: refuse the
        /// identity, never mark this device.
        #[tokio::test]
        async fn a_banned_identity_on_a_clean_device_is_refused_without_branding() {
            let (engine, fake) = engine_with_play(conforming_payload(serde_json::json!({}))).await;
            enroll_and_store(&engine, "ban-1", verdict("case-1", Disposition::Ban, "csam"), true);

            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(matches!(result, GateCheckResult::Banned { .. }), "{result:?}");
            assert!(fake.lock().unwrap().writes.is_empty(), "no write onto foreign hardware");
        }

        /// A refused write (quota, outage) is mark_write_failed: the
        /// verdict stays unexecuted for the next session, and the
        /// refused attempt is still on the audit log.
        #[tokio::test]
        async fn a_refused_write_stays_queued_and_is_logged() {
            let (engine, fake) = engine_with_play(conforming_payload(serde_json::json!({}))).await;
            fake.lock().unwrap().fail_writes = true;
            let binding = enroll_and_store(
                &engine,
                "ban-1",
                verdict("case-1", Disposition::Ban, "csam"),
                false,
            );

            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await;
            assert!(matches!(result, Err(Error::MarkWriteFailed(_))), "{result:?}");

            let stored = engine.store.verdicts_for_device(&binding).unwrap();
            assert!(!stored[0].executed, "an unaccepted write must not execute the verdict");
            let log = engine.store.write_log(10).unwrap();
            assert_eq!(log.len(), 1);
            assert!(log[0].outcome.starts_with("failed"), "{}", log[0].outcome);
        }

        /// Without Play credentials the gate can clear no one.
        #[tokio::test]
        async fn no_play_configuration_answers_attestation_unavailable() {
            let engine = engine();
            let result = engine.gate_check(Some("token"), REQUEST_HASH, USER, now()).await.unwrap();
            assert!(matches!(
                result,
                GateCheckResult::CheckRequired {
                    reason: CheckRequiredReason::AttestationUnavailable
                }
            ));
        }
    }

}
