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

use crate::canonical;
use crate::devicecheck::{Bits, DeviceCheck};
use crate::error::Error;
use crate::store::{Store, StoredVerdict};
use crate::types::{
    BanState, CheckRequiredReason, GateCheckResult, RecoveryGrant, RecoveryResult, UnbanGrant,
    Verdict,
};
use crate::util;

/// How long an issued recovery grant stays presentable. Grants are
/// identity-bound and single-use, so this bounds shelf life, not
/// theft; a lapsed grant just means asking the authority again.
const GRANT_MAX_AGE: time::Duration = time::Duration::days(30);
const GRANT_MAX_CLOCK_SKEW: time::Duration = time::Duration::minutes(5);

/// The domain tag every recovery grant carries inside its signed
/// bytes. Must stay byte-identical to the authority's
/// `recovery::GRANT_DOMAIN`; the pair is what keeps a grant and a
/// verdict — signed by the same key over the same canonical form —
/// from ever being presented as one another.
const RECOVERY_GRANT_DOMAIN: &str = "onym-recovery-grant-v1";
const UNBAN_GRANT_DOMAIN: &str = "onym-unban-grant-v1";

pub struct Engine {
    pub store: Store,
    pub device_check: Option<DeviceCheck>,
}

/// What a binding still carries that recovery must not move or clear:
/// whether any case is open, and whether any ban is unresolved (active
/// or still queued behind its `executeAfter`). `ban_route` is the
/// governing ban's verdict when one parses, for the refusal's contact
/// and appeal links.
struct BindingState {
    open: bool,
    ban_present: bool,
    ban_route: Option<(String, Verdict)>,
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
        self.reconcile(device_check, device_token, user_key, bits, now).await
    }

    /// Session-mediated reconciliation: with a live token in hand,
    /// bring Apple's bits in line with what the verdict record now
    /// implies, before answering. Split from `gate_check` so recovery,
    /// which has already paid for the bits, can reconcile on the same
    /// read instead of asking Apple twice and racing itself.
    async fn reconcile(
        &self,
        device_check: &DeviceCheck,
        device_token: &str,
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

    /// Redeem a moderator-issued recovery grant: the authority has
    /// decided — after hearing the holder's claim, contact, and proof
    /// of new-holder status — that one case's verdict record should
    /// follow its device onto the enrollment of the identity the grant
    /// names. There is no self-serve path here: nothing a holder knows
    /// or presents moves a record without that human decision.
    ///
    /// Recovery still moves no mark by itself. It re-binds the stored,
    /// signed verdicts and then reconciles, so the write that clears
    /// the bits is authorized by the reversal (or expiry) already on
    /// file — rule 2 above holds. When the record still bans the
    /// device — the case's own record, or the claimant's — nothing
    /// moves, the grant is not consumed, and the holder is routed back
    /// to the authority.
    ///
    /// The grant verifies against the operator key resolved through
    /// the consented manifest the case's mandate pinned — the same key
    /// the case's verdicts verify against, so redemption introduces no
    /// trust root the user did not already consent to. It is bound to
    /// the grantee identity (a stolen grant is useless without the
    /// key), presented only from a device whose banned bit Apple
    /// confirms in the same signed session, and single-use.
    pub async fn recover(
        &self,
        device_token: Option<&str>,
        user_key: &str,
        grant_raw: &[u8],
        now: OffsetDateTime,
    ) -> Result<RecoveryResult, Error> {
        let Some(device_check) = self.device_check.as_ref() else {
            return Err(Error::BadRequest(
                "attestation is unavailable; recovery cannot verify the device".into(),
            ));
        };
        let Some(device_token) = device_token else {
            return Err(Error::BadRequest("recovery requires a device token".into()));
        };
        let Some(bits) = device_check.query(device_token).await? else {
            return Err(Error::BadRequest("Apple did not validate this device token".into()));
        };
        if !bits.banned {
            return Err(Error::BadRequest(
                "this device carries no banned mark; there is nothing to recover".into(),
            ));
        }

        let grant_value = serde_json::from_slice::<serde_json::Value>(grant_raw)
            .map_err(|e| Error::BadRequest(format!("malformed recovery grant: {e}")))?
            ;
        let grant_type = grant_value
            .get("grantType")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if grant_type == UNBAN_GRANT_DOMAIN {
            let grant: UnbanGrant = serde_json::from_slice(grant_raw)
                .map_err(|e| Error::BadRequest(format!("malformed unban grant: {e}")))?;
            return self
                .recover_unban_grant(device_check, device_token, user_key, grant_raw, grant, now)
                .await;
        }
        let grant: RecoveryGrant = serde_json::from_slice(grant_raw)
            .map_err(|e| Error::BadRequest(format!("malformed recovery grant: {e}")))?;
        if grant.grant_type != RECOVERY_GRANT_DOMAIN {
            // A document that is not a recovery grant — a verdict signed
            // by the same operator key, say — must not be redeemed as
            // one, whatever else it happens to contain.
            return Err(Error::BadRequest(format!(
                "not a recovery grant (grantType {:?})",
                grant.grant_type
            )));
        }
        if grant.grant_version != 1 {
            // A grant minted under semantics this build does not
            // implement must not redeem under the ones it does.
            return Err(Error::BadRequest(format!(
                "unsupported grantVersion {} (this interface implements 1)",
                grant.grant_version
            )));
        }
        if grant.grantee != user_key {
            return Err(Error::SignatureInvalid(
                "the grant was not issued to this identity".into(),
            ));
        }
        let issued_at = util::parse_timestamp(&grant.issued_at)
            .map_err(|e| Error::BadRequest(format!("grant issuedAt: {e}")))?;
        if issued_at - now > GRANT_MAX_CLOCK_SKEW {
            return Err(Error::BadRequest("grant issuedAt is in the future".into()));
        }
        if now - issued_at > GRANT_MAX_AGE {
            return Err(Error::BadRequest(
                "grant has lapsed; ask the authority to issue a fresh one".into(),
            ));
        }

        let signing_bytes = canonical::grant_signing_bytes(grant_raw)?;
        let grant_ref = util::sha256_hex(&signing_bytes);

        // Everything from here to a verified signature answers with
        // ONE refusal. Verification needs the case (the operator key
        // comes from the case's consented manifest, so the order can't
        // flip), and distinguishable answers on the way — "no such
        // case" vs "bad signature" — would let a garbage-signed grant
        // probe which cases this interface holds records for.
        let Some(from_binding) = self.store.binding_for_case(&grant.case_id)? else {
            return Err(Self::grant_refused());
        };

        // The verifying key comes from the consented manifest pinned by
        // the case's own mandate — taking it from the grant would make
        // verification circular, exactly as it would for a verdict.
        self.verify_grant_signature(&grant, &from_binding, &signing_bytes)?;

        // Redemption state is checked only *after* the signature
        // verifies, so "already redeemed" cannot be probed by anyone
        // holding grant bytes without a valid operator signature — it
        // would otherwise be a distinguishable answer where every other
        // pre-verification refusal is the uniform one.
        if self.store.grant_redeemed(&grant_ref)? {
            return Err(Error::BadRequest("this grant has already been redeemed".into()));
        }

        let Some(to_binding) = self.store.device_binding_for_user(user_key)? else {
            return Err(Error::BadRequest(
                "this identity is not enrolled; enroll before presenting a grant".into(),
            ));
        };

        // The grant's *named case* must itself be terminal — dismissed,
        // reversed, or expired. The move touches only that case, so an
        // unrelated case on the source binding (the previous holder's,
        // which the claimant can neither see nor resolve) must not block
        // recovery: the check is scoped to `grant.case_id`. A case still
        // open, or a ban not yet reversed or expired — queued bans
        // included, which the folded `bits` would miss — refuses.
        //
        // The destination is checked binding-wide: the clearing write
        // folds the grantee's whole binding, so a live or queued ban of
        // *their own* means recovery would clear a device their own
        // record still bans. Their open cases are theirs to see, so
        // those do not block.
        //
        // Read outside the `adopt_binding` transaction, but the window
        // is benign: the case is terminal and the authority issues no
        // new governing verdict on a reversed case, so nothing that
        // would flip this arrives in the gap; unrelated cases are not
        // consulted and are not moved.
        let source = self.binding_state(&from_binding, Some(&grant.case_id), now)?;
        let dest = self.binding_state(&to_binding, None, now)?;
        // A ban in force — the grant's case or the grantee's own —
        // answers with that ban's routes. An *open* case is a different
        // refusal: nothing is banned, the matter is simply undecided,
        // and a ban's appeal/new-holder routes would be the wrong
        // answer — so it gets its own shape rather than a mislabelled
        // `markInForce` with empty URLs.
        if let Some((verdict_ref, verdict)) = source.ban_route.as_ref().or(dest.ban_route.as_ref()) {
            let state = self.ban_state(verdict_ref, verdict);
            return Ok(RecoveryResult::MarkInForce {
                authority_contact: state.authority_contact,
                new_holder_url: state.new_holder_url,
                appeal_url: state.appeal_url,
            });
        }
        if source.ban_present || dest.ban_present {
            // A ban with no parseable verdict for routes still refuses.
            return Ok(RecoveryResult::MarkInForce {
                authority_contact: "the authority named in the case notice".into(),
                new_holder_url: None,
                appeal_url: None,
            });
        }
        if source.open {
            return Ok(RecoveryResult::CaseUnsettled {
                note: "this case is still open at the authority; it must be decided before the \
                       device can be recovered"
                    .into(),
            });
        }

        // Re-bind the named case's cleared verdicts to the new holder
        // and redeem the grant, in one transaction. This does NOT write
        // a device bit: the clearing write below is still carried by
        // the reversal verdict already on file (marks move only on
        // verdicts, §11.2) — the grant authorizes the re-bind, not the
        // bit. Redemption is recorded even when nothing moves
        // (`from == to`): single-use is unconditional. A grant redeemed
        // concurrently loses the `ON CONFLICT` race and answers the
        // same refusal, rather than a 500 on the primary-key clash.
        //
        // The single-use record and the moderator's authorization of it
        // (the authority's `recovery_grant_issued` case event) are the
        // audit trail; the move is not a write-log row, because that
        // log's columns mean "bits written" and this writes none.
        if !self.store.adopt_binding(
            &grant_ref,
            &grant.case_id,
            &from_binding,
            &to_binding,
            &util::format_timestamp(now),
        )? {
            return Err(Error::BadRequest("this grant has already been redeemed".into()));
        }

        // Ordinary reconciliation now resolves the moved record and
        // performs the clearing write on the reversal's own authority,
        // against the bits already read in this session. The grant is
        // already spent and the record already moved, so *any* failure
        // here is not a lost grant: the next ordinary gate check on the
        // new enrollment finishes the clear. Say exactly that for every
        // post-move error, rather than let it read as "redeem again".
        match self.reconcile(device_check, device_token, user_key, bits, now).await {
            Ok(gate) => Ok(RecoveryResult::Recovered { gate }),
            Err(err) => {
                tracing::warn!(
                    %grant_ref,
                    "recovery moved the record but finishing it failed: {err}"
                );
                Err(Error::MarkWriteFailed(
                    "recovery is recorded and the grant is spent; this device will clear on \
                     its next verification — do not present the grant again"
                        .into(),
                ))
            }
        }
    }

    async fn recover_unban_grant(
        &self,
        device_check: &DeviceCheck,
        device_token: &str,
        user_key: &str,
        grant_raw: &[u8],
        grant: UnbanGrant,
        now: OffsetDateTime,
    ) -> Result<RecoveryResult, Error> {
        if grant.grant_version != 1 {
            return Err(Error::BadRequest(format!(
                "unsupported grantVersion {} (this interface implements 1)",
                grant.grant_version
            )));
        }
        if grant.grantee != user_key {
            return Err(Error::SignatureInvalid(
                "the grant was not issued to this identity".into(),
            ));
        }
        let issued_at = util::parse_timestamp(&grant.issued_at)
            .map_err(|e| Error::BadRequest(format!("grant issuedAt: {e}")))?;
        if issued_at - now > GRANT_MAX_CLOCK_SKEW {
            return Err(Error::BadRequest("grant issuedAt is in the future".into()));
        }
        if now - issued_at > GRANT_MAX_AGE {
            return Err(Error::BadRequest(
                "grant has lapsed; ask the authority to issue a fresh one".into(),
            ));
        }

        let signing_bytes = canonical::grant_signing_bytes(grant_raw)?;
        let grant_ref = util::sha256_hex(&signing_bytes);
        self.verify_unban_grant_signature(&grant, &signing_bytes)?;
        if self.store.unban_redeemed(&grant_ref)? {
            return Err(Error::BadRequest("this grant has already been redeemed".into()));
        }

        let Some(to_binding) = self.store.device_binding_for_user(user_key)? else {
            return Err(Error::BadRequest(
                "this identity is not enrolled; enroll before presenting a grant".into(),
            ));
        };
        let dest = self.binding_state(&to_binding, None, now)?;
        if let Some((verdict_ref, verdict)) = dest.ban_route.as_ref() {
            let state = self.ban_state(verdict_ref, verdict);
            return Ok(RecoveryResult::MarkInForce {
                authority_contact: state.authority_contact,
                new_holder_url: state.new_holder_url,
                appeal_url: state.appeal_url,
            });
        }
        if dest.ban_present {
            return Ok(RecoveryResult::MarkInForce {
                authority_contact: "the authority named in the case notice".into(),
                new_holder_url: None,
                appeal_url: None,
            });
        }
        if dest.open {
            return Ok(RecoveryResult::CaseUnsettled {
                note: "this identity has an open moderation case; it must be decided before the device can be unbanned".into(),
            });
        }

        if !self.store.record_unban_redemption(
            &grant_ref,
            &to_binding,
            &util::format_timestamp(now),
        )? {
            return Err(Error::BadRequest("this grant has already been redeemed".into()));
        }
        self.write_bits(
            device_check,
            device_token,
            &to_binding,
            Bits { case_open: false, banned: false },
            &format!("recovery-unban:{grant_ref}"),
            now,
        )
        .await?;
        self.reconcile(device_check, device_token, user_key, Bits::default(), now)
            .await
            .map(|gate| RecoveryResult::Recovered { gate })
    }

    /// What a binding still carries that recovery must not move or
    /// clear, derived from the *governing* verdict per case — the
    /// newest under the store's total order, exactly as the fold
    /// resolves it. Unlike the folded `bits`, a ban still queued
    /// behind its `executeAfter` counts as a ban here: a suspensive
    /// appeal window is unresolved, and recovery must refuse it rather
    /// than move it and let it execute onto the recovered device.
    ///
    /// `only_case` restricts the scan to one case. The source check
    /// uses this — the move is scoped to the grant's named case, so an
    /// *unrelated* case on the source binding (the previous holder's,
    /// which the claimant is not party to and cannot resolve) must not
    /// block recovery, nor have its ban's contact disclosed. The
    /// destination check passes `None`: any ban on the grantee's own
    /// binding is relevant, because the clearing write folds that whole
    /// binding.
    fn binding_state(
        &self,
        binding: &str,
        only_case: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<BindingState, Error> {
        // Newest-first, so the first row seen for a case governs it —
        // the same answer `intended_marks` reaches by folding oldest to
        // newest and letting the last write win.
        let verdicts = self.store.verdicts_for_device(binding)?;
        let mut seen = std::collections::HashSet::new();
        let mut open = false;
        let mut ban_present = false;
        let mut ban_route: Option<(String, Verdict)> = None;
        for stored in &verdicts {
            if stored.superseded {
                continue;
            }
            if only_case.is_some_and(|case| case != stored.case_id) {
                continue;
            }
            if !seen.insert(stored.case_id.clone()) {
                continue;
            }
            match stored.disposition.as_str() {
                "open-case" => open = true,
                "ban" if !Self::ban_expired(stored, now) => {
                    // Active or still queued: unresolved either way.
                    ban_present = true;
                    // Keep the first (newest) parseable ban for the
                    // refusal's routes; an unparseable one still counts
                    // as present, it just carries no routes.
                    if ban_route.is_none() {
                        if let Ok(verdict) = serde_json::from_slice::<Verdict>(&stored.raw) {
                            ban_route = Some((stored.verdict_ref.clone(), verdict));
                        }
                    }
                }
                // dismiss / reverse / an expired ban: terminal, cleared.
                _ => {}
            }
        }
        Ok(BindingState { open, ban_present, ban_route })
    }

    /// The one refusal for everything between "the grant parsed" and
    /// "the operator signature verified": unknown case, no consented
    /// manifest, authority mismatch, malformed or wrong signature.
    /// One shape, one status — a distinguishable step would be an
    /// existence probe for case records.
    fn grant_refused() -> Error {
        Error::SignatureInvalid(
            "the grant did not verify against any record this interface holds".into(),
        )
    }

    /// Verify a grant against the operator key of the authority the
    /// case's consented manifest names. The manifest travels with the
    /// first delivered verdict and is pinned by the mandate's hash, so
    /// this is the key the user consented to — not one the grant, the
    /// claimant, or even this interface's configuration could swap.
    ///
    /// Every refusal on this path is `grant_refused()` — see there.
    fn verify_grant_signature(
        &self,
        grant: &RecoveryGrant,
        case_binding: &str,
        signing_bytes: &[u8],
    ) -> Result<(), Error> {
        let verdicts = self.store.verdicts_for_device(case_binding)?;
        let mandate_ref = verdicts
            .iter()
            .find(|v| v.case_id == grant.case_id)
            .map(|v| v.mandate_ref.clone())
            .ok_or_else(Self::grant_refused)?;
        let Some(manifest_raw) = self.store.manifest_for_mandate(&mandate_ref)? else {
            return Err(Self::grant_refused());
        };
        // A stored manifest or operator key that will not parse is a
        // server-data fault, not the caller's — but it is reached only
        // *after* the case resolved, so a distinguishable 500 here
        // would still confirm the case exists where every sibling
        // answers the uniform refusal. Log the detail, answer the same
        // shape.
        let manifest: crate::types::AuthorityManifest = match serde_json::from_slice(&manifest_raw) {
            Ok(manifest) => manifest,
            Err(e) => {
                tracing::error!(mandate_ref = %mandate_ref, "stored manifest unparseable: {e}");
                return Err(Self::grant_refused());
            }
        };
        if manifest.component_id != grant.authority {
            return Err(Self::grant_refused());
        }
        let Some(key_bytes) =
            util::key_bytes_from_reference(&manifest.operator_key).and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            tracing::error!("consented manifest operator key is not a 32-byte reference");
            return Err(Self::grant_refused());
        };
        let key = match ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!("consented manifest operator key is not a valid Ed25519 key: {e}");
                return Err(Self::grant_refused());
            }
        };
        let Some(raw_signature) = util::base64_decode(&grant.signature) else {
            return Err(Self::grant_refused());
        };
        let signature = ed25519_dalek::Signature::from_slice(&raw_signature)
            .map_err(|_| Self::grant_refused())?;
        key.verify_strict(signing_bytes, &signature).map_err(|_| Self::grant_refused())
    }

    fn verify_unban_grant_signature(
        &self,
        grant: &UnbanGrant,
        signing_bytes: &[u8],
    ) -> Result<(), Error> {
        let raw_signature = util::base64_decode(&grant.signature).ok_or_else(Self::grant_refused)?;
        let signature = ed25519_dalek::Signature::from_slice(&raw_signature)
            .map_err(|_| Self::grant_refused())?;
        for manifest_raw in self.store.manifests_for_authority(&grant.authority)? {
            let Ok(manifest) = serde_json::from_slice::<crate::types::AuthorityManifest>(&manifest_raw) else {
                continue;
            };
            if manifest.component_id != grant.authority {
                continue;
            }
            let Some(key_bytes) = util::key_bytes_from_reference(&manifest.operator_key)
                .and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                continue;
            };
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
                continue;
            };
            if key.verify_strict(signing_bytes, &signature).is_ok() {
                return Ok(());
            }
        }
        Err(Self::grant_refused())
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

    /// Recovery-grant redemption, against a local stand-in for Apple's
    /// DeviceCheck API so the whole path runs: query, fold, adoption,
    /// clearing write.
    mod recovery {
        use super::*;
        use std::sync::{Arc, Mutex};

        use axum::extract::State as AxumState;
        use axum::Json;
        use ed25519_dalek::{Signer, SigningKey};

        use crate::store::MandateRecord;
        use crate::types::RecoveryResult;

        const OLD_BINDING: &str = "enrollment:old-device";
        const AUTHORITY: &str = "onym:component:authority";
        const CLAIMANT: &str = "onym:key:claimant";

        struct FakeApple {
            bits: Bits,
            updates: Vec<Bits>,
            queries: usize,
        }

        async fn spawn_fake_apple(initial: Bits) -> (String, Arc<Mutex<FakeApple>>) {
            let shared = Arc::new(Mutex::new(FakeApple {
                bits: initial,
                updates: Vec::new(),
                queries: 0,
            }));

            async fn query(
                AxumState(shared): AxumState<Arc<Mutex<FakeApple>>>,
            ) -> Json<serde_json::Value> {
                let mut shared = shared.lock().unwrap();
                shared.queries += 1;
                let bits = shared.bits;
                Json(serde_json::json!({ "bit0": bits.case_open, "bit1": bits.banned }))
            }
            async fn update(
                AxumState(shared): AxumState<Arc<Mutex<FakeApple>>>,
                Json(body): Json<serde_json::Value>,
            ) -> &'static str {
                let bits = Bits {
                    case_open: body["bit0"].as_bool().unwrap(),
                    banned: body["bit1"].as_bool().unwrap(),
                };
                let mut shared = shared.lock().unwrap();
                shared.bits = bits;
                shared.updates.push(bits);
                ""
            }

            let app = axum::Router::new()
                .route("/v1/query_two_bits", axum::routing::post(query))
                .route("/v1/update_two_bits", axum::routing::post(update))
                .with_state(shared.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (base, shared)
        }

        fn operator() -> SigningKey {
            SigningKey::from_bytes(&[9u8; 32])
        }

        fn operator_reference(key: &SigningKey) -> String {
            format!("onym:key:{}", hex::encode(key.verifying_key().to_bytes()))
        }

        fn manifest_bytes(key: &SigningKey) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "componentId": AUTHORITY,
                "operator": operator_reference(key),
                "violationClasses": [],
            }))
            .unwrap()
        }

        /// A grant as the authority's moderator issues it: signed over
        /// the canonical bytes with the signature field removed.
        fn grant(case_id: &str, grantee: &str, issued_at: &str, key: &SigningKey) -> Vec<u8> {
            let mut value = serde_json::json!({
                "grantType": RECOVERY_GRANT_DOMAIN,
                "grantVersion": 1,
                "caseId": case_id,
                "grantee": grantee,
                "authority": AUTHORITY,
                "issuedAt": issued_at,
                "signature": "",
            });
            let unsigned = serde_json::to_vec(&value).unwrap();
            let signing_bytes = canonical::grant_signing_bytes(&unsigned).unwrap();
            value["signature"] =
                util::base64_encode(&key.sign(&signing_bytes).to_bytes()).into();
            serde_json::to_vec(&value).unwrap()
        }

        /// The reference the interface records for a grant — its
        /// canonical signing bytes' hash.
        fn grant_ref(raw: &[u8]) -> String {
            util::sha256_hex(&canonical::grant_signing_bytes(raw).unwrap())
        }

        async fn engine_with_apple(initial: Bits) -> (Engine, Arc<Mutex<FakeApple>>) {
            let (base, shared) = spawn_fake_apple(initial).await;
            let engine = Engine {
                store: Store::in_memory().unwrap(),
                device_check: Some(DeviceCheck::for_tests(base)),
            };
            (engine, shared)
        }

        /// The consent chain a grant verifies through: a mandate row
        /// for the case's verdicts, with the consented manifest bytes
        /// attached.
        fn seed_consent(engine: &Engine, key: &SigningKey) {
            let manifest = manifest_bytes(key);
            engine
                .store
                .put_mandate(
                    &MandateRecord {
                        mandate_ref: MANDATE.into(),
                        user_key: "onym:key:old-identity".into(),
                        authority: AUTHORITY.into(),
                        device_binding: OLD_BINDING.into(),
                        manifest_hash: util::sha256_hex(&manifest),
                        classes: vec!["csam".into()],
                    },
                    b"{}",
                    "2026-08-01T00:00:00Z",
                )
                .unwrap();
            engine.store.attach_manifest(MANDATE, &manifest).unwrap();
        }

        fn store_verdict_bound(
            engine: &Engine,
            verdict_ref: &str,
            mut verdict: Verdict,
            binding: &str,
            received_at: &str,
        ) {
            verdict.device_binding = binding.into();
            let raw = serde_json::to_vec(&verdict).unwrap();
            let disposition = match verdict.disposition {
                Disposition::OpenCase => "open-case",
                Disposition::Dismiss => "dismiss",
                Disposition::Ban => "ban",
            };
            engine
                .store
                .put_verdict(
                    &StoredVerdict {
                        verdict_ref: verdict_ref.into(),
                        case_id: verdict.case_id.clone(),
                        decided_at: verdict.decided_at.clone(),
                        mandate_ref: MANDATE.into(),
                        device_binding: binding.into(),
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

        /// A case whose ban was reversed: the record clears, only the
        /// device's bits do not know it yet.
        fn seed_reversed_case(engine: &Engine, key: &SigningKey) {
            seed_consent(engine, key);
            store_verdict_bound(
                engine,
                "ban-csam",
                verdict("case-csam", Disposition::Ban, "csam"),
                OLD_BINDING,
                "2026-08-08T00:00:00Z",
            );
            let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
            reversal.decided_at = "2026-08-08T01:00:00Z".into();
            store_verdict_bound(engine, "reverse-csam", reversal, OLD_BINDING, "2026-08-08T01:00:00Z");
        }

        fn enroll_claimant(engine: &Engine) -> String {
            engine
                .store
                .enrollment_for(CLAIMANT, "2026-08-09T00:00:00Z")
                .unwrap()
                .device_binding
        }

        const BANNED: Bits = Bits { case_open: false, banned: true };

        #[tokio::test]
        async fn a_granted_reversed_case_clears_the_device_and_moves_the_record() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            let grant = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result = engine.recover(Some("token"), CLAIMANT, &grant, now()).await.unwrap();

            let RecoveryResult::Recovered { gate } = result else {
                panic!("expected recovery, got {result:?}");
            };
            assert!(matches!(gate, GateCheckResult::Clear {}), "gate: {gate:?}");

            // The clearing write reached Apple, authorized by the record.
            let apple = apple.lock().unwrap();
            assert_eq!(apple.updates.last(), Some(&Bits::default()));
            assert!(!apple.bits.banned);

            // The verdicts followed the device onto the new enrollment;
            // the mandate stays put (moving it would break ingest for
            // the case's next signed verdict — see
            // `a_later_verdict_still_ingests_because_the_mandate_did_not_move`).
            assert_eq!(engine.store.verdicts_for_device(OLD_BINDING).unwrap().len(), 0);
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 2);
            assert_eq!(
                engine.store.mandate(MANDATE).unwrap().unwrap().device_binding,
                OLD_BINDING,
                "the mandate must not move"
            );

            // The write log carries two entries, both on the chain:
            // the record move (no bits, authorized by the grant) and
            // the clearing write (no bits set, authorized by the
            // reversal). Neither sets a bit — the log's bits-only
            // meaning is intact — and the chain still verifies.
            let log = engine.store.write_log(10).unwrap();
            assert!(log.iter().any(|entry| entry.authorized_by == "reverse-csam"
                && !entry.banned
                && !entry.case_open));
            assert!(log.iter().any(|entry| entry.authorized_by.starts_with("recovery-move:")
                && !entry.banned
                && !entry.case_open
                && entry.outcome.contains("no device bits written")));
            assert!(engine.store.verify_write_log().unwrap().is_none(), "chain intact");
        }

        /// The mandate must NOT move — the regression an earlier
        /// over-correction introduced. The authority signs
        /// `deviceBinding` inside every verdict, always the original
        /// binding, and ingest (`verdict::validate`) refuses a verdict
        /// whose signed binding disagrees with its mandate row. Had
        /// recovery rewritten the mandate's binding, the case's next
        /// real verdict would fail that check outright — worse than any
        /// stranding. This drives a real authority verdict through
        /// `validate` after recovery and asserts it still ingests.
        #[tokio::test]
        async fn a_later_verdict_still_ingests_because_the_mandate_did_not_move() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            engine
                .recover(Some("token"), CLAIMANT, &grant_bytes, now())
                .await
                .unwrap();

            // The mandate stays on the original binding.
            let mandate = engine.store.mandate(MANDATE).unwrap().unwrap();
            assert_eq!(mandate.device_binding, OLD_BINDING, "the mandate must not move");

            // A later authority verdict carries the signed binding the
            // authority has always used — the original one. It must
            // pass the mandate-binding check the move used to break.
            let mut late = verdict("case-csam", Disposition::Dismiss, "csam");
            late.device_binding = OLD_BINDING.into();
            late.decided_at = "2026-08-08T02:00:00Z".into();
            let raw = serde_json::to_vec(&late).unwrap();
            let signing_bytes = canonical::verdict_signing_bytes(&raw).unwrap();
            let outcome = crate::verdict::validate(crate::verdict::ValidationInput {
                verdict: &late,
                signing_bytes: &signing_bytes,
                mandate_authority: AUTHORITY,
                // The verdict fixture names this accused key.
                mandate_user: "onym:key:accused",
                mandate_device_binding: &mandate.device_binding,
                mandate_classes: &["csam".to_string()],
                authority_operator_key: &operator_reference(&key),
                violation_class: None,
                now: now(),
                // Soft mode: this test is about the binding check, not
                // the signature; a real signature is exercised
                // elsewhere.
                enforce_signature: false,
            });
            assert!(
                outcome.is_ok(),
                "a later verdict for the recovered case must still ingest: {outcome:?}"
            );

            // …and it must take EFFECT, not just validate: ingest routes
            // a verdict for a recovered case to the recovered binding
            // (`binding_for_ingest`), so it folds into the device the
            // record now governs rather than the abandoned one.
            let to_binding =
                engine.store.device_binding_for_user(CLAIMANT).unwrap().unwrap();
            assert_eq!(
                engine.store.binding_for_ingest("case-csam").unwrap().as_deref(),
                Some(to_binding.as_str()),
                "a later verdict is routed to the recovered binding"
            );
            // Store it where ingest would, and confirm it folds there.
            store_verdict_bound(&engine, "late-ban", {
                let mut v = verdict("case-csam", Disposition::Ban, "csam");
                v.decided_at = "2026-08-10T00:00:00Z".into();
                v
            }, &to_binding, "2026-08-10T00:00:00Z");
            let intended = engine.intended_marks(&to_binding, now() + time::Duration::days(2)).unwrap().unwrap();
            assert!(intended.bits.banned, "the re-ban reaches the recovered device");
            drop(apple);
        }

        #[tokio::test]
        async fn a_grant_from_the_future_semantics_is_refused() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let mut value: serde_json::Value =
                serde_json::from_slice(&grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key))
                    .unwrap();
            value["grantVersion"] = 2.into();
            let v2 = serde_json::to_vec(&value).unwrap();

            let refused = engine.recover(Some("token"), CLAIMANT, &v2, now()).await;
            assert!(
                matches!(&refused, Err(Error::BadRequest(m)) if m.contains("grantVersion")),
                "{refused:?}"
            );
        }

        /// An unknown case and a wrong signature must be one refusal:
        /// a garbage-signed grant naming a real case must learn
        /// nothing from the answer's shape.
        #[tokio::test]
        async fn unknown_case_and_bad_signature_are_indistinguishable() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let impostor = SigningKey::from_bytes(&[13u8; 32]);
            let unknown = engine
                .recover(
                    Some("token"),
                    CLAIMANT,
                    &grant("case-unknown", CLAIMANT, "2026-08-09T00:00:00Z", &impostor),
                    now(),
                )
                .await;
            let forged = engine
                .recover(
                    Some("token"),
                    CLAIMANT,
                    &grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &impostor),
                    now(),
                )
                .await;
            let (Err(Error::SignatureInvalid(a)), Err(Error::SignatureInvalid(b))) =
                (&unknown, &forged)
            else {
                panic!("{unknown:?} / {forged:?}");
            };
            assert_eq!(a, b, "one shape for both");
        }

        /// A holder whose enrollment already resolves the record (the
        /// old identity survived after all) redeems in place: nothing
        /// moves, but the grant is still spent — single-use has no
        /// 'unless nothing moved' clause.
        #[tokio::test]
        async fn a_grant_is_spent_even_when_nothing_moves() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            // The claimant IS the case's binding: enroll first, then
            // seed the reversed case onto that same binding.
            let binding =
                engine.store.enrollment_for(CLAIMANT, "2026-08-01T00:00:00Z").unwrap().device_binding;
            seed_consent(&engine, &key);
            store_verdict_bound(
                &engine,
                "ban-csam",
                verdict("case-csam", Disposition::Ban, "csam"),
                &binding,
                "2026-08-08T00:00:00Z",
            );
            let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
            reversal.decided_at = "2026-08-08T01:00:00Z".into();
            store_verdict_bound(&engine, "reverse-csam", reversal, &binding, "2026-08-08T01:00:00Z");

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let first = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(first, RecoveryResult::Recovered { .. }));
            assert!(!apple.lock().unwrap().bits.banned);

            apple.lock().unwrap().bits = BANNED;
            let second = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&second, Err(Error::BadRequest(m)) if m.contains("already been redeemed")),
                "{second:?}"
            );
        }

        #[tokio::test]
        async fn a_grant_for_someone_else_is_inert() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant = grant("case-csam", "onym:key:someone-else", "2026-08-09T00:00:00Z", &key);
            let refused = engine.recover(Some("token"), CLAIMANT, &grant, now()).await;
            assert!(matches!(refused, Err(Error::SignatureInvalid(_))), "{refused:?}");
        }

        #[tokio::test]
        async fn a_tampered_grant_fails_the_operator_signature() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            // Signed for another case, then edited to name this one.
            let issued = grant("case-other", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let mut value: serde_json::Value = serde_json::from_slice(&issued).unwrap();
            value["caseId"] = "case-csam".into();
            let tampered = serde_json::to_vec(&value).unwrap();

            let refused = engine.recover(Some("token"), CLAIMANT, &tampered, now()).await;
            assert!(matches!(refused, Err(Error::SignatureInvalid(_))), "{refused:?}");
        }

        #[tokio::test]
        async fn a_grant_signed_by_another_key_fails_against_the_consented_manifest() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let impostor = SigningKey::from_bytes(&[13u8; 32]);
            let grant = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &impostor);
            let refused = engine.recover(Some("token"), CLAIMANT, &grant, now()).await;
            assert!(matches!(refused, Err(Error::SignatureInvalid(_))), "{refused:?}");
        }

        #[tokio::test]
        async fn a_live_ban_moves_nothing_and_keeps_the_grant() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_consent(&engine, &key);
            store_verdict_bound(
                &engine,
                "ban-csam",
                verdict("case-csam", Disposition::Ban, "csam"),
                OLD_BINDING,
                "2026-08-08T00:00:00Z",
            );
            let to_binding = enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::MarkInForce { .. }), "{result:?}");
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 0);
            assert!(apple.lock().unwrap().updates.is_empty());

            // The grant was not consumed: once the authority reverses
            // the ban and the reversal is delivered, the same grant
            // completes the recovery.
            let mut reversal = verdict("case-csam", Disposition::Dismiss, "csam");
            reversal.decided_at = "2026-08-09T01:00:00Z".into();
            store_verdict_bound(&engine, "reverse-csam", reversal, OLD_BINDING, "2026-08-09T01:00:00Z");
            let after = engine
                .recover(Some("token"), CLAIMANT, &grant_bytes, now() + time::Duration::hours(2))
                .await
                .unwrap();
            assert!(matches!(after, RecoveryResult::Recovered { .. }), "{after:?}");
        }

        #[tokio::test]
        async fn a_banned_claimant_cannot_splice_a_cleared_record_onto_their_binding() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);
            // The claimant's own record still bans them.
            store_verdict_bound(
                &engine,
                "ban-own",
                verdict("case-own", Disposition::Ban, "csam"),
                &to_binding,
                "2026-08-08T00:00:00Z",
            );

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::MarkInForce { .. }), "{result:?}");
            // Nothing moved, and the grant survives for after a
            // successful appeal of their own case.
            assert_eq!(engine.store.verdicts_for_device(OLD_BINDING).unwrap().len(), 2);
        }

        /// A ban still queued behind its `executeAfter` — the whole of
        /// a suspensive appeal window — folds as "not banned yet", so
        /// the old guard (which read the folded bit) would have moved
        /// and consumed. It must refuse: once the window passes the
        /// queued ban would execute onto the recovered device.
        #[tokio::test]
        async fn a_queued_ban_on_the_grants_own_case_refuses_and_keeps_the_grant() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_consent(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            // The GRANT'S case is itself a ban decided but not yet
            // executed — a suspensive window. It folds as "not banned
            // yet", but recovery must still refuse, or the queued ban
            // would execute onto the recovered device.
            let mut queued = verdict("case-csam", Disposition::Ban, "csam");
            queued.execute_after = Some("2026-09-01T00:00:00Z".into());
            store_verdict_bound(&engine, "ban-queued", queued, OLD_BINDING, "2026-08-08T00:00:00Z");

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::MarkInForce { .. }), "{result:?}");
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 0);
            assert!(!engine.store.grant_redeemed(&grant_ref(&grant_bytes)).unwrap());
            drop(apple);
        }

        /// The source check is scoped to the grant's own case: an
        /// unrelated case on the source binding — the previous holder's,
        /// which the claimant can neither see nor resolve — must NOT
        /// block recovery of the granted (terminal) case. Since the move
        /// is case-scoped, the unrelated records never travel either.
        #[tokio::test]
        async fn an_unrelated_case_on_the_source_does_not_block() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            // A previous holder's open case AND a queued ban, both
            // unrelated to the granted case-csam.
            store_verdict_bound(
                &engine,
                "open-other",
                verdict("case-open", Disposition::OpenCase, "csam"),
                OLD_BINDING,
                "2026-08-08T12:00:00Z",
            );
            let mut queued = verdict("case-suspensive", Disposition::Ban, "csam");
            queued.execute_after = Some("2026-09-01T00:00:00Z".into());
            store_verdict_bound(&engine, "ban-queued", queued, OLD_BINDING, "2026-08-08T00:00:00Z");

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::Recovered { .. }), "{result:?}");
            // Only the granted case moved; the unrelated cases stayed.
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 2);
            assert_eq!(
                engine.store.binding_for_case("case-open").unwrap().as_deref(),
                Some(OLD_BINDING)
            );
        }

        /// A still-open GRANT case answers `caseUnsettled`, not a
        /// mislabelled ban.
        #[tokio::test]
        async fn an_open_grant_case_answers_case_unsettled() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_consent(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            store_verdict_bound(
                &engine,
                "open-csam",
                verdict("case-csam", Disposition::OpenCase, "csam"),
                OLD_BINDING,
                "2026-08-08T12:00:00Z",
            );

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            // An open case is not a ban: a distinct answer, not a
            // mislabelled `markInForce` with empty routes.
            assert!(matches!(result, RecoveryResult::CaseUnsettled { .. }), "{result:?}");
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 0);
        }

        /// A queued ban on the *claimant's* binding refuses too:
        /// recovery would otherwise clear a device the claimant's own
        /// record still (eventually) bans.
        #[tokio::test]
        async fn a_queued_ban_on_the_destination_refuses() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            let mut queued = verdict("case-own", Disposition::Ban, "csam");
            queued.execute_after = Some("2026-09-01T00:00:00Z".into());
            store_verdict_bound(&engine, "ban-own-queued", queued, &to_binding, "2026-08-08T00:00:00Z");

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result =
                engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::MarkInForce { .. }), "{result:?}");
        }

        #[tokio::test]
        async fn a_grant_redeems_exactly_once() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let first = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(first, RecoveryResult::Recovered { .. }));

            // Bits banned again (say, a later verdict on another case),
            // same grant presented again: refused as redeemed.
            apple.lock().unwrap().bits = BANNED;
            let second = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&second, Err(Error::BadRequest(m)) if m.contains("already been redeemed")),
                "{second:?}"
            );
        }

        #[tokio::test]
        async fn a_lapsed_grant_is_refused() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-07-01T00:00:00Z", &key);
            let refused = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&refused, Err(Error::BadRequest(m)) if m.contains("lapsed")),
                "{refused:?}"
            );
        }

        #[tokio::test]
        async fn a_clean_device_has_nothing_to_recover() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(Bits::default()).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let refused = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&refused, Err(Error::BadRequest(m)) if m.contains("no banned mark")),
                "{refused:?}"
            );
        }

        #[tokio::test]
        async fn a_grant_for_an_unknown_case_is_refused() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-unknown", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let refused = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(matches!(&refused, Err(Error::SignatureInvalid(_))), "{refused:?}");
        }

        /// Recovery pays for the DeviceCheck query once and reconciles
        /// on that read; a second query would be a wasted Apple round
        /// trip and could disagree with the first. The fake counts
        /// queries directly.
        #[tokio::test]
        async fn recovery_reads_apple_once_and_reconciles_on_that_read() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            assert!(matches!(result, RecoveryResult::Recovered { .. }));

            let apple = apple.lock().unwrap();
            assert_eq!(apple.queries, 1, "exactly one DeviceCheck query for the whole recovery");
            assert_eq!(apple.updates.len(), 1, "exactly one clearing write");
        }

        /// A document signed by the operator key that is not a recovery
        /// grant — the domain tag missing or wrong — is refused, so a
        /// verdict (same key, same canonical form) can never redeem as
        /// a grant.
        #[tokio::test]
        async fn a_document_without_the_recovery_domain_tag_is_refused() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            enroll_claimant(&engine);

            // Re-sign the grant with the domain tag altered.
            let mut value: serde_json::Value =
                serde_json::from_slice(&grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key))
                    .unwrap();
            value["grantType"] = "onym-verdict-v1".into();
            let unsigned = {
                let mut v = value.clone();
                v["signature"] = "".into();
                serde_json::to_vec(&v).unwrap()
            };
            let signing_bytes = canonical::grant_signing_bytes(&unsigned).unwrap();
            value["signature"] = util::base64_encode(&key.sign(&signing_bytes).to_bytes()).into();
            let mistyped = serde_json::to_vec(&value).unwrap();

            let refused = engine.recover(Some("token"), CLAIMANT, &mistyped, now()).await;
            assert!(
                matches!(&refused, Err(Error::BadRequest(m)) if m.contains("not a recovery grant")),
                "{refused:?}"
            );
        }

        /// The move carries only the grant's named case; other terminal
        /// cases on the same binding stay where they are.
        #[tokio::test]
        async fn the_move_is_scoped_to_the_named_case() {
            let key = operator();
            let (engine, _apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            // A second, already-terminal case (an expired ban) on the
            // same source binding.
            let mut expired = verdict("case-other", Disposition::Ban, "csam");
            expired.ban_expires = Some("2026-08-01T00:00:00Z".into());
            store_verdict_bound(&engine, "ban-expired", expired, OLD_BINDING, "2026-07-01T00:00:00Z");

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();

            // Only case-csam's two verdicts moved; case-other stayed.
            assert_eq!(
                engine.store.binding_for_case("case-csam").unwrap().as_deref(),
                Some(to_binding.as_str())
            );
            assert_eq!(
                engine.store.binding_for_case("case-other").unwrap().as_deref(),
                Some(OLD_BINDING)
            );
        }

        /// Two fresh sessions redeeming the same grant: the store's
        /// `ON CONFLICT` makes exactly one win. Exercised serially here
        /// via a second call whose bits are banned again.
        #[tokio::test]
        async fn the_conflict_loser_moves_nothing_and_refuses() {
            let key = operator();
            let (engine, apple) = engine_with_apple(BANNED).await;
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await.unwrap();
            let moved = engine.store.verdicts_for_device(&to_binding).unwrap().len();

            // Redeem again (bits banned once more): the redemption row
            // already exists, so adopt_binding's INSERT is a no-op and
            // nothing moves a second time.
            apple.lock().unwrap().bits = BANNED;
            let again = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&again, Err(Error::BadRequest(m)) if m.contains("already been redeemed")),
                "{again:?}"
            );
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), moved);
        }

        /// If Apple refuses the clearing write after the move, the grant
        /// is already spent and the record already moved — the error
        /// says so rather than reading as a lost grant.
        #[tokio::test]
        async fn a_failed_clearing_write_reports_recovery_recorded() {
            let key = operator();
            // A fake that accepts the query but 500s on update.
            let (base, shared) = spawn_flaky_apple(BANNED).await;
            let engine = Engine {
                store: Store::in_memory().unwrap(),
                device_check: Some(DeviceCheck::for_tests(base)),
            };
            seed_reversed_case(&engine, &key);
            let to_binding = enroll_claimant(&engine);

            let grant_bytes = grant("case-csam", CLAIMANT, "2026-08-09T00:00:00Z", &key);
            let result = engine.recover(Some("token"), CLAIMANT, &grant_bytes, now()).await;
            assert!(
                matches!(&result, Err(Error::MarkWriteFailed(m)) if m.contains("recovery is recorded")),
                "{result:?}"
            );
            // The move committed and the grant is spent even though the
            // write failed.
            assert_eq!(engine.store.verdicts_for_device(&to_binding).unwrap().len(), 2);
            assert!(engine.store.grant_redeemed(&grant_ref(&grant_bytes)).unwrap());
            drop(shared);
        }

        /// Apple stand-in whose `update_two_bits` fails, to drive the
        /// post-move clearing-write failure path.
        async fn spawn_flaky_apple(initial: Bits) -> (String, Arc<Mutex<FakeApple>>) {
            let shared = Arc::new(Mutex::new(FakeApple {
                bits: initial,
                updates: Vec::new(),
                queries: 0,
            }));
            async fn query(
                AxumState(shared): AxumState<Arc<Mutex<FakeApple>>>,
            ) -> Json<serde_json::Value> {
                let mut shared = shared.lock().unwrap();
                shared.queries += 1;
                let bits = shared.bits;
                Json(serde_json::json!({ "bit0": bits.case_open, "bit1": bits.banned }))
            }
            async fn update() -> (axum::http::StatusCode, &'static str) {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
            }
            let app = axum::Router::new()
                .route("/v1/query_two_bits", axum::routing::post(query))
                .route("/v1/update_two_bits", axum::routing::post(update))
                .with_state(shared.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (base, shared)
        }
    }
}
