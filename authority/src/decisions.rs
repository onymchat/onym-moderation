//! The one path by which a case becomes a verdict.
//!
//! Three callers reach it — the JSON API, the moderator's web panel,
//! and autonomous triage — and every guard the contract puts around a
//! sanction lives here rather than in any of them. A "you may not ban
//! yet" check duplicated across three call sites is a check one of
//! them will eventually lose.

use serde_json::Value;
use time::OffsetDateTime;

use crate::cases::{self, Issued};
use crate::error::Error;
use crate::state::AppState;
use crate::store::NoticeDelivery;
use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Dismiss,
    Ban,
    /// A reversal on appeal — a new verdict that clears marks, never an
    /// edit to the one it corrects (§12).
    Reverse,
}

impl Disposition {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "dismiss" => Ok(Disposition::Dismiss),
            "ban" => Ok(Disposition::Ban),
            "reverse" => Ok(Disposition::Reverse),
            other => Err(Error::BadRequest(format!(
                "unknown disposition {other:?} (expected dismiss | ban | reverse)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::Dismiss => "dismiss",
            Disposition::Ban => "ban",
            Disposition::Reverse => "reverse",
        }
    }
}

/// Who decided. Recorded on the case so an audit can tell a human's
/// judgment from a classifier's, which is exactly the distinction a
/// user consenting to "professional judgment" cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decider {
    /// A moderator, via the API or the panel.
    Human,
    /// A moderator acting on a triage recommendation they were shown.
    HumanAssisted,
    /// Autonomous triage, with no human in the loop.
    Automated,
}

impl Decider {
    pub fn as_str(self) -> &'static str {
        match self {
            Decider::Human => "human",
            Decider::HumanAssisted => "human-assisted",
            Decider::Automated => "automated",
        }
    }
}

/// Apply a decision to a case: check it is allowed, issue the signed
/// verdict, update the case, adjust the reporter's record, and hand the
/// verdict to the interface.
/// Which claim a reviewer answered. A reversal clears the marks either
/// way, but only the claim actually read gets an outcome recorded
/// against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    Appeal,
    NewHolder,
}

pub async fn apply(
    state: &std::sync::Arc<AppState>,
    case_id: &str,
    disposition: Disposition,
    reasoning: &str,
    decider: Decider,
    now: OffsetDateTime,
) -> Result<Issued, Error> {
    apply_inner(state, case_id, disposition, reasoning, decider, now, Context::default()).await
}

/// As `apply`, naming the claim the reviewer answered and the claim
/// revision the page they answered it from was rendered at.
///
/// The second is not bookkeeping. A pending appeal may be supplemented
/// without leaving `pending`, and another moderator may answer the same
/// claim while this one reads it — neither moves the case revision, so
/// without this the review commits as though it had read a file it
/// never saw, or re-decides a claim already decided.
#[allow(clippy::too_many_arguments)]
pub async fn apply_reviewing(
    state: &std::sync::Arc<AppState>,
    case_id: &str,
    disposition: Disposition,
    reasoning: &str,
    decider: Decider,
    now: OffsetDateTime,
    reviewed: Claim,
    read_at_claim_revision: Option<i64>,
) -> Result<Issued, Error> {
    apply_inner(
        state,
        case_id,
        disposition,
        reasoning,
        decider,
        now,
        Context {
            reviewed: Some(reviewed),
            expect_claim_revision: read_at_claim_revision,
            ..Context::default()
        },
    )
    .await
}

/// As `apply`, but refusing if the case has changed since the reading
/// this decision was made from. Automated deciders read the case
/// document, wait on a model, and only then commit; without this the
/// gap between the freshness check and the commit was a window in
/// which a response could land, and the recovery path skipped the
/// check entirely.
pub async fn apply_at_revision(
    state: &std::sync::Arc<AppState>,
    case_id: &str,
    disposition: Disposition,
    reasoning: &str,
    decider: Decider,
    now: OffsetDateTime,
    revision: i64,
) -> Result<Issued, Error> {
    apply_inner(
        state,
        case_id,
        disposition,
        reasoning,
        decider,
        now,
        Context { expect_revision: Some(revision), ..Context::default() },
    )
    .await
}

/// The parts of a decision beyond who and what: the revision it was
/// read at, and which claim the decider answered. Both are `None` for
/// the plain path — a moderator deciding from the page in front of
/// them, with nothing pending.
#[derive(Default, Clone, Copy)]
struct Context {
    expect_revision: Option<i64>,
    expect_claim_revision: Option<i64>,
    reviewed: Option<Claim>,
}

async fn apply_inner(
    state: &std::sync::Arc<AppState>,
    case_id: &str,
    disposition: Disposition,
    reasoning: &str,
    decider: Decider,
    now: OffsetDateTime,
    context: Context,
) -> Result<Issued, Error> {
    let Context { expect_revision, expect_claim_revision, reviewed } = context;
    let mut case = state
        .store
        .case(case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    // Reasoning is mandatory on every disposition — an unexplained ban
    // is nonconforming even where confidentiality keeps it private
    // between authority and accused (§5.6 constraint 2).
    if reasoning.trim().is_empty() {
        return Err(Error::BadRequest("reasoning is required on every disposition".into()));
    }

    let stamp = util::format_timestamp(now);

    // Every reporter attached to the case, not just whoever filed
    // first. A case three people reported was upheld or dismissed for
    // all three.
    let reporters = {
        let mut reporters = state.store.case_reporters(case_id)?;
        if !reporters.contains(&case.reporter) {
            reporters.push(case.reporter.clone());
        }
        reporters
    };

    let issued = match disposition {
        Disposition::Dismiss => {
            require_open(&case)?;
            cases::dismissal_verdict(
                &case,
                &state.config.manifest.component_id,
                reasoning,
                now,
                &state.signing_key,
            )?
        }
        Disposition::Ban => {
            require_open(&case)?;
            // Deadline first: a case past it is already dismissed by
            // default, and saying "notice has not been delivered"
            // about a case that is over would be a refusal for the
            // wrong reason.
            require_decision_deadline_not_passed(&case, now)?;
            require_notice_delivered(state, case_id)?;
            if !(state.config.allow_early_ban_for_qa
                && matches!(decider, Decider::Human | Decider::HumanAssisted))
            {
                require_response_window_closed(&case, now)?;
            }
            // The terms come from the manifest the accused's mandate
            // pinned. Republishing with a longer ban term must not
            // re-term someone who consented before it.
            let consented = consented_manifest(state, &case)?;
            let class = consented
                .violation_class(&case.class_id)
                .ok_or_else(|| Error::ClassOutsideMandate(case.class_id.clone()))?;
            cases::ban_verdict(
                &case,
                class,
                &state.config.manifest.component_id,
                reasoning,
                now,
                &state.signing_key,
            )?
        }
        Disposition::Reverse => {
            if case.disposition.as_deref() != Some("ban") {
                return Err(Error::CaseState("only a ban can be reversed".into()));
            }
            cases::reversal_verdict(
                &case,
                &state.config.manifest.component_id,
                reasoning,
                now,
                &state.signing_key,
            )?
        }
    };

    case.stage = "decided".into();
    case.disposition = Some(match disposition {
        Disposition::Reverse => "reversed".to_string(),
        other => other.as_str().to_string(),
    });
    if disposition == Disposition::Ban {
        let verdict: Value = serde_json::from_slice(&issued.raw)
            .map_err(|e| Error::Internal(format!("re-read verdict: {e}")))?;
        case.appeal_deadline = verdict["appealDeadline"].as_str().map(str::to_string);
    }
    // Verdict, case stage, event, and reporters' standing commit
    // together, and only after the verdict was built and signed.
    // Crediting reporters first meant a decision that failed to sign
    // still moved their records.
    //
    // A reversal is not a dismissal of the report: it corrects this
    // authority's own error, so nobody's record moves for it.
    let credited: &[String] =
        if disposition == Disposition::Reverse { &[] } else { &reporters };

    // A reversal answers whatever was pending, and only what was
    // pending. Deciding this here rather than at the call site is what
    // makes the JSON API and the panel agree: a reversal through
    // `/decide` used to leave the appeal `pending` forever — the case
    // stayed in the panel's queue, and a moderator could then "uphold"
    // a verdict that had already been reversed. And a reversal of a
    // ban nobody appealed was recorded as an appeal outcome, which is a
    // review that did not happen.
    // A reversal resolves the claim that was *reviewed*, and only that
    // one. Resolving both marked a claim nobody had read as decided:
    // granting the unauthenticated new-holder claim also recorded the
    // accused's appeal as reversed, and vice versa. The other claim is
    // marked moot — the marks are cleared, so its remedy has arrived —
    // which is true without inventing a review that did not happen.
    let (appeal_state, new_holder_state, extra_event) = if disposition == Disposition::Reverse {
        let appeal_pending = case.appeal_state == "pending";
        let claim_pending = case.new_holder_state == "pending";
        let (appeal, claim, event) = match reviewed {
            Some(Claim::Appeal) if appeal_pending => (
                Some("reversed"),
                claim_pending.then_some("moot"),
                Some(("appeal_reversed", reasoning)),
            ),
            Some(Claim::NewHolder) if claim_pending => (
                appeal_pending.then_some("moot"),
                Some("granted"),
                Some(("new_holder_claim_granted", reasoning)),
            ),
            // Reversing with nothing reviewed, or with the named claim
            // not pending: the authority correcting its own error.
            // Anything pending becomes moot, because the marks are
            // gone — but no review is recorded for it.
            _ => (
                appeal_pending.then_some("moot"),
                claim_pending.then_some("moot"),
                None,
            ),
        };
        (appeal, claim, event)
    } else {
        (None, None, None)
    };
    state.store.commit_decision(&crate::store::Decision {
        case: &case,
        verdict_ref: &issued.verdict_ref,
        disposition: &issued.disposition,
        raw: &issued.raw,
        at: &stamp,
        event_kind: "decided",
        event_detail: &format!("{} by {}", disposition.as_str(), decider.as_str()),
        credited_reporters: credited,
        // The state the guards above found. Re-asserted inside the
        // transaction, because they read the case under a lock this
        // function has long since released — and three callers reach
        // here, one of them a background sweep.
        expect_stage: if disposition == Disposition::Reverse { "decided" } else { "open" },
        expect_disposition: if disposition == Disposition::Reverse { Some("ban") } else { None },
        // Only automated decisions carry one: they are made from a
        // reading of the case document taken up to two minutes
        // earlier, and are the ones that can go stale. A moderator
        // decides from the page in front of them.
        expect_revision,
        // Only a review carries one — the panel and the JSON API's
        // reversal path. A first-instance decision answers no claim.
        expect_claim_revision,
        appeal_state,
        new_holder_state,
        extra_event,
    })?;

    // Detached: the verdict is committed, and the caller should not
    // wait on a backlog drained at fifteen seconds a verdict. The sweep
    // is the reliable path; this only makes a fresh verdict leave
    // promptly when the interface is healthy.
    crate::delivery::flush_soon(state);

    tracing::info!(
        %case_id,
        verdict_ref = %issued.verdict_ref,
        disposition = %issued.disposition,
        decider = decider.as_str(),
        "case decided"
    );
    Ok(issued)
}

fn require_open(case: &crate::store::CaseRecord) -> Result<(), Error> {
    if case.stage != "open" {
        return Err(Error::CaseState("case is already decided".into()));
    }
    Ok(())
}

/// The terms a case is judged by: the manifest its accused's mandate
/// pinned. Missing jurisdiction state must never fall forward to terms
/// published after the accused consented.
fn consented_manifest(
    state: &AppState,
    case: &crate::store::CaseRecord,
) -> Result<crate::types::AuthorityManifest, Error> {
    let mandate = state
        .store
        .mandate(&case.mandate_ref)?
        .ok_or_else(|| {
            Error::Internal(format!(
                "case {} references missing mandate {}; refusing to judge under published \
                 terms the accused may not have consented to",
                case.case_id, case.mandate_ref
            ))
        })?;
    match state.store.manifest_bytes(&mandate.manifest_hash)? {
        Some(raw) => serde_json::from_slice(&raw)
            .map_err(|e| Error::Internal(format!("stored consented manifest unparseable: {e}"))),
        None => {
            let published_hash = util::sha256_hex(&state.config.manifest_raw);
            if published_hash == mandate.manifest_hash {
                tracing::warn!(
                    mandate_ref = %mandate.mandate_ref,
                    "legacy mandate has no snapshot; published bytes still match its hash"
                );
                Ok(state.config.manifest.clone())
            } else {
                Err(Error::Internal(format!(
                    "mandate {} pins manifest {}, but its snapshot is missing and the published \
                     manifest hashes to {published_hash}; refusing to judge under unconsented terms",
                    mandate.mandate_ref, mandate.manifest_hash
                )))
            }
        }
    }
}

/// Notice must actually have reached the interface before a sanction.
///
/// The opening verdict is what the accused is served with; until it
/// has been delivered, their response window has been running against
/// a case nobody told them about. Holding the window is not the same
/// as holding it *visibly*, and a ban at the end of a silent window is
/// a ban without notice however carefully the clock was kept.
///
/// This sits in the shared decision path, so autonomous triage inherits
/// it — the caller most likely to reach a verdict while delivery is
/// still queued.
fn require_notice_delivered(state: &AppState, case_id: &str) -> Result<(), Error> {
    // One read. Which notice, and whether waiting will help: a refusal
    // on shape marks the verdict `undeliverable` and leaves
    // `delivered = 0` permanently, so this guard then refuses every ban
    // on the case for the rest of its life. That is the safe direction
    // and it is not a reason to be unhelpful about it — a moderator
    // reading "the opening verdict has not reached the interface" on a
    // case that will never clear has no way to tell a queue from a dead
    // end.
    match state.store.notice_delivery(case_id)? {
        NoticeDelivery::AllDelivered => Ok(()),
        NoticeDelivery::NoneIssued => Err(Error::CaseState(
            "no notice has been issued for this case, so the accused has never been served; \
             banning would run the response window silently"
                .into(),
        )),
        NoticeDelivery::Queued(refs) => Err(Error::CaseState(format!(
            "notice {} has not reached the interface yet, so the accused has not been served; \
             banning now would run the response window silently. It is still queued — no action \
             is needed beyond letting delivery finish.",
            refs.join(", ")
        ))),
        // One URL per stuck ref. Listing every ref and then a single
        // URL built from the first left a moderator with two problems
        // and one instruction, having to infer the rest.
        NoticeDelivery::GivenUp(refs) => Err(Error::CaseState(format!(
            "this case cannot be banned: {} {} refused by the interface and given up on, so the \
             accused has never been served. Banning would run the response window silently. \
             Repair the interface, then requeue — this will not happen on its own: {}",
            if refs.len() == 1 { format!("notice {}", refs[0]) } else { format!("notices {}", refs.join(", ")) },
            if refs.len() == 1 { "was" } else { "were" },
            refs.iter()
                .map(|reference| format!("POST /v1/verdicts/{reference}/requeue"))
                .collect::<Vec<_>>()
                .join("; ")
        ))),
    }
}

/// Once the decision deadline passes the case is dismissed by default
/// (§3.5), whether or not the sweep has run yet. Without this a
/// moderator — or a classifier — could ban a case the contract had
/// already ended in the accused's favour, simply by winning the race
/// against a background task.
fn require_decision_deadline_not_passed(
    case: &crate::store::CaseRecord,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let deadline = util::parse_timestamp(&case.decision_deadline)
        .map_err(|e| Error::Internal(format!("stored decisionDeadline: {e}")))?;
    if now > deadline {
        return Err(Error::WindowClosed(format!(
            "the decision deadline passed at {}; this case is dismissed by default and cannot \
             be banned",
            case.decision_deadline
        )));
    }
    Ok(())
}

/// Notice must precede sanction. A ban before the consented response
/// window has *elapsed* is nonconforming (§8 obligation 4, §11.4), and
/// this holds however confident whoever is deciding happens to be — a
/// classifier's certainty is not a reason to shorten someone's window
/// to answer.
///
/// An answered case does not shorten it either. The accused was
/// promised the time, not one chance to speak: they may reply on day
/// one and keep gathering counter-evidence until day seven.
fn require_response_window_closed(
    case: &crate::store::CaseRecord,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let deadline = util::parse_timestamp(&case.response_deadline)
        .map_err(|e| Error::Internal(format!("stored responseDeadline: {e}")))?;
    if now < deadline {
        return Err(Error::CaseState(format!(
            "the response window runs until {}; a ban before it closes is nonconforming",
            case.response_deadline
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CaseRecord, MandateRecord, Store};

    fn state_with_mandate() -> std::sync::Arc<AppState> {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        let manifest_hash = util::sha256_hex(&state.config.manifest_raw);
        state
            .store
            .put_mandate(
                &MandateRecord {
                    mandate_ref: "m1".into(),
                    user_key: "onym:key:acc".into(),
                    device_binding: "d1".into(),
                    classes: vec!["unsolicited-pornography".into()],
                    manifest_hash,
                },
                b"{}",
                &state.config.manifest_raw,
                "2026-08-01T00:00:00Z",
            )
            .unwrap();
        state
    }

    fn case(responded: bool, response_deadline: &str) -> CaseRecord {
        CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "unsolicited-pornography".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: response_deadline.into(),
            decision_deadline: "2026-08-30T00:00:00Z".into(),
            responded,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
        }
    }

    #[tokio::test]
    async fn a_ban_before_the_response_window_closes_is_refused() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&case(false, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await;
        assert!(matches!(result, Err(Error::CaseState(_))));
        // And nothing was issued — a refused decision leaves no verdict.
        assert!(state.store.undelivered_verdicts().unwrap().is_empty());
    }

    /// Automation gets no shortcut. This is the case that matters: a
    /// classifier is exactly the thing likely to "know" the answer
    /// before the accused has spoken.
    #[tokio::test]
    async fn automation_may_not_ban_early_either() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&case(false, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Automated, now).await;
        assert!(matches!(result, Err(Error::CaseState(_))));
    }

    /// A case whose accused was actually served: the opening verdict
    /// exists and reached the interface, which is what a ban requires.
    fn notice_served(state: &AppState, case_id: &str) {
        state.store.put_delivered_open_case_verdict(case_id, "v-open").unwrap();
    }

    #[tokio::test]
    async fn a_ban_after_the_window_is_allowed() {
        let state = state_with_mandate();
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();
        notice_served(&state, "c1");

        apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await.unwrap();
        assert_eq!(state.store.case("c1").unwrap().unwrap().disposition.as_deref(), Some("ban"));
    }

    /// A response does not close the window early. The accused was
    /// promised the time, not merely one chance to speak — they may
    /// answer on day one and keep gathering counter-evidence until the
    /// deadline their consented class declared.
    #[tokio::test]
    async fn a_response_does_not_close_the_window_early() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&case(true, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await;
        assert!(matches!(result, Err(Error::CaseState(_))));
    }

    /// Undecided is dismissal, and it binds at the moment of decision
    /// rather than whenever the sweep next happens to run.
    #[tokio::test]
    async fn a_ban_after_the_decision_deadline_is_refused() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        let mut overdue = case(false, "2026-08-05T00:00:00Z");
        overdue.decision_deadline = "2026-08-08T00:00:00Z".into();
        state.store.put_case(&overdue).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await;
        assert!(matches!(result, Err(Error::WindowClosed(_))));
        assert!(state.store.undelivered_verdicts().unwrap().is_empty());
    }

    /// Dismissals carry no such constraint — they are not a sanction,
    /// and making someone wait for one would be perverse.
    #[tokio::test]
    async fn a_dismissal_may_land_at_any_time() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&case(false, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        apply(&state, "c1", Disposition::Dismiss, "hash:why", Decider::Automated, now)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_reasoning_is_refused_for_every_disposition() {
        let state = std::sync::Arc::new(AppState::for_tests(Store::in_memory().unwrap()));
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        for disposition in [Disposition::Dismiss, Disposition::Ban] {
            let result = apply(&state, "c1", disposition, "   ", Decider::Human, now).await;
            assert!(matches!(result, Err(Error::BadRequest(_))));
        }
    }

    #[tokio::test]
    async fn the_decider_is_recorded_on_the_case() {
        let state = state_with_mandate();
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();
        notice_served(&state, "c1");

        apply(&state, "c1", Disposition::Ban, "hash:why", Decider::HumanAssisted, now)
            .await
            .unwrap();
        let events = state.store.events("c1").unwrap();
        assert!(events.iter().any(|(_, kind, detail)| kind == "decided"
            && detail.contains("human-assisted")));
    }
}
