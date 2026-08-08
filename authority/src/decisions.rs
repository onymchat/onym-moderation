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
pub async fn apply(
    state: &AppState,
    case_id: &str,
    disposition: Disposition,
    reasoning: &str,
    decider: Decider,
    now: OffsetDateTime,
) -> Result<Issued, Error> {
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
            require_decision_deadline_not_passed(&case, now)?;
            require_response_window_closed(&case, now)?;
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
    state.store.commit_decision(&crate::store::Decision {
        case: &case,
        verdict_ref: &issued.verdict_ref,
        disposition: &issued.disposition,
        raw: &issued.raw,
        at: &stamp,
        event_kind: "decided",
        event_detail: &format!("{} by {}", disposition.as_str(), decider.as_str()),
        credited_reporters: credited,
    })?;

    state.delivery.flush(&state.store).await?;

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
/// pinned, falling back to the published one only for mandates
/// predating manifest snapshots.
fn consented_manifest(
    state: &AppState,
    case: &crate::store::CaseRecord,
) -> Result<crate::types::AuthorityManifest, Error> {
    let snapshot = state
        .store
        .mandate(&case.mandate_ref)?
        .and_then(|mandate| state.store.manifest_bytes(&mandate.manifest_hash).transpose())
        .transpose()?;
    match snapshot {
        Some(raw) => serde_json::from_slice(&raw)
            .map_err(|e| Error::Internal(format!("stored consented manifest unparseable: {e}"))),
        None => Ok(state.config.manifest.clone()),
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
            "the decision deadline passed at {}; this case is dismissed by default and cannot              be banned",
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
    use crate::store::{CaseRecord, Store};

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
        }
    }

    #[tokio::test]
    async fn a_ban_before_the_response_window_closes_is_refused() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
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
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(false, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Automated, now).await;
        assert!(matches!(result, Err(Error::CaseState(_))));
    }

    #[tokio::test]
    async fn a_ban_after_the_window_is_allowed() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await.unwrap();
        assert_eq!(state.store.case("c1").unwrap().unwrap().disposition.as_deref(), Some("ban"));
    }

    /// A response does not close the window early. The accused was
    /// promised the time, not merely one chance to speak — they may
    /// answer on day one and keep gathering counter-evidence until the
    /// deadline their consented class declared.
    #[tokio::test]
    async fn a_response_does_not_close_the_window_early() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(true, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        let result = apply(&state, "c1", Disposition::Ban, "hash:why", Decider::Human, now).await;
        assert!(matches!(result, Err(Error::CaseState(_))));
    }

    /// Undecided is dismissal, and it binds at the moment of decision
    /// rather than whenever the sweep next happens to run.
    #[tokio::test]
    async fn a_ban_after_the_decision_deadline_is_refused() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
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
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(false, "2026-08-20T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        apply(&state, "c1", Disposition::Dismiss, "hash:why", Decider::Automated, now)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_reasoning_is_refused_for_every_disposition() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        for disposition in [Disposition::Dismiss, Disposition::Ban] {
            let result = apply(&state, "c1", disposition, "   ", Decider::Human, now).await;
            assert!(matches!(result, Err(Error::BadRequest(_))));
        }
    }

    #[tokio::test]
    async fn the_decider_is_recorded_on_the_case() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case(false, "2026-08-05T00:00:00Z")).unwrap();
        let now = util::parse_timestamp("2026-08-10T00:00:00Z").unwrap();

        apply(&state, "c1", Disposition::Ban, "hash:why", Decider::HumanAssisted, now)
            .await
            .unwrap();
        let events = state.store.events("c1").unwrap();
        assert!(events.iter().any(|(_, kind, detail)| kind == "decided"
            && detail.contains("human-assisted")));
    }
}
