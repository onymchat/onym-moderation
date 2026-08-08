//! The decision-deadline default: **undecided is dismissal**.
//!
//! This is the invariant that keeps a stalled authority from acquiring
//! hostage power (Moderation.md §3.5, §11.6). Every case carries a
//! decision deadline from the manifest, and when it passes with no
//! decision the case is dismissed and the case-open mark cleared — with
//! no action by the authority, the reporter, or the accused. A blown
//! deadline is a dismissal, not an extension nobody consented to.
//!
//! It runs as a sweep rather than a timer per case so that a service
//! that was down over a deadline still honours it on the way back up:
//! the arithmetic is wall-clock, not elapsed-process-time.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::cases;
use crate::error::Error;
use crate::state::AppState;
use crate::util;

/// Dismiss every open case whose decision deadline has passed. Returns
/// how many were dismissed.
pub async fn sweep(state: &AppState, now: OffsetDateTime) -> Result<usize, Error> {
    let overdue = state.store.cases_overdue(&util::format_timestamp(now))?;
    sweep_overdue(state, now, overdue).await
}

async fn sweep_overdue(
    state: &AppState,
    now: OffsetDateTime,
    overdue: Vec<crate::store::CaseRecord>,
) -> Result<usize, Error> {
    let mut dismissed = 0;

    for mut case in overdue {
        let issued = cases::dismissal_verdict(
            &case,
            &state.config.manifest.component_id,
            // The reasoning is mandatory and must say something true:
            // this authority did not decide in time.
            "decision deadline passed without a decision; dismissed by default",
            now,
            &state.signing_key,
        )?;

        let stamp = util::format_timestamp(now);
        case.stage = "decided".into();
        case.disposition = Some("dismiss".into());

        // The reporter's track record is deliberately *not* touched
        // here. This dismissal says nothing about their report — it
        // says this authority failed to decide in time. Charging them a
        // `dismissed` would make the authority's own silence lower the
        // intake weight of someone who may have been entirely right,
        // and would give a stalling authority a quiet way to demote
        // reporters it would rather not hear from.
        let committed = state.store.commit_decision(&crate::store::Decision {
            case: &case,
            verdict_ref: &issued.verdict_ref,
            disposition: &issued.disposition,
            raw: &issued.raw,
            at: &stamp,
            event_kind: "decision_overdue",
            event_detail: "dismissed by default",
            credited_reporters: &[],
            // The sweep found it open; if a moderator decided it in the
            // meantime, theirs stands and this one does not land.
            expect_stage: "open",
            expect_disposition: None,
        });
        match committed {
            Ok(()) => {}
            Err(Error::CaseState(reason)) => {
                tracing::info!(
                    case_id = %case.case_id,
                    %reason,
                    "overdue dismissal lost a decision race; keeping the committed decision"
                );
                continue;
            }
            Err(error) => return Err(error),
        }

        tracing::warn!(
            case_id = %case.case_id,
            verdict_ref = %issued.verdict_ref,
            "decision deadline passed; case dismissed by default"
        );
        dismissed += 1;
    }

    if dismissed > 0 {
        state.delivery.flush(&state.store).await?;
    }
    Ok(dismissed)
}

/// Background loop: sweep deadlines, then push any undelivered
/// verdicts. Both are idempotent, so a missed tick costs nothing.
pub fn spawn(state: Arc<AppState>) {
    let interval = std::time::Duration::from_secs(state.config.deadline_sweep_secs);
    tokio::spawn(async move {
        loop {
            if let Err(e) = sweep(&state, OffsetDateTime::now_utc()).await {
                tracing::error!(error = %e, "deadline sweep failed");
            }
            if let Err(e) = state.delivery.flush(&state.store).await {
                tracing::error!(error = %e, "verdict delivery failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CaseRecord, Store};

    fn case_due(decision_deadline: &str) -> CaseRecord {
        CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: decision_deadline.into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
        }
    }

    #[tokio::test]
    async fn an_overdue_case_is_dismissed_and_the_mark_cleared() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case_due("2026-08-08T00:00:00Z")).unwrap();

        let now = util::parse_timestamp("2026-08-09T00:00:00Z").unwrap();
        assert_eq!(sweep(&state, now).await.unwrap(), 1);

        let case = state.store.case("c1").unwrap().unwrap();
        assert_eq!(case.stage, "decided");
        assert_eq!(case.disposition.as_deref(), Some("dismiss"));

        // The verdict it emitted clears both marks — the accused is not
        // left carrying a case-open mark for an authority's silence.
        let queued = state.store.undelivered_verdicts().unwrap();
        assert_eq!(queued.len(), 1);
        let v: serde_json::Value = serde_json::from_slice(&queued[0].raw).unwrap();
        assert_eq!(v["disposition"], "dismiss");
        assert_eq!(v["marks"]["case-open"], false);
        assert_eq!(v["marks"]["banned"], false);
        assert_eq!(v["final"], true);
    }

    #[tokio::test]
    async fn a_case_inside_its_deadline_is_left_alone() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case_due("2026-08-20T00:00:00Z")).unwrap();

        let now = util::parse_timestamp("2026-08-09T00:00:00Z").unwrap();
        assert_eq!(sweep(&state, now).await.unwrap(), 0);
        assert_eq!(state.store.case("c1").unwrap().unwrap().stage, "open");
    }

    /// Sweeping twice must not issue a second dismissal — the case is
    /// no longer open after the first.
    #[tokio::test]
    async fn the_sweep_is_idempotent() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        state.store.put_case(&case_due("2026-08-08T00:00:00Z")).unwrap();

        let now = util::parse_timestamp("2026-08-09T00:00:00Z").unwrap();
        assert_eq!(sweep(&state, now).await.unwrap(), 1);
        assert_eq!(sweep(&state, now).await.unwrap(), 0);
        assert_eq!(state.store.undelivered_verdicts().unwrap().len(), 1);
    }

    /// A moderator may decide one case after the sweep reads the
    /// overdue batch. That expected race must not delay the defaults
    /// owed to every other case in the same batch.
    #[tokio::test]
    async fn a_lost_decision_race_does_not_abort_the_overdue_batch() {
        let state = AppState::for_tests(Store::in_memory().unwrap());
        let first = case_due("2026-08-08T00:00:00Z");
        let mut second = case_due("2026-08-08T00:00:00Z");
        second.case_id = "c2".into();
        second.accused = "onym:key:acc-2".into();
        state.store.put_case(&first).unwrap();
        state.store.put_case(&second).unwrap();

        let now = util::parse_timestamp("2026-08-09T00:00:00Z").unwrap();
        let stale_batch = state.store.cases_overdue(&util::format_timestamp(now)).unwrap();

        let mut moderator_winner = first;
        let issued = cases::dismissal_verdict(
            &moderator_winner,
            &state.config.manifest.component_id,
            "moderator dismissed first",
            now,
            &state.signing_key,
        )
        .unwrap();
        moderator_winner.stage = "decided".into();
        moderator_winner.disposition = Some("dismiss".into());
        state
            .store
            .commit_decision(&crate::store::Decision {
                case: &moderator_winner,
                verdict_ref: &issued.verdict_ref,
                disposition: &issued.disposition,
                raw: &issued.raw,
                at: &util::format_timestamp(now),
                event_kind: "decided",
                event_detail: "moderator dismissed",
                credited_reporters: &[],
                expect_stage: "open",
                expect_disposition: None,
            })
            .unwrap();

        assert_eq!(sweep_overdue(&state, now, stale_batch).await.unwrap(), 1);
        assert_eq!(state.store.case("c1").unwrap().unwrap().stage, "decided");
        assert_eq!(state.store.case("c2").unwrap().unwrap().stage, "decided");
    }
}
