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
            expect_revision: None,
            expect_claim_revision: None,
            appeal_state: None,
            new_holder_state: None,
            extra_event: None,
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

/// Assess every case whose response window has closed and that has no
/// decision from the model yet.
///
/// The timing is the point. The reference policy has the authority
/// assess the *completed* case document — the one that includes
/// whatever the accused chose to file — so a case is not shown to a
/// model until the window they were promised has run out. There is no
/// "classify on arrival, apply later" path any more: an assessment made
/// before the response exists is an assessment of a different document,
/// and deciding on it would make the response window decorative.
///
/// A case whose last assessment reached no decision is retried, which
/// is the "valid retry" the policy allows. If none ever lands, the
/// decision deadline dismisses the case — and because the dismissal
/// sweep runs first, an overdue case is dismissed rather than decided.
const MAX_ASSESSMENTS_PER_SWEEP: usize = 25;

/// How many times one case is put to the model before the sweep stops
/// trying. Generous, because a model can be down for maintenance and a
/// response window is days long — but not unbounded: a case the model
/// will never read should end at its decision deadline, dismissed, not
/// be retried until then.
const MAX_ASSESSMENT_ATTEMPTS: i64 = 24;

/// Retry spacing. A model that could not read a case a moment ago is
/// unlikely to read it thirty seconds later, so each failed attempt
/// pushes the next one further out, to a ceiling of six hours.
fn retry_due(attempts: i64, last_attempt: Option<&str>, now: OffsetDateTime) -> bool {
    let Some(last) = last_attempt else { return true };
    let Ok(last) = util::parse_timestamp(last) else { return true };
    // Clamped at 7 shifts, so the doubling actually reaches the stated
    // ceiling: `5 << 6` is 320, which `min(360)` never touched.
    let minutes = (5i64 << attempts.min(7)).min(360);
    now >= last + time::Duration::minutes(minutes)
}

pub async fn triage_sweep(
    state: &std::sync::Arc<AppState>,
    now: OffsetDateTime,
) -> Result<(), Error> {
    if state.triage.is_none() {
        return Ok(());
    }

    // Bounded per tick. Each case is awaited in turn against a model
    // that may take two minutes, so an unbounded backlog would make a
    // single tick run for hours and starve the next deadline sweep.
    // What is left over is picked up on the following tick, and a case
    // that waits is a case that stays open — never one that gets
    // decided by default early.
    let due: Vec<_> = state
        .store
        .cases_awaiting_assessment(&util::format_timestamp(now))?
        .into_iter()
        .filter(|(_, attempts, last)| {
            *attempts < MAX_ASSESSMENT_ATTEMPTS && retry_due(*attempts, last.as_deref(), now)
        })
        .collect();
    let total = due.len();
    for (case, _, _) in due.into_iter().take(MAX_ASSESSMENTS_PER_SWEEP) {
        crate::triage::assess_and_maybe_decide(state, &case.case_id, now).await;
    }
    // Decisions the model reached and a guard refused. Cheap — no
    // model call — and the reason it runs every tick: the guard that
    // refused is usually a delivery that has since completed.
    crate::triage::retry_unapplied_decisions(state).await;

    if total > MAX_ASSESSMENTS_PER_SWEEP {
        tracing::info!(
            assessed = MAX_ASSESSMENTS_PER_SWEEP,
            waiting = total - MAX_ASSESSMENTS_PER_SWEEP,
            "assessment backlog exceeds one sweep; the rest wait for the next tick"
        );
    }

    Ok(())
}

/// Background loop: sweep deadlines, run triage, then push any
/// undelivered verdicts. All three are idempotent, so a missed tick
/// costs nothing.
/// How long an upload that never became evidence is kept.
///
/// Generous enough that a client can upload, prompt the user through
/// the report screen, and file — and short enough that a photo somebody
/// chose not to report does not sit on this server.
const UNREFERENCED_UPLOAD_TTL: time::Duration = time::Duration::hours(24);

/// Delete media the case and appeal no longer require.
///
/// Two disposals with one rule behind them: material is kept for the
/// process that needs it and no longer. Uploads that never became
/// evidence expire on a timer; a decided case's images go once its
/// appeal window has closed.
///
/// Original and derivative always go together. Keeping the derivative
/// would be keeping the picture, and a deletion that leaves a legible
/// copy behind is not one.
pub fn retention_sweep(state: &AppState, now: OffsetDateTime) -> Result<usize, Error> {
    let cutoff = util::format_timestamp(now - UNREFERENCED_UPLOAD_TTL);
    let mut removed = state.store.sweep_unreferenced_evidence_blobs(&cutoff)?;
    if removed > 0 {
        tracing::info!(removed, "expired evidence uploads that were never reported");
    }

    for case_id in state.store.cases_with_media_past_retention(&util::format_timestamp(now))? {
        let gone = state.store.delete_evidence_blobs_for_case(&case_id)?;
        if gone > 0 {
            tracing::info!(%case_id, images = gone, "deleted case media past its appeal window");
        }
        removed += gone;
    }
    Ok(removed)
}

pub fn spawn(state: Arc<AppState>) {
    let interval = std::time::Duration::from_secs(state.config.deadline_sweep_secs);

    // Deadlines and delivery run in their own task, on their own
    // clock. Sharing a loop with assessment meant a slow model delayed
    // them: 25 cases awaited in turn at a two-minute timeout is a
    // worst-case tick far longer than the interval, and "undecided is
    // dismissal" is the invariant that must not wait behind an
    // unrelated inference. Nothing here calls the model.
    let deadlines = state.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = sweep(&deadlines, OffsetDateTime::now_utc()).await {
                tracing::error!(error = %e, "deadline sweep failed");
            }
            if let Err(e) = deadlines.delivery.flush(&deadlines.store).await {
                tracing::error!(error = %e, "verdict delivery failed");
            }
            if let Err(e) = retention_sweep(&deadlines, OffsetDateTime::now_utc()) {
                tracing::error!(error = %e, "media retention sweep failed");
            }
            tokio::time::sleep(interval).await;
        }
    });

    if state.triage.is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = triage_sweep(&state, OffsetDateTime::now_utc()).await {
                tracing::error!(error = %e, "triage sweep failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CaseRecord, Store};

    /// Store one image and return its digest.
    fn store_image(store: &Store, uploaded_at: &str) -> String {
        let bytes = crate::media::tiny_jpeg(10, 10);
        let accepted = crate::media::accept_image(&bytes).unwrap();
        store.put_evidence_blob(&accepted, &bytes, uploaded_at, "onym:key:uploader").unwrap();
        accepted.sha256
    }

    #[tokio::test]
    async fn an_upload_nobody_reported_expires() {
        let store = Store::in_memory().unwrap();
        let stale = store_image(&store, "2026-08-01T00:00:00Z");
        let state = crate::state::AppState::for_tests(store);

        let removed =
            retention_sweep(&state, util::parse_timestamp("2026-08-10T00:00:00Z").unwrap())
                .unwrap();

        assert_eq!(removed, 1);
        assert!(state.store.evidence_blob(&stale).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_reports_uploads_survive_the_gap_before_its_case_opens() {
        // The report goes on file before its case exists, and filing
        // restarts the upload's clock — so the gap is protected for a
        // full window rather than by a flag the sweep then skips.
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-10T00:00:00Z").unwrap();
        let state = crate::state::AppState::for_tests(store);

        retention_sweep(&state, util::parse_timestamp("2026-08-10T06:00:00Z").unwrap()).unwrap();

        assert!(state.store.evidence_blob(&digest).unwrap().is_some());
    }

    #[tokio::test]
    async fn an_upload_whose_case_never_opened_still_expires() {
        // The hole this closes: a flag set at filing time made a blob
        // invisible to the expiry sweep, and a case that never opened
        // left it invisible to case deletion too — retained forever and
        // counted against no budget. Case opening genuinely can fail
        // after the report is stored: a lapsed manifest and an expired
        // mandate both return an error in exactly that span.
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-01T00:00:00Z").unwrap();
        let state = crate::state::AppState::for_tests(store);

        let removed =
            retention_sweep(&state, util::parse_timestamp("2026-08-03T00:00:00Z").unwrap())
                .unwrap();

        assert_eq!(removed, 1);
        assert!(state.store.evidence_blob(&digest).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_decided_case_past_its_appeal_window_loses_original_and_derivative_together() {
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-01T00:00:00Z").unwrap();

        let mut case = case_due("2026-08-05T00:00:00Z");
        case.stage = "decided".into();
        case.disposition = Some("dismiss".into());
        case.appeal_deadline = Some("2026-08-06T00:00:00Z".into());
        store.put_case(&case).unwrap();
        store.attach_evidence_blobs(&case.case_id, &[digest.clone()]).unwrap();
        let state = crate::state::AppState::for_tests(store);

        // Still inside the appeal window: a human may yet need to look.
        retention_sweep(&state, util::parse_timestamp("2026-08-05T12:00:00Z").unwrap()).unwrap();
        assert!(state.store.evidence_blob(&digest).unwrap().is_some());

        retention_sweep(&state, util::parse_timestamp("2026-08-07T00:00:00Z").unwrap()).unwrap();
        assert!(state.store.evidence_blob(&digest).unwrap().is_none());
        assert!(
            state.store.evidence_blob_derivative(&digest).unwrap().is_none(),
            "a deletion that leaves the derivative behind still leaves the picture"
        );
    }

    /// The same photo can legitimately belong to two cases — forwarded
    /// by two senders, or one sender reported under two classes — and
    /// content addressing makes both resolve to one stored row. The
    /// first case finishing must not take the second case's evidence
    /// with it.
    #[tokio::test]
    async fn a_photo_two_cases_rest_on_survives_the_first_one_ending() {
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-01T00:00:00Z").unwrap();

        let mut finished = case_due("2026-08-05T00:00:00Z");
        finished.case_id = "finished".into();
        finished.stage = "decided".into();
        finished.disposition = Some("dismiss".into());
        store.put_case(&finished).unwrap();
        store.attach_evidence_blobs("finished", &[digest.clone()]).unwrap();

        // Still open, and resting on the same bytes.
        let mut live = case_due("2026-12-01T00:00:00Z");
        live.case_id = "live".into();
        store.put_case(&live).unwrap();
        store.attach_evidence_blobs("live", &[digest.clone()]).unwrap();

        let state = crate::state::AppState::for_tests(store);
        retention_sweep(&state, util::parse_timestamp("2026-08-10T00:00:00Z").unwrap()).unwrap();

        assert!(
            state.store.evidence_blob(&digest).unwrap().is_some(),
            "a finished case must not delete evidence a live case still rests on"
        );

        // And once the last case holding it is done, it does go.
        live.stage = "decided".into();
        live.disposition = Some("dismiss".into());
        state.store.put_case(&live).unwrap();
        retention_sweep(&state, util::parse_timestamp("2026-12-02T00:00:00Z").unwrap()).unwrap();
        assert!(state.store.evidence_blob(&digest).unwrap().is_none());
    }

    /// A dismissal carries no appeal deadline — it is final and clears
    /// the marks — so keying retention on that alone would delete its
    /// evidence on the very next sweep, minutes after a decision
    /// somebody may still be asking about.
    #[tokio::test]
    async fn a_dismissal_does_not_lose_its_evidence_the_moment_it_is_decided() {
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-01T00:00:00Z").unwrap();

        let mut case = case_due("2026-08-20T00:00:00Z");
        case.stage = "decided".into();
        case.disposition = Some("dismiss".into());
        case.appeal_deadline = None;
        store.put_case(&case).unwrap();
        store.attach_evidence_blobs(&case.case_id, &[digest.clone()]).unwrap();
        let state = crate::state::AppState::for_tests(store);

        // Decided early; the case's own signed horizon has not passed.
        retention_sweep(&state, util::parse_timestamp("2026-08-06T00:00:00Z").unwrap()).unwrap();
        assert!(state.store.evidence_blob(&digest).unwrap().is_some());

        retention_sweep(&state, util::parse_timestamp("2026-08-21T00:00:00Z").unwrap()).unwrap();
        assert!(state.store.evidence_blob(&digest).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_pending_appeal_keeps_the_evidence_it_is_about() {
        let store = Store::in_memory().unwrap();
        let digest = store_image(&store, "2026-08-01T00:00:00Z");
        store.touch_evidence_blobs(&[digest.clone()], "2026-08-01T00:00:00Z").unwrap();

        let mut case = case_due("2026-08-05T00:00:00Z");
        case.stage = "decided".into();
        case.disposition = Some("ban".into());
        case.appeal_deadline = Some("2026-08-06T00:00:00Z".into());
        case.appeal_state = "pending".into();
        store.put_case(&case).unwrap();
        store.attach_evidence_blobs(&case.case_id, &[digest.clone()]).unwrap();
        let state = crate::state::AppState::for_tests(store);

        retention_sweep(&state, util::parse_timestamp("2026-09-01T00:00:00Z").unwrap()).unwrap();

        assert!(
            state.store.evidence_blob(&digest).unwrap().is_some(),
            "deleting the material under a pending review would decide it by attrition"
        );
    }

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
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
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

    /// A model that could not read a case a moment ago is unlikely to
    /// read it thirty seconds later, so retries space out — and stop.
    #[test]
    fn assessment_retries_back_off_and_are_capped() {
        let now = util::parse_timestamp("2026-08-09T12:00:00Z").unwrap();

        // Never attempted: due immediately.
        assert!(retry_due(0, None, now));
        // Just attempted: not due again yet.
        assert!(!retry_due(1, Some("2026-08-09T11:58:00Z"), now));
        // Ten minutes on, a second attempt is due.
        assert!(retry_due(1, Some("2026-08-09T11:45:00Z"), now));
        // The wait grows, and stops growing at six hours.
        assert!(!retry_due(6, Some("2026-08-09T08:00:00Z"), now));
        assert!(retry_due(6, Some("2026-08-09T05:00:00Z"), now));
        // The documented ceiling is six hours, and the shift now
        // actually reaches it: `5 << 6` is 320 minutes, so the clamp at
        // 6 made `min(360)` dead code and the real ceiling 5h20m.
        assert!(!retry_due(9, Some("2026-08-09T06:30:00Z"), now), "5h30m is inside six hours");
        assert!(retry_due(9, Some("2026-08-09T05:30:00Z"), now), "6h30m is past it");

        // An unreadable timestamp does not wedge the case: it retries.
        assert!(retry_due(3, Some("not a timestamp"), now));
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
                expect_revision: None,
                expect_claim_revision: None,
                appeal_state: None,
                new_holder_state: None,
                extra_event: None,
            })
            .unwrap();

        assert_eq!(sweep_overdue(&state, now, stale_batch).await.unwrap(), 1);
        assert_eq!(state.store.case("c1").unwrap().unwrap().stage, "decided");
        assert_eq!(state.store.case("c2").unwrap().unwrap().stage, "decided");
    }
}
