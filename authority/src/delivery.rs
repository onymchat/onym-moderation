//! Delivering signed verdicts to the interface's enforcement backend.
//!
//! Delivery is deliberately decoupled from issuance. A verdict is
//! issued, signed, and stored whether or not the interface is
//! reachable; an undelivered verdict is a delivery problem, never an
//! undecided case. The retry loop drains the backlog, and the
//! interface's own queued-write rules take it from there.

use crate::error::Error;
use crate::store::Store;
use crate::types::VerdictSubmission;
use crate::util;

/// Push the delivery backlog without making the caller wait for it.
///
/// `flush` drains the *whole* queue at fifteen seconds a verdict, so
/// running it inline made a request take time proportional to the
/// backlog whenever the interface was down — and every request
/// re-attempted every stuck verdict, inflating their counts. The sweep
/// remains the reliable path; this only lets a fresh verdict leave
/// promptly when the interface is healthy.
///
/// **Single-flight, and re-armed.** Spawning one of these per report
/// and per decision moved the problem rather than solving it: with a
/// slow interface the tasks overlap, each drains the same backlog, and
/// the same verdicts are re-POSTed by several flushes at once —
/// inflating `attempts`, which is the number the refusal budget and the
/// operator both read.
///
/// So one background drain runs at a time. But a call arriving while
/// one is in flight cannot simply be dropped: `flush` snapshots the
/// backlog once, before its loop, so a verdict enqueued after that
/// snapshot is invisible to the drain already running. Dropping the
/// call would leave a fresh notice waiting for the sweep —
/// `deadline_sweep_secs` is 300 — on a *healthy* interface, which is
/// precisely the case this function exists to serve. The call instead
/// re-arms the running drain, which goes round again.
pub fn flush_soon(state: &std::sync::Arc<crate::state::AppState>) {
    use std::sync::atomic::Ordering;

    if state.delivery.flush_in_flight.swap(true, Ordering::AcqRel) {
        state.delivery.flush_again.store(true, Ordering::Release);
        return;
    }

    let state = std::sync::Arc::clone(state);
    tokio::spawn(async move {
        {
            let _gate = FlushGate(std::sync::Arc::clone(&state));
            loop {
                if let Err(e) = state.delivery.flush(&state.store).await {
                    tracing::warn!(
                        error = %e,
                        "background verdict delivery failed; the sweep will retry"
                    );
                }
                // Only set by a caller that found the gate closed, so
                // this loops when there is genuinely new work and never
                // spins on a backlog that is merely failing to drain.
                if !state.delivery.flush_again.swap(false, Ordering::AcqRel) {
                    break;
                }
            }
        }
        // The gate is down now. A call landing between the last check
        // and the drop set the flag with nobody left to read it, and
        // would otherwise wait for the sweep — so consume it and start
        // a fresh cycle. Terminates: the flag is only ever set by a
        // call that lost the gate.
        if state.delivery.flush_again.swap(false, Ordering::AcqRel) {
            flush_soon(&state);
        }
    });
}

/// Releases the single-flight gate however the drain ends.
///
/// A straight-line `store(false)` after the `.await` covered errors and
/// not panics, and the panic case is the one that matters: every
/// `Store` method takes `conn.lock().unwrap()`, so a single panic under
/// that lock poisons the mutex and *every* subsequent `flush` panics
/// too. `tokio::spawn` swallows the unwind into a `JoinError` nobody
/// reads, leaving the flag pinned true for the life of the process —
/// exactly the failure the straight-line release was written to
/// prevent, with exactly the symptom it predicted: verdicts leaving
/// only on the sweep's clock, looking like a slow interface.
struct FlushGate(std::sync::Arc<crate::state::AppState>);

impl Drop for FlushGate {
    fn drop(&mut self) {
        self.0
            .delivery
            .flush_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

#[derive(serde::Deserialize)]
struct InterfaceErrorBody {
    error: String,
}

/// What one delivery attempt came to.
pub enum Attempt {
    Delivered,
    /// Worth trying again: the interface was unreachable or unwell.
    Retry(String),
    /// The interface refused the verdict itself. Identical bytes will
    /// be refused identically.
    Refused(String),
}

/// How many refusals before a verdict is treated as undeliverable. A
/// few, not one: a 4xx can also come from a proxy in front of an
/// interface that is merely restarting.
const MAX_REFUSALS: i64 = 3;

fn truncate(value: &str) -> String {
    const LIMIT: usize = 300;
    if value.len() <= LIMIT {
        return value.to_string();
    }
    let mut end = LIMIT;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

pub struct Delivery {
    client: reqwest::Client,
    base_url: Option<String>,
    token: Option<String>,
    /// Base64 of the currently published manifest. A fallback only
    /// when those exact bytes still hash to the mandate's reference.
    published_manifest: String,
    published_manifest_hash: String,
    /// Whether a `flush_soon` task is already draining the backlog.
    /// The sweep's own `flush` is deliberately not gated by this — it
    /// is the reliable path and must run on its own clock.
    pub flush_in_flight: std::sync::atomic::AtomicBool,
    /// Set by a `flush_soon` call that found the gate closed. `flush`
    /// snapshots its backlog before its loop, so the drain in progress
    /// cannot see what that caller enqueued; this asks it to go round
    /// again rather than leaving the new verdict to the sweep.
    pub flush_again: std::sync::atomic::AtomicBool,
}

impl Delivery {
    pub fn new(base_url: Option<String>, token: Option<String>, manifest_raw: &[u8]) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url,
            token,
            published_manifest: util::base64_encode(manifest_raw),
            published_manifest_hash: util::sha256_hex(manifest_raw),
            flush_in_flight: std::sync::atomic::AtomicBool::new(false),
            flush_again: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn configured(&self) -> bool {
        self.base_url.is_some()
    }

    /// Deliver one verdict. `Ok(Retry)` means "not delivered, try
    /// again" — the caller keeps it queued rather than treating the
    /// case as unresolved. `Ok(Refused)` means the interface rejected
    /// the verdict's shape, which identical bytes will hit again.
    pub async fn deliver(
        &self,
        raw_verdict: &[u8],
        consented_manifest: Option<&[u8]>,
        mandate_manifest_hash: Option<&str>,
    ) -> Result<Attempt, Error> {
        let Some(base_url) = self.base_url.as_deref() else {
            return Ok(Attempt::Retry("no interface URL configured".into()));
        };
        let verdict: serde_json::Value = serde_json::from_slice(raw_verdict)
            .map_err(|e| Error::Internal(format!("stored verdict unparseable: {e}")))?;

        // The interface checks these bytes against the hash *this
        // user's mandate* pinned. Sending the currently published
        // manifest would make every verdict for a pre-republication
        // mandate fail that check — the sanction would silently never
        // execute, and the case would look decided from here.
        let consented_manifest = match consented_manifest {
            Some(raw) => util::base64_encode(raw),
            None if mandate_manifest_hash == Some(self.published_manifest_hash.as_str()) => {
                self.published_manifest.clone()
            }
            None => {
                return Ok(Attempt::Retry(
                    "consented manifest snapshot is missing and published bytes do not match"
                        .into(),
                ))
            }
        };
        let submission = VerdictSubmission {
            verdict,
            consented_manifest,
        };

        let mut request = self
            .client
            .post(format!("{}/v1/verdicts", base_url.trim_end_matches('/')))
            .json(&submission);
        if let Some(token) = self.token.as_deref() {
            request = request.bearer_auth(token);
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => Ok(Attempt::Delivered),
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let detail = format!("{status}: {}", truncate(&body));
                let attempt = classify_response(status, &body, detail);
                match &attempt {
                    Attempt::Refused(_) => {
                        tracing::error!(%status, %body, "interface permanently refused a verdict")
                    }
                    Attempt::Retry(_) => {
                        tracing::warn!(%status, %body, "interface temporarily refused delivery")
                    }
                    Attempt::Delivered => unreachable!(),
                }
                Ok(attempt)
            }
            Err(e) => {
                tracing::warn!(error = %e, "interface unreachable; verdict stays queued");
                Ok(Attempt::Retry(format!("unreachable: {e}")))
            }
        }
    }

    /// Drain the undelivered backlog.
    pub async fn flush(&self, store: &Store) -> Result<(), Error> {
        if !self.configured() {
            return Ok(());
        }
        for queued in store.undelivered_verdicts()? {
            match self
                .deliver(
                    &queued.raw,
                    queued.consented_manifest.as_deref(),
                    queued.manifest_hash.as_deref(),
                )
                .await?
            {
                Attempt::Delivered => {
                    store.mark_delivered(&queued.verdict_ref)?;
                    tracing::info!(verdict_ref = %queued.verdict_ref, "verdict delivered");
                }
                Attempt::Retry(detail) => {
                    // Counted, but not toward giving up: an unreachable
                    // interface is a different fault from one that
                    // rejects the verdict.
                    store.record_delivery_failure(&queued.verdict_ref, &detail, false)?;
                }
                Attempt::Refused(detail) => {
                    let refusals =
                        store.record_delivery_failure(&queued.verdict_ref, &detail, true)?;
                    if refusals >= MAX_REFUSALS {
                        store.mark_undeliverable(&queued.verdict_ref)?;
                        // Loud, and once. A verdict nobody will execute
                        // is a mark that should have moved and did not:
                        // for a dismissal, someone stays marked; for a
                        // ban, a sanction the authority believes it
                        // issued is not in force anywhere.
                        tracing::error!(
                            verdict_ref = %queued.verdict_ref,
                            %refusals,
                            error = %detail,
                            "giving up on delivering this verdict — the interface refuses its \
                             shape. It is now stuck rather than retrying: the mark it authorizes \
                             will not move until this is fixed and it is requeued."
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Only structured verdict/content errors are permanent. Authentication
/// failures, rate limits, missing state, proxy responses, and unknown
/// client errors are repairable operational conditions and stay queued.
fn classify_response(status: reqwest::StatusCode, body: &str, detail: String) -> Attempt {
    let code = serde_json::from_str::<InterfaceErrorBody>(body)
        .ok()
        .map(|body| body.error);
    let permanent = status.is_client_error()
        && matches!(
            code.as_deref(),
            Some("bad_request" | "verdict_invalid" | "class_outside_mandate")
        );
    if permanent {
        Attempt::Refused(detail)
    } else {
        Attempt::Retry(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CaseRecord, Decision, Store};

    /// One verdict queued for delivery.
    fn queued(store: &Store, verdict_ref: &str) {
        let case = CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
        };
        store.put_case(&case).unwrap();
        let mut decided = case.clone();
        decided.stage = "decided".into();
        decided.disposition = Some("dismiss".into());
        store
            .commit_decision(&Decision {
                case: &decided,
                verdict_ref,
                disposition: "dismiss",
                raw: b"{}",
                at: "2026-08-05T00:00:00Z",
                event_kind: "decided",
                event_detail: "dismiss",
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
    }

    /// The bug this separation exists to prevent. An interface down for
    /// a few sweeps must not make the next refusal the last straw —
    /// counting both against one threshold meant the "a few, not one"
    /// rationale was defeated by ordinary downtime.
    #[test]
    fn unreachability_does_not_count_toward_giving_up() {
        let store = Store::in_memory().unwrap();
        queued(&store, "v1");

        for _ in 0..10 {
            let refusals = store.record_delivery_failure("v1", "unreachable: connection refused", false).unwrap();
            assert_eq!(refusals, 0, "an unreachable interface has refused nothing");
        }
        assert!(store.undeliverable_verdicts().unwrap().is_empty());
        assert_eq!(store.undelivered_verdicts().unwrap().len(), 1, "still queued, still retried");

        // Refusals are what count, and it takes more than one.
        assert_eq!(store.record_delivery_failure("v1", "400: bad shape", true).unwrap(), 1);
        assert_eq!(store.record_delivery_failure("v1", "400: bad shape", true).unwrap(), 2);
        const _: () = assert!(MAX_REFUSALS > 1, "the threshold is more than one refusal");
    }

    /// A verdict given up on is not deleted and not treated as
    /// delivered: it is a mark that should have moved and did not, and
    /// it has to stay visible as exactly that.
    #[test]
    fn an_undeliverable_verdict_stays_visible_and_stops_being_retried() {
        let store = Store::in_memory().unwrap();
        queued(&store, "v1");

        for _ in 0..MAX_REFUSALS {
            store.record_delivery_failure("v1", "422: unknown field", true).unwrap();
        }
        store.mark_undeliverable("v1").unwrap();

        assert!(store.undelivered_verdicts().unwrap().is_empty(), "no longer retried");
        let stuck = store.undeliverable_verdicts().unwrap();
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].0, "v1");
        assert!(stuck[0].1.contains("422"), "the interface's own words are kept: {:?}", stuck[0].1);

        assert!(store.requeue_verdict("v1").unwrap());
        assert!(store.undeliverable_verdicts().unwrap().is_empty());
        assert_eq!(store.undelivered_verdicts().unwrap().len(), 1);
        assert!(!store.requeue_verdict("v1").unwrap(), "an already queued verdict is unchanged");
    }

    /// A delivery that succeeds after earlier trouble clears the error
    /// rather than leaving a stale one on a healthy verdict.
    #[test]
    fn delivering_clears_the_last_error() {
        let store = Store::in_memory().unwrap();
        queued(&store, "v1");
        store.record_delivery_failure("v1", "unreachable", false).unwrap();
        store.mark_delivered("v1").unwrap();

        assert!(store.undelivered_verdicts().unwrap().is_empty());
        assert!(store.undeliverable_verdicts().unwrap().is_empty());
    }

    /// Status alone cannot say whether retrying helps: authentication,
    /// rate limits, and missing interface state are all 4xx responses.
    #[test]
    fn only_structured_permanent_errors_count_as_refusals() {
        assert!(matches!(classify(400, "verdict_invalid"), Attempt::Refused(_)));
        assert!(matches!(classify(400, "class_outside_mandate"), Attempt::Refused(_)));
        assert!(matches!(classify(401, "signature_invalid"), Attempt::Retry(_)));
        assert!(matches!(classify(429, "rate_limited"), Attempt::Retry(_)));
        assert!(matches!(classify(400, "no_mandate"), Attempt::Retry(_)));
        assert!(matches!(classify(425, "verdict_not_yet_valid"), Attempt::Retry(_)));
        assert!(matches!(classify(404, "not_found"), Attempt::Retry(_)));
        assert!(matches!(classify(500, "internal_error"), Attempt::Retry(_)));
    }

    fn classify(status: u16, code: &str) -> Attempt {
        let status = reqwest::StatusCode::from_u16(status).unwrap();
        classify_response(
            status,
            &serde_json::json!({ "error": code }).to_string(),
            status.to_string(),
        )
    }
}
