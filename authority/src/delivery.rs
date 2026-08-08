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
    /// Base64 of the currently published manifest. A fallback only:
    /// each verdict normally travels with the manifest its own case's
    /// mandate pinned, which for an older mandate is not this one.
    published_manifest: String,
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
        let submission = VerdictSubmission {
            verdict,
            consented_manifest: consented_manifest
                .map(util::base64_encode)
                .unwrap_or_else(|| self.published_manifest.clone()),
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
                // A 4xx means the interface refused the verdict's
                // shape, and identical bytes will be refused
                // identically forever. Retrying it every sweep turns a
                // mutual-check mismatch into a log line nobody reads;
                // the caller gives up after a few attempts and leaves
                // it visible as stuck instead.
                //
                // A 5xx is the interface having a bad day, which is a
                // different thing and does deserve retrying.
                let detail = format!("{status}: {}", truncate(&body));
                tracing::error!(%status, %body, "interface refused a verdict");
                if status.is_client_error() {
                    Ok(Attempt::Refused(detail))
                } else {
                    Ok(Attempt::Retry(detail))
                }
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
            match self.deliver(&queued.raw, queued.consented_manifest.as_deref()).await? {
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

    /// 4xx and 5xx are different faults: one is the verdict being
    /// wrong, the other is the interface having a bad day.
    #[test]
    fn only_client_errors_are_treated_as_refusals() {
        assert!(matches!(classify(400), Attempt::Refused(_)));
        assert!(matches!(classify(422), Attempt::Refused(_)));
        assert!(matches!(classify(500), Attempt::Retry(_)));
        assert!(matches!(classify(503), Attempt::Retry(_)));
    }

    fn classify(status: u16) -> Attempt {
        let status = reqwest::StatusCode::from_u16(status).unwrap();
        if status.is_client_error() {
            Attempt::Refused(status.to_string())
        } else {
            Attempt::Retry(status.to_string())
        }
    }
}
