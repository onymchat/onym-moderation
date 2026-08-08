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
                    store.record_delivery_failure(&queued.verdict_ref, &detail)?;
                }
                Attempt::Refused(detail) => {
                    let attempts = store.record_delivery_failure(&queued.verdict_ref, &detail)?;
                    if attempts >= MAX_REFUSALS {
                        store.mark_undeliverable(&queued.verdict_ref)?;
                        // Loud, and once. A verdict nobody will execute
                        // is a mark that should have moved and did not:
                        // for a dismissal, someone stays marked; for a
                        // ban, a sanction the authority believes it
                        // issued is not in force anywhere.
                        tracing::error!(
                            verdict_ref = %queued.verdict_ref,
                            %attempts,
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
