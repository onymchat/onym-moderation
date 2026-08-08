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

    /// Deliver one verdict. `Ok(false)` means "not delivered, try
    /// again" — the caller keeps it queued rather than treating the
    /// case as unresolved.
    pub async fn deliver(
        &self,
        raw_verdict: &[u8],
        consented_manifest: Option<&[u8]>,
    ) -> Result<bool, Error> {
        let Some(base_url) = self.base_url.as_deref() else {
            return Ok(false);
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
            Ok(response) if response.status().is_success() => Ok(true),
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                // A 4xx means the interface refused the verdict's
                // shape. Retrying identical bytes will not help, but
                // the mismatch is worth shouting about: one side of a
                // mutual check is wrong.
                tracing::error!(%status, %body, "interface refused a verdict");
                Ok(false)
            }
            Err(e) => {
                tracing::warn!(error = %e, "interface unreachable; verdict stays queued");
                Ok(false)
            }
        }
    }

    /// Drain the undelivered backlog.
    pub async fn flush(&self, store: &Store) -> Result<(), Error> {
        if !self.configured() {
            return Ok(());
        }
        for queued in store.undelivered_verdicts()? {
            if self.deliver(&queued.raw, queued.consented_manifest.as_deref()).await? {
                store.mark_delivered(&queued.verdict_ref)?;
                tracing::info!(verdict_ref = %queued.verdict_ref, "verdict delivered");
            }
        }
        Ok(())
    }
}
