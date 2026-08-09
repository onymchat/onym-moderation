//! Apple DeviceCheck client — the two per-device bits, scoped to the
//! vendor's Apple developer account (Moderation-DeviceCheck.md §1).
//!
//! `bit0` = `case-open`, `bit1` = `banned`.
//!
//! This module is the *only* place that can reach `update_two_bits`.
//! Callers are the verdict-execution and reconciliation paths and
//! nothing else — no administrative tool, support desk, or
//! store-pressure path (profile §4 requirement 1). Every write is
//! logged by the caller against the verdict hash that authorized it.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Apple's two environments. A token minted by a development build is
/// only valid against the development endpoint, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}

impl Environment {
    fn host(self) -> &'static str {
        match self {
            Environment::Production => "https://api.devicecheck.apple.com",
            Environment::Development => "https://api.development.devicecheck.apple.com",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "production" => Ok(Environment::Production),
            "development" => Ok(Environment::Development),
            other => Err(format!(
                "unknown DeviceCheck environment {other:?} (expected production|development)"
            )),
        }
    }
}

/// The bit pair as Apple reports it. "Not found" — a device whose bits
/// were never written — is the clean state, not an error (profile §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bits {
    pub case_open: bool,
    pub banned: bool,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    bit0: bool,
    #[serde(default)]
    bit1: bool,
    /// `YYYY-MM` — a consistency check only, never an authorization or
    /// expiry source (profile §4 requirement 3). Retained for the
    /// write log's benefit.
    #[serde(default)]
    last_update_time: Option<String>,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct QueryBody<'a> {
    device_token: &'a str,
    transaction_id: String,
    timestamp: u128,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct UpdateBody<'a> {
    device_token: &'a str,
    transaction_id: String,
    timestamp: u128,
    bit0: bool,
    bit1: bool,
}

pub struct DeviceCheck {
    client: reqwest::Client,
    encoding_key: EncodingKey,
    key_id: String,
    team_id: String,
    base_url: String,
}

impl DeviceCheck {
    /// `p8_pem` is the contents of the `AuthKey_<keyId>.p8` downloaded
    /// from the Apple developer portal (a PKCS#8 EC private key).
    pub fn new(
        p8_pem: &[u8],
        key_id: String,
        team_id: String,
        environment: Environment,
    ) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_ec_pem(p8_pem)
            .map_err(|e| format!("DeviceCheck key is not a usable EC private key: {e}"))?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|e| format!("http client: {e}"))?,
            encoding_key,
            key_id,
            team_id,
            base_url: environment.host().to_string(),
        })
    }

    /// A client aimed at a local stand-in for Apple's API. The key is
    /// a throwaway generated for the fixture — it signs bearer tokens
    /// nothing verifies. Test builds only.
    #[cfg(test)]
    pub(crate) fn for_tests(base_url: String) -> Self {
        const TEST_ONLY_EC_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPC+5ufSkeZJWHsVf
gW9U1RIbpSIrKIGPXtZQA3DFiCehRANCAAQrk0U30JpQ6sV4PjMPJXFh5+cUevmQ
7sDoERfT71/j755DGo0x2PU/9HE2AQE2z6FtLqPng3mgknhrffXMFe07
-----END PRIVATE KEY-----";
        Self {
            client: reqwest::Client::new(),
            encoding_key: EncodingKey::from_ec_pem(TEST_ONLY_EC_KEY)
                .expect("fixture key parses"),
            key_id: "test-key".into(),
            team_id: "test-team".into(),
            base_url,
        }
    }

    /// ES256 JWT, re-minted per call. Apple accepts tokens for a
    /// limited window; minting fresh avoids caching an expiry we would
    /// then have to manage.
    fn bearer(&self) -> Result<String, Error> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = Claims {
            iss: self.team_id.clone(),
            iat: now_secs(),
        };
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| Error::Internal(format!("DeviceCheck JWT: {e}")))
    }

    /// Read the bits. `Ok(None)` means Apple could not validate the
    /// token (expired, wrong environment, replayed) — the caller must
    /// treat that as "no trustworthy answer", never as clean.
    pub async fn query(&self, device_token: &str) -> Result<Option<Bits>, Error> {
        let body = QueryBody {
            device_token,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_millis(),
        };
        let response = self
            .client
            .post(format!("{}/v1/query_two_bits", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::MarkWriteFailed(format!("query_two_bits unreachable: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if status.is_success() {
            // Apple answers 200 with a plain-text body when the device
            // has no bit state yet. That is the clean state.
            if text.trim().is_empty() || text.contains("Failed to find bit state") {
                return Ok(Some(Bits::default()));
            }
            let parsed: QueryResponse = serde_json::from_str(&text).map_err(|e| {
                Error::Internal(format!("query_two_bits: unparseable body {text:?}: {e}"))
            })?;
            let _ = parsed.last_update_time;
            return Ok(Some(Bits {
                case_open: parsed.bit0,
                banned: parsed.bit1,
            }));
        }

        // 400/401 here means the *token* was rejected, not that the
        // device is clean. Distinguishing this is the whole point:
        // answering `clear` to an unverifiable token would let anyone
        // bypass the gate by sending garbage.
        if status.as_u16() == 400 || status.as_u16() == 401 {
            tracing::warn!(%status, body = %text, "DeviceCheck rejected the device token");
            return Ok(None);
        }
        Err(Error::MarkWriteFailed(format!(
            "query_two_bits failed: {status} {text}"
        )))
    }

    /// Write the bits. Only the verdict-execution and reconciliation
    /// paths may call this.
    pub async fn update(&self, device_token: &str, bits: Bits) -> Result<(), Error> {
        let body = UpdateBody {
            device_token,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_millis(),
            bit0: bits.case_open,
            bit1: bits.banned,
        };
        let response = self
            .client
            .post(format!("{}/v1/update_two_bits", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::MarkWriteFailed(format!("update_two_bits unreachable: {e}")))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        Err(Error::MarkWriteFailed(format!(
            "update_two_bits failed: {status} {text}"
        )))
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
