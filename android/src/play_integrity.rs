//! Google Play Integrity client — decoding integrity tokens and
//! writing the three per-device recall values, scoped to the vendor's
//! Play developer account (Moderation-Device-Recall.md §1).
//!
//! `bitFirst` = `case-open`, `bitSecond` = `banned`, `bitThird` is
//! reserved and **never written** — `RecallChanges` has no field for it,
//! so the requirement is unrepresentable rather than merely checked.
//!
//! This module is the *only* place that can reach `deviceRecall:write`.
//! Callers are the verdict-execution and reconciliation paths and
//! nothing else — no administrative tool, support desk, or
//! store-pressure path (profile §4 requirement 1). Every write is
//! logged by the caller against the verdict hash that authorized it.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::google_auth::GoogleAuth;

pub const PRODUCTION_BASE_URL: &str = "https://playintegrity.googleapis.com";

/// The mark pair as this profile interprets it. "Never written" — a
/// device whose recall values were never set — is the clean state, not
/// an error (profile §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bits {
    pub case_open: bool,
    pub banned: bool,
}

/// The values a write actually changes. `None` = unspecified, which
/// Google leaves unchanged — required by profile §4 requirement 3.
/// There is deliberately no `bit_third`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_first: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_second: Option<bool>,
}

impl RecallChanges {
    /// The fields where `intended` differs from what the token carried.
    pub fn diff(current: Bits, intended: Bits) -> Self {
        Self {
            bit_first: (current.case_open != intended.case_open).then_some(intended.case_open),
            bit_second: (current.banned != intended.banned).then_some(intended.banned),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bit_first.is_none() && self.bit_second.is_none()
    }
}

// ─── Decoded verdict (tokenPayloadExternal) ──────────────────────────
//
// Every field is default-tolerant: the classifier decides what a
// missing field means, not the deserializer.

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetails {
    #[serde(default)]
    pub request_package_name: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
    /// Milliseconds since epoch. Google's JSON encodes int64 as a
    /// string; tolerate both spellings.
    #[serde(default, deserialize_with = "flexible_millis")]
    pub timestamp_millis: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIntegrity {
    #[serde(default)]
    pub app_recognition_verdict: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub certificate_sha256_digest: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallValues {
    #[serde(default)]
    pub bit_first: bool,
    #[serde(default)]
    pub bit_second: bool,
    /// Deserialized for wire completeness, deliberately never read:
    /// the value is reserved and outside this profile's markBindings.
    #[serde(default)]
    #[allow(dead_code)]
    pub bit_third: bool,
}

/// `yyyymm*` fields are month-and-year consistency signals, never an
/// authorization, execution, or expiry source (profile §4 req 4).
/// Retained for the write log's benefit.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallWriteDates {
    #[serde(default)]
    pub yyyymm_first: Option<i64>,
    #[serde(default)]
    pub yyyymm_second: Option<i64>,
    #[serde(default)]
    pub yyyymm_third: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecall {
    #[serde(default)]
    pub values: RecallValues,
    #[serde(default)]
    pub write_dates: RecallWriteDates,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrity {
    #[serde(default)]
    pub device_recognition_verdict: Vec<String>,
    /// `None` when device recall is unavailable or not enabled — the
    /// classifier fails that closed.
    #[serde(default)]
    pub device_recall: Option<DeviceRecall>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDetails {
    #[serde(default)]
    pub app_licensing_verdict: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedVerdict {
    #[serde(default)]
    pub request_details: RequestDetails,
    #[serde(default)]
    pub app_integrity: AppIntegrity,
    #[serde(default)]
    pub device_integrity: DeviceIntegrity,
    #[serde(default)]
    pub account_details: AccountDetails,
}

fn flexible_millis<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(i64),
        Text(String),
    }
    Ok(match Option::<Raw>::deserialize(deserializer)? {
        None => None,
        Some(Raw::Number(n)) => Some(n),
        Some(Raw::Text(s)) => s.parse().ok(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecodeResponse {
    #[serde(default)]
    token_payload_external: Option<DecodedVerdict>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeBody<'a> {
    integrity_token: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteBody<'a> {
    integrity_token: &'a str,
    // NOTE: `newValues` is drawn from the device-recall documentation;
    // Google offers no sandbox for recall writes, so the exact field
    // name must be re-verified against the live API at first deploy
    // (plan risk #3).
    new_values: RecallChanges,
}

pub struct PlayIntegrity {
    client: reqwest::Client,
    auth: GoogleAuth,
    base_url: String,
    package_name: String,
}

impl PlayIntegrity {
    pub fn new(auth: GoogleAuth, package_name: String) -> Result<Self, String> {
        Self::with_base_url(auth, package_name, PRODUCTION_BASE_URL.to_string())
    }

    /// A client aimed elsewhere — the test stand-in for Google's API.
    pub fn with_base_url(
        auth: GoogleAuth,
        package_name: String,
        base_url: String,
    ) -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|e| format!("http client: {e}"))?,
            auth,
            base_url,
            package_name,
        })
    }

    /// Decode an integrity token through Google. `Ok(None)` means
    /// Google rejected the *token* (malformed, expired, replayed) — the
    /// caller must treat that as "no trustworthy answer", never as
    /// clean. Answering `clear` to an unverifiable token would let
    /// anyone bypass the gate by sending garbage.
    pub async fn decode(&self, integrity_token: &str) -> Result<Option<DecodedVerdict>, Error> {
        let bearer = self.auth.access_token().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/{}:decodeIntegrityToken",
                self.base_url, self.package_name
            ))
            .bearer_auth(bearer)
            .json(&DecodeBody { integrity_token })
            .send()
            .await
            .map_err(|e| Error::MarkWriteFailed(format!("decodeIntegrityToken unreachable: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if status.is_success() {
            let parsed: DecodeResponse = serde_json::from_str(&text).map_err(|e| {
                Error::Internal(format!("decodeIntegrityToken: unparseable body: {e}"))
            })?;
            return Ok(Some(parsed.token_payload_external.unwrap_or_default()));
        }
        if status.is_client_error() {
            tracing::warn!(%status, body = %text, "Google rejected the integrity token");
            return Ok(None);
        }
        Err(Error::MarkWriteFailed(format!(
            "decodeIntegrityToken failed: {status} {text}"
        )))
    }

    /// Write the changed recall values. Only the verdict-execution and
    /// reconciliation paths may call this. The write is authorized by a
    /// verified token from the target device's own session (profile
    /// §6.2); `changes` carries only the values this transition moves.
    pub async fn write_recall(
        &self,
        integrity_token: &str,
        changes: RecallChanges,
    ) -> Result<(), Error> {
        let bearer = self.auth.access_token().await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/{}/deviceRecall:write",
                self.base_url, self.package_name
            ))
            .bearer_auth(bearer)
            .json(&WriteBody { integrity_token, new_values: changes })
            .send()
            .await
            .map_err(|e| Error::MarkWriteFailed(format!("deviceRecall:write unreachable: {e}")))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        Err(Error::MarkWriteFailed(format!(
            "deviceRecall:write failed: {status} {text}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_body_never_names_bit_third_and_omits_unchanged_values() {
        let body = serde_json::to_string(&WriteBody {
            integrity_token: "token",
            new_values: RecallChanges { bit_first: None, bit_second: Some(true) },
        })
        .unwrap();
        assert!(!body.contains("bitThird"), "{body}");
        assert!(!body.contains("bitFirst"), "unchanged values must be omitted: {body}");
        assert!(body.contains("\"bitSecond\":true"), "{body}");
    }

    #[test]
    fn diff_specifies_only_what_changes() {
        let current = Bits { case_open: true, banned: false };
        let intended = Bits { case_open: true, banned: true };
        let changes = RecallChanges::diff(current, intended);
        assert_eq!(changes.bit_first, None);
        assert_eq!(changes.bit_second, Some(true));
        assert!(RecallChanges::diff(current, current).is_empty());
    }

    #[test]
    fn decoded_verdict_reads_googles_field_spellings() {
        // timestampMillis arrives as a string (Google's int64-in-JSON),
        // and deviceRecall may be entirely absent.
        let verdict: DecodedVerdict = serde_json::from_value(serde_json::json!({
            "requestDetails": {
                "requestPackageName": "app.onym.android",
                "requestHash": "aGFzaA",
                "timestampMillis": "1754651200000",
            },
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": "app.onym.android",
                "certificateSha256Digest": ["6a6a"],
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                "deviceRecall": {
                    "values": {"bitFirst": true},
                    "writeDates": {"yyyymmFirst": 202608},
                },
            },
            "accountDetails": {"appLicensingVerdict": "LICENSED"},
        }))
        .unwrap();
        assert_eq!(verdict.request_details.timestamp_millis, Some(1754651200000));
        let recall = verdict.device_integrity.device_recall.unwrap();
        assert!(recall.values.bit_first);
        assert!(!recall.values.bit_second);
        assert_eq!(recall.write_dates.yyyymm_first, Some(202608));
    }

    #[test]
    fn an_absent_device_recall_object_stays_absent() {
        let verdict: DecodedVerdict = serde_json::from_value(serde_json::json!({
            "requestDetails": {},
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        }))
        .unwrap();
        assert!(verdict.device_integrity.device_recall.is_none());
    }
}
