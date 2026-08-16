//! The prerequisite classifier (Moderation-Device-Recall.md §5.2):
//! five conditions that must all hold before any recall value is
//! interpreted. Failure of any one is `checkRequired`, regardless of
//! what `values` contains — the evaluation rule is deliberately
//! stricter than testing whether the maps are empty.
//!
//! If all five pass, a present `deviceRecall` object with empty maps is
//! the profile's clean never-written state. Google exposes no separate
//! "recall evaluated" boolean, so a technically unavailable result that
//! satisfies every condition is indistinguishable from a clean device;
//! callers emit the `recall_empty_result` monitoring event for exactly
//! that residual ambiguity (§8 gap 6).

use crate::play_integrity::{Bits, DecodedVerdict};

/// Which prerequisite failed. The wire answer is uniformly
/// `checkRequired(tokenInvalid)`; the distinction exists for logs and
/// tests, not for callers to branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifierFailure {
    /// `requestDetails.timestampMillis` absent or outside the freshness
    /// window.
    RequestStale,
    /// `requestDetails.requestPackageName` is not the expected package.
    PackageMismatch,
    /// `requestDetails.requestHash` does not match the hash recomputed
    /// from the transmitted fields — the token was not minted for this
    /// request.
    RequestHashMismatch,
    /// `appRecognitionVerdict` is not `PLAY_RECOGNIZED`, or the app's
    /// package name disagrees.
    AppNotPlayRecognized,
    /// None of the signing-certificate digests is an expected one.
    CertDigestMismatch,
    /// `appLicensingVerdict` is not `LICENSED`.
    NotLicensed,
    /// `deviceRecognitionVerdict` lacks `MEETS_DEVICE_INTEGRITY`.
    DeviceIntegrityMissing,
    /// The `deviceIntegrity.deviceRecall` object is absent.
    DeviceRecallMissing,
}

impl ClassifierFailure {
    pub fn describe(self) -> &'static str {
        match self {
            ClassifierFailure::RequestStale => "request timestamp stale or absent",
            ClassifierFailure::PackageMismatch => "request package mismatch",
            ClassifierFailure::RequestHashMismatch => "requestHash mismatch",
            ClassifierFailure::AppNotPlayRecognized => "app not PLAY_RECOGNIZED",
            ClassifierFailure::CertDigestMismatch => "signing certificate digest mismatch",
            ClassifierFailure::NotLicensed => "account not LICENSED",
            ClassifierFailure::DeviceIntegrityMissing => "device lacks MEETS_DEVICE_INTEGRITY",
            ClassifierFailure::DeviceRecallMissing => "deviceRecall object absent",
        }
    }
}

/// What the deployment expects a trustworthy token to carry.
pub struct Expected<'a> {
    pub package_name: &'a str,
    /// Accepted signing-certificate SHA-256 digests, exactly as Google
    /// spells them in `certificateSha256Digest`.
    pub cert_sha256_digests: &'a [String],
    /// The `requestHash` this session's payload derives to.
    pub request_hash: &'a str,
    /// Now, in milliseconds since epoch.
    pub now_millis: i64,
    /// How old `timestampMillis` may be.
    pub max_age_millis: i64,
}

/// Run the five prerequisites in order; on success, interpret the
/// recall values into the profile's mark pair. `bit_third` is read but
/// deliberately ignored — it is reserved and outside `markBindings`.
pub fn classify(decoded: &DecodedVerdict, expected: &Expected) -> Result<Bits, ClassifierFailure> {
    // 1. Fresh, matching requestDetails — package, hash, timestamp.
    let details = &decoded.request_details;
    match details.timestamp_millis {
        Some(t)
            if t <= expected.now_millis + 60_000
                && expected.now_millis - t <= expected.max_age_millis => {}
        _ => return Err(ClassifierFailure::RequestStale),
    }
    if details.request_package_name.as_deref() != Some(expected.package_name) {
        return Err(ClassifierFailure::PackageMismatch);
    }
    if details.request_hash.as_deref() != Some(expected.request_hash) {
        return Err(ClassifierFailure::RequestHashMismatch);
    }

    // 2. PLAY_RECOGNIZED, with the expected package and cert digest.
    let app = &decoded.app_integrity;
    if app.app_recognition_verdict.as_deref() != Some("PLAY_RECOGNIZED")
        || app.package_name.as_deref() != Some(expected.package_name)
    {
        return Err(ClassifierFailure::AppNotPlayRecognized);
    }
    if !app
        .certificate_sha256_digest
        .iter()
        .any(|digest| expected.cert_sha256_digests.contains(digest))
    {
        return Err(ClassifierFailure::CertDigestMismatch);
    }

    // 3. LICENSED.
    if decoded.account_details.app_licensing_verdict.as_deref() != Some("LICENSED") {
        return Err(ClassifierFailure::NotLicensed);
    }

    // 4. MEETS_DEVICE_INTEGRITY.
    if !decoded
        .device_integrity
        .device_recognition_verdict
        .iter()
        .any(|v| v == "MEETS_DEVICE_INTEGRITY")
    {
        return Err(ClassifierFailure::DeviceIntegrityMissing);
    }

    // 5. The deviceRecall object itself.
    let Some(recall) = decoded.device_integrity.device_recall.as_ref() else {
        return Err(ClassifierFailure::DeviceRecallMissing);
    };

    // All five hold: absent bit fields are false, and empty maps are
    // the clean never-written state (subject to the disclosed §8
    // ambiguity — the caller's monitoring event, not a refusal).
    Ok(Bits {
        case_open: recall.values.bit_first,
        banned: recall.values.bit_second,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::play_integrity::DecodedVerdict;

    const NOW: i64 = 1_754_651_260_000;
    const MAX_AGE: i64 = 600_000;

    fn digests() -> Vec<String> {
        vec!["expected-digest".to_string()]
    }

    fn conforming_token() -> serde_json::Value {
        serde_json::json!({
            "requestDetails": {
                "requestPackageName": "app.onym.android",
                "requestHash": "expected-hash",
                "timestampMillis": (NOW - 5_000).to_string(),
            },
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": "app.onym.android",
                "certificateSha256Digest": ["expected-digest"],
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"],
                "deviceRecall": {"values": {}, "writeDates": {}},
            },
            "accountDetails": {"appLicensingVerdict": "LICENSED"},
        })
    }

    fn classify_value(value: serde_json::Value) -> Result<Bits, ClassifierFailure> {
        let decoded: DecodedVerdict = serde_json::from_value(value).unwrap();
        let digests = digests();
        classify(
            &decoded,
            &Expected {
                package_name: "app.onym.android",
                cert_sha256_digests: &digests,
                request_hash: "expected-hash",
                now_millis: NOW,
                max_age_millis: MAX_AGE,
            },
        )
    }

    /// The disclosed ambiguity: present-but-empty maps with every
    /// prerequisite passing is the clean never-written state.
    #[test]
    fn a_conforming_token_with_empty_recall_is_clean() {
        assert_eq!(classify_value(conforming_token()), Ok(Bits::default()));
    }

    #[test]
    fn populated_values_are_read_and_bit_third_is_ignored() {
        let mut token = conforming_token();
        token["deviceIntegrity"]["deviceRecall"]["values"] =
            serde_json::json!({"bitFirst": true, "bitSecond": true, "bitThird": true});
        assert_eq!(
            classify_value(token),
            Ok(Bits { case_open: true, banned: true })
        );
    }

    #[test]
    fn explicit_false_values_are_clean() {
        let mut token = conforming_token();
        token["deviceIntegrity"]["deviceRecall"]["values"] =
            serde_json::json!({"bitFirst": false, "bitSecond": false});
        assert_eq!(classify_value(token), Ok(Bits::default()));
    }

    // ─── Each prerequisite failed individually ───────────────────────

    #[test]
    fn a_stale_timestamp_fails() {
        let mut token = conforming_token();
        token["requestDetails"]["timestampMillis"] = (NOW - MAX_AGE - 1).to_string().into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::RequestStale));
    }

    #[test]
    fn a_future_timestamp_beyond_skew_fails() {
        let mut token = conforming_token();
        token["requestDetails"]["timestampMillis"] = (NOW + 120_000).to_string().into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::RequestStale));
    }

    #[test]
    fn a_missing_timestamp_fails() {
        let mut token = conforming_token();
        token["requestDetails"]
            .as_object_mut()
            .unwrap()
            .remove("timestampMillis");
        assert_eq!(classify_value(token), Err(ClassifierFailure::RequestStale));
    }

    #[test]
    fn a_wrong_request_package_fails() {
        let mut token = conforming_token();
        token["requestDetails"]["requestPackageName"] = "com.other.app".into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::PackageMismatch));
    }

    /// The freshness/binding core: a token minted for some other
    /// request must not authorize this one, whatever it carries.
    #[test]
    fn a_wrong_request_hash_fails() {
        let mut token = conforming_token();
        token["requestDetails"]["requestHash"] = "someone-elses-hash".into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::RequestHashMismatch));
    }

    #[test]
    fn an_unrecognized_app_fails_even_with_clean_values() {
        let mut token = conforming_token();
        token["appIntegrity"]["appRecognitionVerdict"] = "UNRECOGNIZED_VERSION".into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::AppNotPlayRecognized));
    }

    #[test]
    fn a_wrong_signing_certificate_fails() {
        let mut token = conforming_token();
        token["appIntegrity"]["certificateSha256Digest"] = serde_json::json!(["rogue-digest"]);
        assert_eq!(classify_value(token), Err(ClassifierFailure::CertDigestMismatch));
    }

    #[test]
    fn an_unlicensed_account_fails() {
        let mut token = conforming_token();
        token["accountDetails"]["appLicensingVerdict"] = "UNLICENSED".into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::NotLicensed));
    }

    #[test]
    fn a_device_without_integrity_fails() {
        let mut token = conforming_token();
        token["deviceIntegrity"]["deviceRecognitionVerdict"] =
            serde_json::json!(["MEETS_BASIC_INTEGRITY"]);
        assert_eq!(classify_value(token), Err(ClassifierFailure::DeviceIntegrityMissing));
    }

    /// A missing deviceRecall object is `checkRequired`, never clean —
    /// this is the boundary between the fail-closed rule and the
    /// disclosed empty-maps ambiguity above.
    #[test]
    fn a_missing_device_recall_object_fails() {
        let mut token = conforming_token();
        token["deviceIntegrity"].as_object_mut().unwrap().remove("deviceRecall");
        assert_eq!(classify_value(token), Err(ClassifierFailure::DeviceRecallMissing));
    }

    /// Marked values behind a failed prerequisite are never read: the
    /// failure wins, in both directions (no clean bypass, no phantom
    /// ban).
    #[test]
    fn values_behind_a_failed_prerequisite_are_not_interpreted() {
        let mut token = conforming_token();
        token["deviceIntegrity"]["deviceRecall"]["values"] = serde_json::json!({"bitSecond": true});
        token["accountDetails"]["appLicensingVerdict"] = "UNLICENSED".into();
        assert_eq!(classify_value(token), Err(ClassifierFailure::NotLicensed));
    }
}
