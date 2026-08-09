//! Canonical signing bytes.
//!
//! Deliberately a copy of `apple/src/canonical.rs` rather than a shared
//! crate: the two services are owned by *different operators* in the
//! contract, and a reference implementation that made them share a
//! library would quietly suggest they may. They must agree on bytes,
//! not on code — so the agreement is pinned by the identical fixtures
//! in both test modules, which fail if either side drifts.
//!
//! Encode, drop the signature field(s) **structurally**, re-serialize
//! with sorted keys. Removing a signature by string surgery is
//! forgeable: an attacker can plant extra copies of a known signature
//! elsewhere in the document so that removing every occurrence
//! reconstructs the signed bytes while decoding different content.
//!
//! `serde_json::Value` uses a `BTreeMap` for objects, so serialization
//! is key-sorted, matching Swift's `.sortedKeys`; serde_json also does
//! not escape `/`, matching `.withoutEscapingSlashes`.

use serde_json::Value;

use crate::error::Error;

pub fn canonical_bytes(raw: &[u8], omit: &[&str]) -> Result<Vec<u8>, Error> {
    let mut value: Value =
        serde_json::from_slice(raw).map_err(|e| Error::BadRequest(format!("malformed JSON: {e}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::BadRequest("expected a JSON object".into()))?;
    for key in omit {
        object.remove(*key);
    }
    serde_json::to_vec(&value).map_err(|e| Error::Internal(format!("re-serialize: {e}")))
}

/// The bytes a user signs for a mandate (and the interface
/// countersigns): every field except `signatures`.
pub fn mandate_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signatures"])
}

/// The bytes this authority signs for a verdict: every field except
/// `signature`.
pub fn verdict_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signature"])
}

/// The bytes a reporter signs for a report, and the accused for a
/// response or appeal.
pub fn report_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signature"])
}

/// The bytes this authority signs for a recovery grant, and a claimant
/// for a recovery claim: every field except `signature`. Must stay
/// byte-identical to `grant_signing_bytes` in `apple/src/canonical.rs`
/// — the interface reconstructs them to verify the grant and to derive
/// its single-use reference.
pub fn grant_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signature"])
}

#[cfg(test)]
mod tests {
    use super::*;

    // These four cases are byte-identical to the ones in
    // `apple/src/canonical.rs`. If either implementation drifts, the
    // pair stops agreeing and one of these fails.

    #[test]
    fn drops_the_named_field_and_sorts_keys() {
        let raw = br#"{"b":2,"signatures":["x"],"a":1}"#;
        let out = mandate_signing_bytes(raw).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn signature_text_inside_another_field_survives() {
        let raw = br#"{"reasoning":"hash:SIG","signature":"SIG"}"#;
        let out = verdict_signing_bytes(raw).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"reasoning":"hash:SIG"}"#);
    }

    #[test]
    fn is_stable_across_input_key_order() {
        let one = mandate_signing_bytes(br#"{"a":1,"b":2}"#).unwrap();
        let two = mandate_signing_bytes(br#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn does_not_escape_slashes() {
        let out = mandate_signing_bytes(br#"{"a":"https://x/y"}"#).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":"https://x/y"}"#);
    }

    /// Keys sort by **UTF-8 byte order**, so an uppercase letter sorts
    /// before any lowercase one.
    ///
    /// This is not incidental. Foundation has two `.sortedKeys`
    /// implementations that disagree: `JSONEncoder` sorts by byte
    /// order (matching this), while `JSONSerialization` sorts
    /// case-insensitively. The `Report` object is the one boundary
    /// type whose keys actually collide under that difference —
    /// `reportId` and `reportVersion` sort before `reporter` by byte
    /// order but after it case-insensitively — so a client whose
    /// canonicalization ends in `JSONSerialization` produces report
    /// bytes this service cannot reproduce, and every report signature
    /// fails. `mandate`, `verdict`, and `notice` happen to sort
    /// identically under both rules, which is why the interface
    /// interoperates today.
    #[test]
    fn keys_sort_by_utf8_byte_order_not_case_insensitively() {
        let raw = br#"{"reporter":1,"reportId":2,"reportVersion":3}"#;
        let out = report_signing_bytes(raw).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"reportId":2,"reportVersion":3,"reporter":1}"#
        );
    }

    /// The same rule, stated at its sharpest: uppercase before
    /// lowercase.
    #[test]
    fn uppercase_sorts_before_lowercase() {
        let out = report_signing_bytes(br#"{"apple":1,"Zebra":2}"#).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"Zebra":2,"apple":1}"#);
    }
}
