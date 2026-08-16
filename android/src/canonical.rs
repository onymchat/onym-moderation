//! Canonical signing bytes for mandates and verdicts.
//!
//! Mirrors `SigningBytes.canonical` in the iOS client: encode, drop the
//! signature field(s) **structurally**, re-serialize with sorted keys.
//! Removing the signature by string surgery is forgeable — an attacker
//! can plant extra copies of a known signature string elsewhere in the
//! document so that removing every occurrence reconstructs the signed
//! bytes while decoding different content.
//!
//! `serde_json::Value` uses a `BTreeMap` for objects (the `preserve_order`
//! feature is off), so serialization is key-sorted, matching Swift's
//! `.sortedKeys`. Swift also passes `.withoutEscapingSlashes`, which
//! matches serde_json's default of not escaping `/`.
//!
//! PROVISIONAL, exactly as on the client: the draft spec fixes no
//! canonical JSON form, so this agreement is by construction between
//! these two implementations rather than by specification.
//!
//! The fixtures in the test module below are byte-identical to the ones
//! in `authority/src/canonical.rs`. That is the whole mechanism: the
//! two services are owned by different operators in the contract, so
//! they must agree on bytes rather than share a library, and the
//! fixtures are what fails if either side drifts. A case pinned on one
//! side only pins nothing.

use serde_json::Value;

use crate::error::Error;

/// Re-serialize `raw` (a JSON object) with `omit` removed at the top
/// level and keys sorted.
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

/// The bytes a user signs for a mandate, and that the interface
/// countersigns: every field except `signatures`.
pub fn mandate_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signatures"])
}

/// The bytes an authority signs for a verdict: every field except
/// `signature`.
pub fn verdict_signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signature"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_the_named_field_and_sorts_keys() {
        let raw = br#"{"b":2,"signatures":["x"],"a":1}"#;
        let out = mandate_signing_bytes(raw).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"b":2}"#);
    }

    /// The property string-surgery removal lacked: a signature value
    /// appearing inside another field must survive intact.
    #[test]
    fn signature_text_inside_another_field_survives() {
        let raw = br#"{"reasoning":"hash:SIG","signature":"SIG"}"#;
        let out = verdict_signing_bytes(raw).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"reasoning":"hash:SIG"}"#
        );
    }

    #[test]
    fn is_stable_across_input_key_order() {
        let one = mandate_signing_bytes(br#"{"a":1,"b":2}"#).unwrap();
        let two = mandate_signing_bytes(br#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn does_not_escape_slashes() {
        // Swift encodes with `.withoutEscapingSlashes`; serde_json
        // agrees by default. A mismatch here would break every
        // signature over a URL-bearing field.
        let out = mandate_signing_bytes(br#"{"a":"https://x/y"}"#).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":"https://x/y"}"#);
    }

    /// Keys sort by **UTF-8 byte order**, so an uppercase letter sorts
    /// before any lowercase one.
    ///
    /// This is not incidental. Foundation has two `.sortedKeys`
    /// implementations that disagree: `JSONEncoder` sorts by byte order
    /// (matching this), while `JSONSerialization` sorts
    /// case-insensitively. The `Report` object is the one boundary type
    /// whose keys actually collide under that difference —
    /// `reportId` and `reportVersion` sort before `reporter` by byte
    /// order but after it case-insensitively.
    ///
    /// Reports are signed to the authority, not to this service, so the
    /// fixture uses `canonical_bytes` with the same omit list rather
    /// than a `report_signing_bytes` this side has no use for. The
    /// bytes are the point, and they are identical to the pair in
    /// `authority/src/canonical.rs` — which is what the module's
    /// "agree on bytes, not code" claim requires, and what it did not
    /// have while these two cases lived on one side only.
    #[test]
    fn keys_sort_by_utf8_byte_order_not_case_insensitively() {
        let raw = br#"{"reporter":1,"reportId":2,"reportVersion":3}"#;
        let out = canonical_bytes(raw, &["signature"]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"reportId":2,"reportVersion":3,"reporter":1}"#
        );
    }

    /// The same rule, stated at its sharpest: uppercase before
    /// lowercase.
    #[test]
    fn uppercase_sorts_before_lowercase() {
        let out = canonical_bytes(br#"{"apple":1,"Zebra":2}"#, &["signature"]).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"Zebra":2,"apple":1}"#);
    }
}
