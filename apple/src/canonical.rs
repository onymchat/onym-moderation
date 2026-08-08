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
}
