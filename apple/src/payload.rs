//! Reconstruction of the byte strings the user's identity key signs.
//!
//! These MUST match `SignedSessionPayload` in the iOS client
//! (`Packages/OnymModeration/.../EnforcementBackendClient.swift`)
//! byte-for-byte, or every signature check fails. The client builds
//! them from exactly the fields it transmits, which is what makes
//! verification here possible at all.
//!
//! Layout: for each field in order — context, device token (empty when
//! absent), user key, ISO 8601 timestamp, mandate ref (empty when
//! absent) — a big-endian `u32` length followed by the raw bytes.
//! Length prefixes make the concatenation injective, so no two
//! different field splits can collide, and the leading context string
//! domain-separates enrollment from gate-check so neither signature can
//! be replayed as the other.

pub const ENROLL_CONTEXT: &str = "onym-moderation-enroll-v1";
pub const GATE_CONTEXT: &str = "onym-moderation-gate-v1";
pub const RECOVER_CONTEXT: &str = "onym-moderation-recover-v1";

fn append(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn bytes(
    context: &str,
    device_token: Option<&[u8]>,
    user_key: &str,
    timestamp: &str,
    mandate_ref: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, context.as_bytes());
    append(&mut out, device_token.unwrap_or(&[]));
    append(&mut out, user_key.as_bytes());
    append(&mut out, timestamp.as_bytes());
    append(&mut out, mandate_ref.unwrap_or("").as_bytes());
    out
}

/// Signed bytes for `POST /v1/enroll`.
pub fn enrollment(device_token: Option<&[u8]>, user_key: &str, timestamp: &str) -> Vec<u8> {
    bytes(ENROLL_CONTEXT, device_token, user_key, timestamp, None)
}

/// Signed bytes for `POST /v1/gate-check`.
pub fn gate_check(
    device_token: Option<&[u8]>,
    user_key: &str,
    mandate_ref: Option<&str>,
    timestamp: &str,
) -> Vec<u8> {
    bytes(GATE_CONTEXT, device_token, user_key, timestamp, mandate_ref)
}

/// Signed bytes for `POST /v1/recover`. Same five-field layout as the
/// session payloads, with the case reference in the trailing slot the
/// others use for the mandate ref — the signature binds the claim to
/// one case, so it cannot be replayed to recover a different one.
pub fn recovery(
    device_token: Option<&[u8]>,
    user_key: &str,
    case_id: &str,
    timestamp: &str,
) -> Vec<u8> {
    bytes(RECOVER_CONTEXT, device_token, user_key, timestamp, Some(case_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_length_prefixed_big_endian() {
        let out = enrollment(Some(b"ab"), "k", "t");
        // context(25) + token(2) + userKey(1) + timestamp(1) + mandateRef(0),
        // each with a 4-byte prefix.
        assert_eq!(out.len(), 4 * 5 + ENROLL_CONTEXT.len() + 2 + 1 + 1);
        assert_eq!(&out[0..4], &(ENROLL_CONTEXT.len() as u32).to_be_bytes());
    }

    /// The property length-prefixing exists for: no two different field
    /// splits may produce the same bytes.
    #[test]
    fn field_boundaries_are_unambiguous() {
        assert_ne!(
            enrollment(Some(b"ab"), "c", "t"),
            enrollment(Some(b"a"), "bc", "t")
        );
    }

    #[test]
    fn enrollment_and_gate_payloads_are_domain_separated() {
        assert_ne!(enrollment(Some(b"t"), "u", "ts"), gate_check(Some(b"t"), "u", None, "ts"));
    }

    #[test]
    fn gate_payload_covers_mandate_ref() {
        assert_ne!(
            gate_check(None, "u", Some("mandate-a"), "ts"),
            gate_check(None, "u", Some("mandate-b"), "ts")
        );
    }

    /// An absent token must not be interchangeable with an empty one at
    /// the byte level — both encode as a zero-length field, which is
    /// intentional and matches the client.
    #[test]
    fn absent_and_empty_token_agree_with_the_client() {
        assert_eq!(enrollment(None, "u", "ts"), enrollment(Some(&[]), "u", "ts"));
    }

    // ─── Cross-implementation fixtures ───────────────────────────────
    //
    // These hex strings were produced by running the **iOS client's own
    // `SignedSessionPayload`** (lifted verbatim from
    // `Packages/OnymModeration/.../EnforcementBackendClient.swift`) over
    // the inputs below. They are the only thing standing between this
    // reimplementation and a silent drift that would reject every real
    // signature, so regenerate them from Swift — never by hand — if the
    // client's payload format ever changes.
    //
    //   timestamp "2026-08-08T12:00:00Z", token "device-token",
    //   userKey "onym:key:aabb", mandateRef "mandate-ref-1"

    const TS: &str = "2026-08-08T12:00:00Z";
    const USER_KEY: &str = "onym:key:aabb";
    const TOKEN: &[u8] = b"device-token";

    #[test]
    fn enrollment_matches_the_swift_client_byte_for_byte() {
        let expected = "000000196f6e796d2d6d6f6465726174696f6e2d656e726f6c6c2d76310000\
000c6465766963652d746f6b656e0000000d6f6e796d3a6b65793a616162620000\
0014323032362d30382d30385431323a30303a30305a00000000";
        assert_eq!(hex::encode(enrollment(Some(TOKEN), USER_KEY, TS)), expected.replace('\n', ""));
    }

    #[test]
    fn gate_check_matches_the_swift_client_byte_for_byte() {
        let expected = "000000176f6e796d2d6d6f6465726174696f6e2d676174652d76310000000c\
6465766963652d746f6b656e0000000d6f6e796d3a6b65793a6161626200000014\
323032362d30382d30385431323a30303a30305a0000000d6d616e646174652d72\
65662d31";
        assert_eq!(
            hex::encode(gate_check(Some(TOKEN), USER_KEY, Some("mandate-ref-1"), TS)),
            expected.replace('\n', "")
        );
    }

    /// The simulator / enterprise-build case: no token at all.
    #[test]
    fn gate_check_without_token_matches_the_swift_client() {
        let expected = "000000176f6e796d2d6d6f6465726174696f6e2d676174652d76310000000000\
00000d6f6e796d3a6b65793a6161626200000014323032362d30382d3038543132\
3a30303a30305a00000000";
        assert_eq!(
            hex::encode(gate_check(None, USER_KEY, None, TS)),
            expected.replace('\n', "")
        );
    }
}
