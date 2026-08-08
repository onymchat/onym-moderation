//! Small shared helpers: timestamps in the client's ISO 8601 form,
//! the spec's `onym:key:` references, base64, and hashing.

use base64::Engine;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Parse a timestamp as the iOS client writes it. The client uses
/// `ISO8601DateFormatter` with `.withInternetDateTime` (no fractional
/// seconds), which is RFC 3339; accepting the wider RFC 3339 grammar
/// here is deliberate, so an authority emitting fractional seconds
/// isn't rejected over formatting.
pub fn parse_timestamp(raw: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|e| format!("not an RFC 3339 timestamp: {e}"))
}

/// Format in the same shape the client emits (UTC, second precision).
pub fn format_timestamp(value: OffsetDateTime) -> String {
    let utc = value.to_offset(time::UtcOffset::UTC).replace_nanosecond(0).unwrap_or(value);
    utc.format(&Rfc3339).unwrap_or_default()
}

/// Whole days from the spec's `P<n>D` duration subset — the only form
/// manifest windows use.
pub fn parse_days(raw: &str) -> Result<i64, String> {
    let inner = raw
        .strip_prefix('P')
        .and_then(|s| s.strip_suffix('D'))
        .ok_or_else(|| format!("{raw:?} is not a P<n>D duration"))?;
    let days: i64 = inner
        .parse()
        .map_err(|_| format!("{raw:?} is not a P<n>D duration"))?;
    if days <= 0 {
        return Err(format!("{raw:?} must be a positive number of days"));
    }
    Ok(days)
}

pub const KEY_REFERENCE_PREFIX: &str = "onym:key:";

/// Raw key bytes from `onym:key:<hex>`. Parsed rather than
/// prefix-matched: the bare prefix names no key.
pub fn key_bytes_from_reference(reference: &str) -> Option<Vec<u8>> {
    let hex_part = reference.strip_prefix(KEY_REFERENCE_PREFIX)?;
    if hex_part.is_empty() || hex_part.len() % 2 != 0 {
        return None;
    }
    hex::decode(hex_part).ok()
}

pub fn key_reference(raw: &[u8]) -> String {
    format!("{KEY_REFERENCE_PREFIX}{}", hex::encode(raw))
}

pub fn base64_decode(value: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

pub fn base64_encode(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

/// Lowercase hex SHA-256 — the hash form every reference in the
/// contract uses (manifest hash, mandate ref, verdict ref).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_day_granular_duration_subset() {
        assert_eq!(parse_days("P1D").unwrap(), 1);
        assert_eq!(parse_days("P90D").unwrap(), 90);
        for bad in ["", "P", "PD", "P0D", "P-1D", "PT1H", "90D", "P90"] {
            assert!(parse_days(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn key_references_round_trip_and_reject_malformed() {
        let raw = vec![0x00, 0x0f, 0xa0, 0xff];
        assert_eq!(key_reference(&raw), "onym:key:000fa0ff");
        assert_eq!(key_bytes_from_reference("onym:key:000fa0ff").unwrap(), raw);
        for bad in ["", "onym:key:", "000fa0ff", "onym:key:0f0", "onym:key:zz"] {
            assert!(key_bytes_from_reference(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn timestamps_round_trip_in_the_clients_shape() {
        let parsed = parse_timestamp("2026-08-08T12:00:00Z").unwrap();
        assert_eq!(format_timestamp(parsed), "2026-08-08T12:00:00Z");
    }
}
