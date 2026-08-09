//! Device-recovery grants (REFERENCE-AUTHORITY-POLICY §6).
//!
//! A marked device whose enrolled identity did not survive a reinstall
//! or a change of hands cannot resolve its own record at the
//! interface. The way back is a human decision: the holder files a
//! claim with a real contact and their account of how they hold the
//! device, a moderator weighs it, and — when satisfied — issues the
//! grant built here. The grant authorizes exactly one thing at the
//! interface: moving the named case's verdict record to the named
//! identity's enrollment, where ordinary reconciliation acts on the
//! signed verdicts already on file. It moves no mark itself, and the
//! interface refuses it whenever any record still bans the device.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use time::OffsetDateTime;

use crate::canonical;
use crate::error::Error;
use crate::util;

/// Domain tag written into every grant's signed bytes. Must stay
/// byte-identical to the interface's `RECOVERY_GRANT_DOMAIN`; the pair
/// is what keeps a grant and a verdict — signed by the same operator
/// key over the same canonical form — from ever being presented as one
/// another.
pub const GRANT_DOMAIN: &str = "onym-recovery-grant-v1";
/// A moderator-approved unban for a freshly reinstalled device. Unlike a
/// case-bound recovery grant, this intentionally carries no case id: the
/// fresh DeviceCheck token cannot be linked to the old binding after a
/// reinstall.
pub const UNBAN_GRANT_DOMAIN: &str = "onym-unban-grant-v1";

/// The signed grant, exactly as the device presents it for redemption.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryGrant<'a> {
    grant_type: &'a str,
    grant_version: u32,
    case_id: &'a str,
    grantee: &'a str,
    authority: &'a str,
    issued_at: String,
    signature: String,
}

pub struct IssuedGrant {
    /// Hex hash of the signing bytes — the reference redemption records
    /// to make the grant single-use, and what the case event names.
    pub grant_ref: String,
    /// The signed grant, serialized — the exact bytes the claimant's
    /// device will present to the interface.
    pub raw: Vec<u8>,
}

fn sign_unban_grant(
    claim_id: &str,
    grantee: &str,
    authority: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<IssuedGrant, Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct UnbanGrant<'a> {
        grant_type: &'a str,
        grant_version: u32,
        claim_id: &'a str,
        grantee: &'a str,
        authority: &'a str,
        issued_at: String,
        signature: String,
    }
    let mut grant = UnbanGrant {
        grant_type: UNBAN_GRANT_DOMAIN,
        grant_version: 1,
        claim_id,
        grantee,
        authority,
        issued_at: util::format_timestamp(now),
        signature: String::new(),
    };
    let unsigned = serde_json::to_vec(&grant)
        .map_err(|e| Error::Internal(format!("encode unban grant: {e}")))?;
    let signing_bytes = canonical::grant_signing_bytes(&unsigned)?;
    grant.signature = util::base64_encode(&key.sign(&signing_bytes).to_bytes());
    let raw = serde_json::to_vec(&grant)
        .map_err(|e| Error::Internal(format!("encode unban grant: {e}")))?;
    Ok(IssuedGrant { grant_ref: util::sha256_hex(&signing_bytes), raw })
}

pub fn issue_unban_grant(
    claim_id: &str,
    grantee: &str,
    authority: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<IssuedGrant, Error> {
    sign_unban_grant(claim_id, grantee, authority, now, key)
}

/// Sign a grant with the operator key — the key the case's verdicts
/// are signed with, and therefore the one the interface resolves from
/// the consented manifest the case's mandate pinned.
pub fn issue_grant(
    case_id: &str,
    grantee: &str,
    authority: &str,
    now: OffsetDateTime,
    key: &SigningKey,
) -> Result<IssuedGrant, Error> {
    let mut grant = RecoveryGrant {
        grant_type: GRANT_DOMAIN,
        grant_version: 1,
        case_id,
        grantee,
        authority,
        issued_at: util::format_timestamp(now),
        signature: String::new(),
    };
    let unsigned = serde_json::to_vec(&grant)
        .map_err(|e| Error::Internal(format!("encode grant: {e}")))?;
    let signing_bytes = canonical::grant_signing_bytes(&unsigned)?;
    grant.signature = util::base64_encode(&key.sign(&signing_bytes).to_bytes());

    let raw = serde_json::to_vec(&grant)
        .map_err(|e| Error::Internal(format!("encode signed grant: {e}")))?;
    Ok(IssuedGrant {
        grant_ref: util::sha256_hex(&signing_bytes),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the domain tag the interface refuses a grant without. If
    /// this value drifts from the interface's `RECOVERY_GRANT_DOMAIN`,
    /// every grant this authority issues stops redeeming — so the
    /// constant is asserted here and mirrored there, the same
    /// agreement-by-fixture the canonical bytes use.
    #[test]
    fn issued_grants_carry_the_recovery_domain_tag() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let now = OffsetDateTime::from_unix_timestamp(1_765_000_000).unwrap();
        let issued = issue_grant("case-1", "onym:key:g", "onym:component:a", now, &key).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&issued.raw).unwrap();
        assert_eq!(value["grantType"], "onym-recovery-grant-v1");
        assert_eq!(value["grantType"], GRANT_DOMAIN);
    }

    #[test]
    fn issued_unban_grants_carry_no_case_id() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let now = OffsetDateTime::from_unix_timestamp(1_765_000_000).unwrap();
        let issued = issue_unban_grant(
            "claim-1", "onym:key:g", "onym:component:a", now, &key,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&issued.raw).unwrap();
        assert_eq!(value["grantType"], UNBAN_GRANT_DOMAIN);
        assert_eq!(value["claimId"], "claim-1");
        assert!(value.get("caseId").is_none());
    }
}
