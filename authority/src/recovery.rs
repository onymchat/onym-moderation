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

/// The signed grant, exactly as the device presents it for redemption.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryGrant<'a> {
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
