//! Fixtures shared by the unit tests.
#![cfg(test)]

/// A manifest that satisfies the consent-time conditions the interface
/// checks: a supported profile, an external appellate for its permanent
/// class, and a new-holder path.
pub const MANIFEST_JSON: &str = r#"{
  "version": 1,
  "componentId": "onym:component:test-authority",
  "seat": "moderation",
  "operator": "onym:key:0000000000000000000000000000000000000000000000000000000000000000",
  "moderationProfileId": "onym:moderation-profile:consent-bound-v1",
  "violationClasses": [
    {
      "classId": "csam",
      "definition": "hash:csam",
      "responseWindow": "P3D",
      "decisionDeadline": "P7D",
      "banTerm": "permanent",
      "appealWindow": "P30D",
      "appealEffect": "non-suspensive"
    },
    {
      "classId": "credible-violence",
      "definition": "hash:violence",
      "responseWindow": "P7D",
      "decisionDeadline": "P14D",
      "banTerm": "P365D",
      "appealWindow": "P30D",
      "appealEffect": "non-suspensive"
    },
    {
      "classId": "unsolicited-pornography",
      "definition": "hash:up",
      "responseWindow": "P7D",
      "decisionDeadline": "P14D",
      "banTerm": "P90D",
      "appealWindow": "P30D",
      "appealEffect": "suspensive"
    }
  ],
  "newHolderAppeal": "hash:new-holder",
  "appellate": "onym:component:test-appellate",
  "validUntil": "2030-01-01T00:00:00Z"
}"#;

// ─── Signing fixtures ────────────────────────────────────────────────
//
// Fixed seeds: a test that generates keys at random cannot be told apart
// from one that passes by luck.

use ed25519_dalek::{Signer, SigningKey};

pub const INTERFACE_SEED: [u8; 32] = [1u8; 32];
pub const ACCUSED_SEED: [u8; 32] = [2u8; 32];
pub const REPORTER_SEED: [u8; 32] = [3u8; 32];
pub const STRANGER_SEED: [u8; 32] = [4u8; 32];

pub fn key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

pub fn key_reference(seed: [u8; 32]) -> String {
    crate::util::key_reference(key(seed).verifying_key().as_bytes())
}

pub fn interface_key_reference() -> String {
    key_reference(INTERFACE_SEED)
}

pub fn sign(seed: [u8; 32], message: &[u8]) -> String {
    crate::util::base64_encode(&key(seed).sign(message).to_bytes())
}
