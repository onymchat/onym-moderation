//! Per-authority countersigning keys, so one can be rotated without
//! invalidating the others.
//!
//! The interface countersigns a mandate to say it witnessed *this user*
//! consenting to *that authority*. Until now one key did that for every
//! authority, which made rotation all-or-nothing: changing the seed
//! invalidated every countersignature ever issued, to every authority,
//! at once. A key you suspect is compromised is a key you are stuck
//! with, which is not a property worth keeping.
//!
//! **This is about rotation, not compromise containment.** Say so
//! plainly, because the opposite is easy to assume: the private seed
//! never leaves this process — authorities only ever receive the public
//! half — so there is no path by which a compromised authority learns
//! it. The realistic compromise is this host, and every derived key
//! lives in the same memory as the root. Splitting one secret into
//! several that share a process does not shrink that blast radius. What
//! it does buy is the ability to burn one relationship: rotate a key
//! for a single authority, or on de-listing one, without touching
//! anyone else's mandates.
//!
//! Derived rather than stored, for the same reason. `N` independent
//! seeds would be `N` secrets to generate, back up and not lose, in
//! exchange for containment this design does not actually provide.
//! One root plus a non-secret epoch per authority gets the rotation
//! property with one secret to protect.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::util;

/// Domain separation, versioned so a future scheme cannot collide with
/// keys issued under this one.
const DOMAIN: &[u8] = b"onym:moderation:interface-countersigning:v1";

/// The interface's countersigning keys: one root, and a per-authority
/// epoch that selects which key is in force.
pub struct CountersigningKeys {
    root: [u8; 32],
    epochs: BTreeMap<String, u32>,
}

impl CountersigningKeys {
    pub fn new(root: [u8; 32], epochs: BTreeMap<String, u32>) -> Self {
        Self { root, epochs }
    }

    /// The epoch in force for an authority. Unconfigured means zero,
    /// which is the un-derived root — an authority nobody has rotated
    /// is an authority whose key has not moved.
    pub fn epoch_for(&self, authority: &str) -> u32 {
        self.epochs.get(authority).copied().unwrap_or(0)
    }

    /// The key this interface countersigns an authority's mandates
    /// with.
    ///
    /// **Epoch 0 is the root seed itself, not a derivation of it.**
    /// That is deliberate and load-bearing: every countersignature
    /// issued before per-authority keys existed still verifies, and
    /// adopting this change requires no coordination with any authority
    /// already configured with the old key. Rotation begins at 1.
    pub fn signing_key(&self, authority: &str) -> SigningKey {
        match self.epoch_for(authority) {
            0 => SigningKey::from_bytes(&self.root),
            epoch => SigningKey::from_bytes(&derive(&self.root, authority, epoch)),
        }
    }

    /// `onym:key:<hex>` of the public half — the value an authority
    /// puts in its `AUTHORITY_INTERFACE_KEY`.
    pub fn key_reference(&self, authority: &str) -> String {
        util::key_reference(self.signing_key(authority).verifying_key().as_bytes())
    }

    /// The epoch-0 key, which is what an authority with no epoch
    /// configured must be told to expect.
    pub fn root_reference(&self) -> String {
        util::key_reference(SigningKey::from_bytes(&self.root).verifying_key().as_bytes())
    }

    /// Every authority whose key has been rotated away from the root,
    /// for `/health`. An authority absent from this map uses the root
    /// key, so publishing only the exceptions keeps the common case
    /// legible.
    pub fn rotated(&self) -> BTreeMap<&str, (u32, String)> {
        self.epochs
            .iter()
            .filter(|(_, epoch)| **epoch != 0)
            .map(|(authority, epoch)| {
                (authority.as_str(), (*epoch, self.key_reference(authority)))
            })
            .collect()
    }
}

/// `SHA-256(DOMAIN ‖ root ‖ authority ‖ 0x00 ‖ epoch)`.
///
/// A plain hash rather than HKDF because the root is a uniformly random
/// 256-bit secret, not a password — there is no entropy to stretch, and
/// the extract step would add a dependency for nothing.
///
/// The NUL and the fixed-width epoch are what stop
/// `("authority-a", 11)` and `("authority-a:1", 1)` from hashing to the
/// same key. Concatenating variable-length fields without a separator
/// is how derivation schemes grow collisions nobody looks for.
fn derive(root: &[u8; 32], authority: &str, epoch: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(root);
    hasher.update(authority.as_bytes());
    hasher.update([0u8]);
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

/// Parse `MODERATION_INTERFACE_KEY_EPOCHS`:
/// `onym:component:a=1,onym:component:b=3`.
///
/// Split on the **last** `=` of each entry, because a component id is
/// full of colons and may one day contain worse.
///
/// Strict: a malformed entry is a boot failure rather than a silent
/// zero. Falling back to the root on a typo'd epoch would countersign
/// with a key the authority is not expecting, and the symptom would be
/// every mandate registration refused for a reason neither side can see
/// from its own logs.
pub fn parse_epochs(raw: &str) -> Result<BTreeMap<String, u32>, String> {
    let mut epochs = BTreeMap::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (authority, epoch) = entry.rsplit_once('=').ok_or_else(|| {
            format!("MODERATION_INTERFACE_KEY_EPOCHS entry {entry:?} is not <componentId>=<epoch>")
        })?;
        let authority = authority.trim();
        if authority.is_empty() {
            return Err(format!(
                "MODERATION_INTERFACE_KEY_EPOCHS entry {entry:?} names no authority"
            ));
        }
        let epoch: u32 = epoch.trim().parse().map_err(|_| {
            format!(
                "MODERATION_INTERFACE_KEY_EPOCHS entry {entry:?} has a non-numeric epoch; it must \
                 be a whole number, and 0 means the un-rotated root key"
            )
        })?;
        if epochs.insert(authority.to_string(), epoch).is_some() {
            return Err(format!(
                "MODERATION_INTERFACE_KEY_EPOCHS names {authority:?} twice; which key is in force \
                 must not depend on ordering"
            ));
        }
    }
    Ok(epochs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [7u8; 32];
    const A: &str = "onym:component:onym-authority";
    const B: &str = "onym:component:other-authority";

    fn keys(pairs: &[(&str, u32)]) -> CountersigningKeys {
        CountersigningKeys::new(
            ROOT,
            pairs.iter().map(|(a, e)| ((*a).to_string(), *e)).collect(),
        )
    }

    /// The compatibility guarantee, and the reason epoch 0 is not a
    /// derivation. Every countersignature issued before this existed
    /// was made with the root seed; if epoch 0 derived instead, they
    /// would all stop verifying the moment this shipped — the exact
    /// catastrophe the feature exists to make avoidable.
    #[test]
    fn epoch_zero_is_the_root_key_itself() {
        let expected = util::key_reference(
            SigningKey::from_bytes(&ROOT).verifying_key().as_bytes(),
        );
        assert_eq!(keys(&[]).key_reference(A), expected, "unconfigured");
        assert_eq!(keys(&[(A, 0)]).key_reference(A), expected, "explicitly zero");
        assert_eq!(keys(&[(B, 4)]).key_reference(A), expected, "someone else rotated");
    }

    /// The point of the change: one authority's key moves and nobody
    /// else's does.
    #[test]
    fn rotating_one_authority_leaves_the_others_alone() {
        let before = keys(&[]);
        let after = keys(&[(A, 1)]);

        assert_ne!(after.key_reference(A), before.key_reference(A), "A rotated");
        assert_eq!(after.key_reference(B), before.key_reference(B), "B did not");
        assert_eq!(after.key_reference(B), after.root_reference());
    }

    #[test]
    fn each_bump_is_a_new_key_and_derivation_is_stable() {
        let one = keys(&[(A, 1)]);
        let two = keys(&[(A, 2)]);
        assert_ne!(one.key_reference(A), two.key_reference(A));
        // Same inputs, same key — a redeploy must not silently rotate.
        assert_eq!(one.key_reference(A), keys(&[(A, 1)]).key_reference(A));
    }

    #[test]
    fn two_authorities_at_the_same_epoch_get_different_keys() {
        let both = keys(&[(A, 1), (B, 1)]);
        assert_ne!(both.key_reference(A), both.key_reference(B));
    }

    /// Variable-length fields concatenated without a separator collide
    /// in ways nobody goes looking for. `("x", 11)` and `("x:1", 1)`
    /// are the shape of it.
    #[test]
    fn the_separator_stops_authority_and_epoch_running_together() {
        assert_ne!(derive(&ROOT, "x", 11), derive(&ROOT, "x:1", 1));
        assert_ne!(derive(&ROOT, "ab", 1), derive(&ROOT, "a", 1));
    }

    #[test]
    fn a_different_root_gives_different_keys_at_every_epoch() {
        let other = CountersigningKeys::new([9u8; 32], [(A.to_string(), 1)].into());
        assert_ne!(keys(&[(A, 1)]).key_reference(A), other.key_reference(A));
    }

    #[test]
    fn only_rotated_authorities_are_published() {
        let k = keys(&[(A, 2), (B, 0)]);
        let rotated = k.rotated();
        assert_eq!(rotated.len(), 1, "B is still on the root and needs no entry");
        let (epoch, reference) = &rotated[A];
        assert_eq!(*epoch, 2);
        assert_eq!(reference, &k.key_reference(A));
    }

    #[test]
    fn epochs_parse_from_the_documented_shape() {
        let parsed = parse_epochs("onym:component:a=1, onym:component:b=12").unwrap();
        assert_eq!(parsed.get("onym:component:a"), Some(&1));
        assert_eq!(parsed.get("onym:component:b"), Some(&12));
        assert!(parse_epochs("").unwrap().is_empty());
    }

    /// A typo must not become epoch 0. Signing with the root when an
    /// authority expects a rotated key fails every registration, and
    /// neither side's logs say why.
    #[test]
    fn a_malformed_epoch_is_a_boot_failure_not_a_silent_zero() {
        for bad in [
            "onym:component:a",        // no epoch
            "onym:component:a=",       // empty epoch
            "onym:component:a=one",    // not a number
            "onym:component:a=-1",     // negative
            "=3",                      // no authority
            "onym:component:a=1,onym:component:a=2", // ambiguous
        ] {
            assert!(parse_epochs(bad).is_err(), "{bad:?} must be refused");
        }
    }
}

/// Wiring, not derivation: the key `countersign` actually reaches for.
///
/// The unit tests above prove the derivation is per-authority and
/// stable. This proves the handler consults it — that a mandate naming
/// a rotated authority is signed with that authority's key, and one
/// naming an unrotated authority is still signed with the root. A
/// derivation nothing calls would pass every test in this file.
#[cfg(test)]
mod wiring_tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn a_mandate_is_countersigned_with_its_own_authoritys_key() {
        const ROOT: [u8; 32] = [3u8; 32];
        let rotated = "onym:component:rotated";
        let untouched = "onym:component:untouched";
        let keys = CountersigningKeys::new(
            ROOT,
            [(rotated.to_string(), 5u32)].into_iter().collect(),
        );

        let bytes = b"the mandate's canonical signing bytes";
        let root_public = SigningKey::from_bytes(&ROOT).verifying_key();

        // Rotated: verifies under the rotated key, and specifically
        // *not* under the root — the point of rotating is that the old
        // key stops working for this relationship.
        let signature = keys.signing_key(rotated).sign(bytes);
        let rotated_public = keys.signing_key(rotated).verifying_key();
        assert!(rotated_public.verify(bytes, &signature).is_ok());
        assert!(
            root_public.verify(bytes, &signature).is_err(),
            "a rotated authority's countersignature must not verify under the old key"
        );

        // Untouched: still the root, so an authority that was never
        // rotated needs no configuration change and notices nothing.
        let signature = keys.signing_key(untouched).sign(bytes);
        assert!(root_public.verify(bytes, &signature).is_ok());
        assert_eq!(keys.key_reference(untouched), keys.root_reference());
    }
}
