//! The referral package: what leaves this authority, and only this.
//!
//! Material preserved under a published duty has to reach a body
//! equipped to act on it. This authority does not submit it — it holds
//! no credentials for any reporting channel and makes no claim about a
//! pipeline it cannot verify landed. It builds a signed package and an
//! operator submits it through whatever channel they are registered for,
//! then records what came back.
//!
//! Two properties are worth stating because they are easy to erode:
//!
//! **This is the one path by which the bytes leave.** The panel does not
//! render them, no model is shown them, and the derivative that would
//! have made either possible is destroyed at intake. Exporting is a
//! deliberate act for a stated purpose, and it is logged as one.
//!
//! **The package is signed.** Whoever receives it is being told this
//! authority holds these exact bytes under this case; a signature over
//! the metadata is what makes that a claim rather than an assertion, and
//! it lets a receiving body check provenance without trusting the
//! transport it arrived over.
//!
//! The package deliberately carries no reporter identity beyond the key
//! reference already in the case record. A referral is about the
//! material and the account that sent it.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::canonical;
use crate::error::Error;
use crate::store::Store;
use crate::util;

/// One preserved image, described.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferralImage {
    /// SHA-256 of the exact bytes this authority holds — the digest the
    /// accused signed, and what a receiving body can verify against the
    /// attached content.
    pub sha256: String,
    pub media_type: String,
    pub byte_length: u64,
    pub width: u32,
    pub height: u32,
}

/// The signed description of what is held and why.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferralManifest {
    pub referral_version: u32,
    pub authority: String,
    pub case_id: String,
    pub class_id: String,
    /// Key references, not names. This authority never held a legal
    /// identity for either party and does not invent one here.
    pub accused: String,
    pub reporter: String,
    pub case_opened_at: String,
    pub preserved_until: String,
    /// The digest of the case document, so the record this referral came
    /// from can be tied to the one an appeal would review.
    pub case_document_digest: String,
    pub images: Vec<ReferralImage>,
    pub prepared_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// A package ready to hand to an operator: the signed manifest, and the
/// bytes it describes.
///
/// `Debug` prints the manifest and the *length* of each image, never the
/// bytes: this type exists to carry material nobody here should be
/// looking at, and a stray log line is a way to look at it.
pub struct ReferralPackage {
    pub manifest: ReferralManifest,
    /// `(sha256, bytes)` in manifest order.
    pub images: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for ReferralPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferralPackage")
            .field("manifest", &self.manifest)
            .field(
                "images",
                &self
                    .images
                    .iter()
                    .map(|(digest, bytes)| (digest.as_str(), bytes.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ReferralPackage {
    /// The manifest as its signed JSON bytes.
    pub fn manifest_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| Error::Internal(format!("encode referral manifest: {e}")))
    }
}

/// Build the package for a preserved case.
///
/// Refuses a case with no preservation hold. A referral is a
/// consequence of a duty, and building one for a case that carries none
/// would be exporting evidence for a reason this authority never
/// published.
pub fn build(
    store: &Store,
    case_id: &str,
    authority: &str,
    key: &SigningKey,
    now: time::OffsetDateTime,
) -> Result<ReferralPackage, Error> {
    let case = store
        .case(case_id)?
        .ok_or_else(|| Error::NotFound(format!("case {case_id}")))?;

    // The duty must be *live*, not merely on file. A hold row survives
    // its own `release_after` until the next sweep deletes it, so
    // existence alone would authorize an export during that window —
    // shipping originals out under a duty that had already ended.
    // `is_preserved` is the gate that answers the actual question.
    // `is_preserved`, not a date compare — because those answer different
    // questions and the difference is the whole point of the rule.
    //
    // A hold whose period has passed with no referral recorded is still
    // live: the material is kept, the case stays queued, and the sweep
    // warns every tick. Gating export on the date alone made the package
    // unbuildable in exactly that state — so the operator could not
    // produce the referral for the one case the hold-until-referred rule
    // exists to protect, and nothing could ever take it off the queue.
    if !store.is_preserved("case", case_id, &util::format_timestamp(now))? {
        return Err(Error::CaseState(format!(
            "case {case_id} carries no live preservation hold; there is no published duty to \
             refer it under"
        )));
    }
    let hold = store.preservation_hold("case", case_id)?.ok_or_else(|| {
        Error::Internal(format!("case {case_id} is preserved but has no hold row"))
    })?;

    let document = crate::casedoc::build(store, &case)?;

    let mut images = Vec::new();
    let mut described = Vec::new();
    for digest in store.case_media_digests(case_id)? {
        let Some(stored) = store.evidence_blob(&digest)? else { continue };
        let Some(bytes) = store.evidence_blob_original(&digest)? else { continue };
        described.push(ReferralImage {
            sha256: stored.sha256.clone(),
            media_type: stored.mime_type,
            byte_length: stored.byte_length,
            width: stored.width,
            height: stored.height,
        });
        images.push((stored.sha256, bytes));
    }

    let mut manifest = ReferralManifest {
        referral_version: 1,
        authority: authority.to_string(),
        case_id: case_id.to_string(),
        class_id: case.class_id.clone(),
        accused: case.accused.clone(),
        reporter: case.reporter.clone(),
        case_opened_at: case.opened_at.clone(),
        preserved_until: hold.release_after,
        case_document_digest: document.digest,
        images: described,
        prepared_at: util::format_timestamp(now),
        signature: String::new(),
    };

    // Signed the way every other authority artifact is: canonical bytes
    // with the signature field structurally removed, so a verifier
    // reconstructs the same input without knowing this type.
    let unsigned = serde_json::to_vec(&manifest)
        .map_err(|e| Error::Internal(format!("encode referral: {e}")))?;
    let signing_bytes = canonical::canonical_bytes(&unsigned, &["signature"])?;
    manifest.signature = util::base64_encode(&key.sign(&signing_bytes).to_bytes());

    Ok(ReferralPackage { manifest, images })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PreservationHold;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn seeded_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn case_with_media() -> (Store, crate::media::AcceptedImage) {
        let store = Store::in_memory().unwrap();
        let case = crate::store::CaseRecord {
            case_id: "c1".into(),
            accused: "onym:key:acc".into(),
            reporter: "onym:key:rep".into(),
            class_id: "csam".into(),
            mandate_ref: "m1".into(),
            device_binding: "d1".into(),
            stage: "open".into(),
            opened_at: "2026-08-01T00:00:00Z".into(),
            response_deadline: "2026-08-04T00:00:00Z".into(),
            decision_deadline: "2026-08-08T00:00:00Z".into(),
            responded: false,
            disposition: None,
            appeal_deadline: None,
            appeal_state: "none".into(),
            new_holder_state: "none".into(),
            revision: 0,
            claim_revision: 0,
        };
        store.put_case(&case).unwrap();

        let bytes = crate::media::tiny_jpeg(16, 12);
        let accepted = crate::media::accept_image(&bytes).unwrap();
        store
            .put_evidence_blob(&accepted, &bytes, "2026-08-02T00:00:00Z", "onym:key:rep", usize::MAX)
            .unwrap();
        store.attach_evidence_blobs("c1", &[accepted.sha256.clone()]).unwrap();
        store
            .place_preservation_hold(&PreservationHold {
                subject_kind: "case".into(),
                subject_id: "c1".into(),
                class_id: "csam".into(),
                reason: "preservation".into(),
                placed_at: "2026-08-02T00:00:00Z".into(),
                release_after: "2027-09-05T00:00:00Z".into(),
            })
            .unwrap();
        (store, accepted)
    }

    #[test]
    fn a_package_describes_and_carries_the_preserved_bytes() {
        let (store, accepted) = case_with_media();
        let now = util::parse_timestamp("2026-08-03T00:00:00Z").unwrap();

        let package =
            build(&store, "c1", "onym:component:test-authority", &seeded_key(), now).unwrap();

        assert_eq!(package.manifest.class_id, "csam");
        assert_eq!(package.manifest.preserved_until, "2027-09-05T00:00:00Z");
        assert_eq!(package.manifest.images.len(), 1);
        assert_eq!(package.manifest.images[0].sha256, accepted.sha256);
        assert_eq!(package.manifest.images[0].width, 16);

        // The bytes travel, and they are the original — the digest a
        // receiving body can check is the digest of what is attached.
        assert_eq!(package.images.len(), 1);
        assert_eq!(util::sha256_hex(&package.images[0].1), accepted.sha256);
    }

    #[test]
    fn the_manifest_signature_verifies_over_its_canonical_bytes() {
        let (store, _) = case_with_media();
        let now = util::parse_timestamp("2026-08-03T00:00:00Z").unwrap();
        let key = seeded_key();

        let package = build(&store, "c1", "onym:component:test-authority", &key, now).unwrap();

        let raw = serde_json::to_vec(&package.manifest).unwrap();
        let signing_bytes = canonical::canonical_bytes(&raw, &["signature"]).unwrap();
        let signature: [u8; 64] = util::base64_decode(&package.manifest.signature)
            .unwrap()
            .try_into()
            .unwrap();
        let verifying = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        verifying
            .verify(&signing_bytes, &Signature::from_bytes(&signature))
            .expect("a receiving body must be able to check provenance");
    }

    /// The state the hold-until-referred rule creates must still be
    /// exportable.
    ///
    /// Past its date with nothing recorded, the hold stays live, the case
    /// stays queued and the panel keeps offering the download — so gating
    /// export on the date alone made the package unbuildable for exactly
    /// the case the rule protects, with no way to ever take it off the
    /// queue.
    #[test]
    fn an_overdue_unreferred_case_can_still_be_referred() {
        let (store, accepted) = case_with_media();
        // Well past the hold's release date, and no reference recorded.
        let now = util::parse_timestamp("2030-01-01T00:00:00Z").unwrap();

        let package =
            build(&store, "c1", "onym:component:test-authority", &seeded_key(), now).unwrap();

        assert_eq!(package.manifest.images.len(), 1);
        assert_eq!(package.manifest.images[0].sha256, accepted.sha256);
    }

    /// And once the referral is recorded and the period has passed, the
    /// hold is gone and there is nothing left to export.
    #[test]
    fn a_discharged_and_expired_duty_cannot_be_referred_again() {
        let (store, _) = case_with_media();
        store.record_referral_reference("c1", "REF-1", "2026-08-03T00:00:00Z").unwrap();
        store.drop_hold("case", "c1").unwrap();
        let now = util::parse_timestamp("2030-01-01T00:00:00Z").unwrap();

        let error =
            build(&store, "c1", "onym:component:test-authority", &seeded_key(), now).unwrap_err();

        assert_eq!(error.code(), "case_state");
    }

    #[test]
    fn a_case_with_no_preservation_duty_cannot_be_referred() {
        // Exporting evidence needs a published reason. Without a hold
        // there is none, and the export route is not a general way to
        // get case material out of this service.
        let (store, _) = case_with_media();
        store.drop_hold("case", "c1").unwrap();
        let now = util::parse_timestamp("2026-08-03T00:00:00Z").unwrap();

        let error =
            build(&store, "c1", "onym:component:test-authority", &seeded_key(), now).unwrap_err();

        assert_eq!(error.code(), "case_state");
    }
}
