//! Media evidence: the sender's signed commitment, and the bytes it names.
//!
//! A reported photo is authenticated by the same mechanism as reported
//! text. `disclosedContent` is an opaque string the accused signed, and
//! the authority verifies that signature over the string verbatim
//! (`api::file_report`). What changes for media is that the string is
//! now also *read*: a v2 preimage carries a `media` array committing to
//! each attached blob's plaintext digest, media type and byte length.
//!
//! That is the whole authenticity story, and it is worth being precise
//! about why it is enough. The bytes travel on their own
//! content-addressed route rather than inside the report, so the
//! obvious worry is that the upload is unauthenticated and could be
//! swapped. It cannot: the report names the blob by the digest the
//! accused signed, and the authority recomputes that digest over the
//! bytes it actually holds. Bytes that do not hash to the signed value
//! are not the reported photo, whoever uploaded them. This is also why
//! the upload needs no ownership scoping, sealing ceremony, or
//! single-use token — referencing somebody else's upload is useless
//! without a signature over that same digest, and such a signature *is*
//! the evidence.
//!
//! The exact original is kept as the authenticated artifact. The model
//! and the moderator panel see a normalized derivative instead, and both
//! digests are recorded, so an appeal can establish what was received
//! and what was shown separately.

use crate::error::Error;
use crate::util;
use serde::Deserialize;

/// Ceiling on one uploaded evidence blob. Sits above the iOS client's
/// ~2 MB encoded-JPEG budget with room to spare, and far below anything
/// that would make holding the bytes in memory to hash them a problem.
pub const MAX_EVIDENCE_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// Hard cap on committed media across one report, applied before any
/// database lookup. A signed preimage is attacker-authored — nothing
/// stops the accused signing one naming a thousand blobs — so the count
/// is bounded before it can become work. The pinned model profile's own
/// maximum applies on top of this and is usually much smaller.
pub const MAX_MEDIA_PER_REPORT: usize = 8;

/// Decoded-pixel ceiling. A few hundred kilobytes of PNG can describe a
/// billion pixels, so the byte-length limit alone does not bound the
/// decode; this does.
pub const MAX_IMAGE_PIXELS: u64 = 40_000_000;

/// Per-edge ceiling, so a 1 × 40,000,000 strip is refused too.
pub const MAX_IMAGE_EDGE: u32 = 12_000;

/// Longest edge of the normalized derivative.
pub const DERIVATIVE_MAX_EDGE: u32 = 1024;

/// Bumped whenever the normalization below changes in a way that alters
/// its output bytes. It is recorded on the assessment and folded into
/// the case document, so a rerun under different normalization is
/// visibly a different input rather than an unexplained digest change.
pub const DERIVATIVE_VERSION: u32 = 1;

/// The media types this authority will accept and decode. Detected from
/// the bytes, never from a client-declared header.
pub const ALLOWED_MEDIA_TYPES: [&str; 2] = ["image/jpeg", "image/png"];

/// One entry of a v2 preimage's `media` array.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MediaCommitment {
    pub blob_sha256: String,
    pub mime_type: String,
    pub plaintext_sha256: String,
    pub plaintext_byte_length: u64,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
}

/// What an evidence item's `disclosedContent` turned out to be.
#[derive(Debug, Clone, PartialEq)]
pub enum Disclosed {
    /// Text, including every disclosure shape that predates media
    /// evidence. Handled exactly as before.
    Text,
    /// A v2 preimage with at least one media commitment.
    Media(Vec<MediaCommitment>),
}

/// Read an evidence item's disclosed content.
///
/// Deliberately lenient about what it does *not* understand. Content
/// that is not a JSON object, or that carries no `proof_version`, is
/// text: this authority has never parsed `disclosedContent` before, so
/// anything already on file or already signed by a shipped client must
/// keep working unchanged.
///
/// It is strict about what it does understand. An unknown
/// `proof_version` is refused rather than guessed at, and a `media`
/// array riding inside a v1 preimage is refused outright — dispatching
/// on the field's presence instead of the version would let an
/// attacker pick which rules applied to their own signed bytes.
pub fn parse_disclosed(content: &str) -> Result<Disclosed, Error> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Ok(Disclosed::Text);
    };
    let Some(object) = value.as_object() else {
        return Ok(Disclosed::Text);
    };
    let Some(version) = object.get("proof_version").and_then(|v| v.as_u64()) else {
        return Ok(Disclosed::Text);
    };

    match version {
        1 => {
            if object.contains_key("media") {
                return Err(Error::AuthenticityUnverified(
                    "a version 1 proof cannot carry media; the version, not the field, decides \
                     how signed bytes are read"
                        .into(),
                ));
            }
            Ok(Disclosed::Text)
        }
        2 => {
            let mut items: Vec<MediaCommitment> = serde_json::from_value(
                object.get("media").cloned().unwrap_or(serde_json::Value::Null),
            )
            .map_err(|e| {
                Error::AuthenticityUnverified(format!("version 2 proof has unreadable media: {e}"))
            })?;
            // Digests are compared against stored keys, and uploads are
            // stored under lowercase hex. Normalizing here rather than
            // at each comparison keeps one spelling of a digest from
            // meaning "not on file" while the bytes sit in the store.
            // Note this touches only the parsed copy — the signature
            // covers the original string, which is never rewritten.
            for item in &mut items {
                item.plaintext_sha256.make_ascii_lowercase();
                item.blob_sha256.make_ascii_lowercase();
            }
            if items.is_empty() {
                return Err(Error::AuthenticityUnverified(
                    "a version 2 proof must commit to at least one media item".into(),
                ));
            }
            Ok(Disclosed::Media(items))
        }
        other => Err(Error::AuthenticityUnverified(format!(
            "unknown proof version {other}"
        ))),
    }
}

/// An accepted upload: the original as received, plus the derivative
/// that stands in for it everywhere the bytes are shown or classified.
#[derive(Debug)]
pub struct AcceptedImage {
    pub mime_type: &'static str,
    pub byte_length: u64,
    pub width: u32,
    pub height: u32,
    pub sha256: String,
    pub derivative: Vec<u8>,
    pub derivative_sha256: String,
    pub derivative_version: u32,
}

/// Detect the media type from the bytes themselves.
///
/// The client's declared type is not consulted. It is attacker-supplied
/// and the whole point of the allowlist is to decide which decoder runs.
fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else {
        None
    }
}

/// Validate an uploaded evidence image and build its derivative.
///
/// Runs before anything is persisted, so malformed input and
/// decompression bombs never reach the database. The order matters:
/// cheap byte-level checks first, dimension limits from the header
/// next, and only then a full decode.
pub fn accept_image(bytes: &[u8]) -> Result<AcceptedImage, Error> {
    if bytes.len() > MAX_EVIDENCE_BLOB_BYTES {
        return Err(Error::MediaTooLarge(format!(
            "evidence blob is {} bytes; the ceiling is {MAX_EVIDENCE_BLOB_BYTES}",
            bytes.len()
        )));
    }
    if bytes.is_empty() {
        return Err(Error::MediaUnsupported("evidence blob is empty".into()));
    }
    let mime_type = sniff(bytes).ok_or_else(|| {
        Error::MediaUnsupported(format!(
            "evidence blob is not one of {}",
            ALLOWED_MEDIA_TYPES.join(", ")
        ))
    })?;

    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes));
    reader.set_format(match mime_type {
        "image/jpeg" => image::ImageFormat::Jpeg,
        _ => image::ImageFormat::Png,
    });
    // Bound the decoder before it allocates. Without this a small PNG
    // declaring enormous dimensions is an out-of-memory kill, not a
    // rejected upload.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_EDGE);
    limits.max_image_height = Some(MAX_IMAGE_EDGE);
    limits.max_alloc = Some(MAX_IMAGE_PIXELS * 4);
    reader.limits(limits);

    let decoded = reader
        .decode()
        .map_err(|e| Error::MediaUnsupported(format!("evidence image did not decode: {e}")))?;

    let (width, height) = (decoded.width(), decoded.height());
    if width == 0 || height == 0 {
        return Err(Error::MediaUnsupported("evidence image has a zero edge".into()));
    }
    if u64::from(width) * u64::from(height) > MAX_IMAGE_PIXELS {
        return Err(Error::MediaUnsupported(format!(
            "evidence image is {width}x{height}, above the {MAX_IMAGE_PIXELS}-pixel ceiling"
        )));
    }

    // The derivative: fixed color space, bounded size, re-encoded so no
    // metadata from the original survives into what a model or a
    // moderator is shown.
    let bounded = if width > DERIVATIVE_MAX_EDGE || height > DERIVATIVE_MAX_EDGE {
        decoded.resize(
            DERIVATIVE_MAX_EDGE,
            DERIVATIVE_MAX_EDGE,
            image::imageops::FilterType::Triangle,
        )
    } else {
        decoded
    };
    let mut derivative = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut derivative, 85)
        .encode_image(&bounded.to_rgb8())
        .map_err(|e| Error::Internal(format!("derivative encode failed: {e}")))?;

    Ok(AcceptedImage {
        mime_type,
        byte_length: bytes.len() as u64,
        width,
        height,
        sha256: util::sha256_hex(bytes),
        derivative_sha256: util::sha256_hex(&derivative),
        derivative,
        derivative_version: DERIVATIVE_VERSION,
    })
}

/// A small, real JPEG. Shared with the API tests so a report fixture is
/// built from bytes this module would actually accept, rather than from
/// a hand-written blob that only resembles one.
#[cfg(test)]
pub fn tiny_jpeg(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
    });
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut out).encode_image(&image).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_that_is_not_a_proof_is_read_as_text() {
        // Every report already on file predates media evidence and its
        // disclosed content is arbitrary. None of it may start failing.
        for content in ["hello", "", "not json {", "[1,2,3]", "\"quoted\"", "42"] {
            assert_eq!(parse_disclosed(content).unwrap(), Disclosed::Text);
        }
    }

    #[test]
    fn a_version_one_proof_is_read_as_text() {
        let content = r#"{"body":"hi","group_binding":"ab","message_id":"m","proof_version":1,"sent_at_millis":1}"#;
        assert_eq!(parse_disclosed(content).unwrap(), Disclosed::Text);
    }

    #[test]
    fn a_version_one_proof_carrying_media_is_refused() {
        // The version decides, not the field. Honouring `media` here
        // would let a sender choose which rules their own signed bytes
        // were read under.
        let content = r#"{"media":[],"proof_version":1}"#;
        let error = parse_disclosed(content).unwrap_err();
        assert_eq!(error.code(), "authenticity_unverified");
    }

    #[test]
    fn an_unknown_proof_version_is_refused_rather_than_guessed() {
        let error = parse_disclosed(r#"{"proof_version":3}"#).unwrap_err();
        assert_eq!(error.code(), "authenticity_unverified");
    }

    #[test]
    fn a_version_two_proof_yields_its_media_commitments() {
        let content = r#"{"body":"","group_binding":"ab","media":[{"blob_sha256":"aa","height":4,"mime_type":"image/jpeg","plaintext_byte_length":9,"plaintext_sha256":"bb","width":3}],"message_id":"m","proof_version":2,"sent_at_millis":1}"#;
        let Disclosed::Media(items) = parse_disclosed(content).unwrap() else {
            panic!("expected media");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].plaintext_sha256, "bb");
        assert_eq!(items[0].mime_type, "image/jpeg");
        assert_eq!(items[0].plaintext_byte_length, 9);
        assert_eq!(items[0].width, Some(3));
    }

    #[test]
    fn a_version_two_proof_with_no_media_is_refused() {
        let error = parse_disclosed(r#"{"media":[],"proof_version":2}"#).unwrap_err();
        assert_eq!(error.code(), "authenticity_unverified");
    }

    #[test]
    fn media_without_dimensions_still_parses() {
        // Audio commits to no width or height, and those keys are
        // absent rather than zero.
        let content = r#"{"media":[{"blob_sha256":"aa","mime_type":"audio/mp4","plaintext_byte_length":9,"plaintext_sha256":"bb"}],"proof_version":2}"#;
        let Disclosed::Media(items) = parse_disclosed(content).unwrap() else {
            panic!("expected media");
        };
        assert_eq!(items[0].width, None);
    }

    #[test]
    fn a_valid_jpeg_is_accepted_and_gets_a_derivative() {
        let bytes = tiny_jpeg(40, 30);
        let accepted = accept_image(&bytes).unwrap();
        assert_eq!(accepted.mime_type, "image/jpeg");
        assert_eq!(accepted.width, 40);
        assert_eq!(accepted.height, 30);
        assert_eq!(accepted.sha256, util::sha256_hex(&bytes));
        assert!(!accepted.derivative.is_empty());
        // The derivative is its own artifact with its own digest — the
        // record has to distinguish what arrived from what was shown.
        assert_ne!(accepted.derivative_sha256, accepted.sha256);
    }

    #[test]
    fn a_large_image_is_bounded_in_the_derivative_but_kept_whole_as_evidence() {
        let bytes = tiny_jpeg(2000, 1000);
        let accepted = accept_image(&bytes).unwrap();
        assert_eq!(accepted.width, 2000, "the original's dimensions are recorded as received");
        let derivative = image::load_from_memory(&accepted.derivative).unwrap();
        assert!(derivative.width() <= DERIVATIVE_MAX_EDGE);
        assert!(derivative.height() <= DERIVATIVE_MAX_EDGE);
    }

    #[test]
    fn a_media_type_outside_the_allowlist_is_refused() {
        // A GIF header: a real image format, and still not one of the
        // two decoders this authority builds.
        let error = accept_image(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;").unwrap_err();
        assert_eq!(error.code(), "media_unsupported");
    }

    #[test]
    fn malformed_bytes_are_refused_rather_than_stored() {
        let mut bytes = tiny_jpeg(10, 10);
        bytes.truncate(bytes.len() / 2);
        let error = accept_image(&bytes).unwrap_err();
        assert_eq!(error.code(), "media_unsupported");
    }

    #[test]
    fn an_empty_blob_is_refused() {
        assert_eq!(accept_image(&[]).unwrap_err().code(), "media_unsupported");
    }

    #[test]
    fn an_oversized_blob_is_refused_before_decoding() {
        let bytes = vec![0xFFu8; MAX_EVIDENCE_BLOB_BYTES + 1];
        assert_eq!(accept_image(&bytes).unwrap_err().code(), "media_too_large");
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        // A PNG header can declare dimensions far larger than the file
        // that carries them. The byte-length limit says nothing about
        // this; the decoder limits do.
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&100_000u32.to_be_bytes());
        ihdr.extend_from_slice(&100_000u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        png.extend_from_slice(&(ihdr.len() as u32 - 4).to_be_bytes());
        png.extend_from_slice(&ihdr);
        png.extend_from_slice(&crc32(&ihdr).to_be_bytes());
        let error = accept_image(&png).unwrap_err();
        assert_eq!(error.code(), "media_unsupported");
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }
}


/// The cross-implementation vector for the version 2 commitment.
///
/// The signer is Swift and the verifier is this crate. They agree on
/// these bytes by construction — two encoders, two languages, one
/// format that was never written down as a schema — so nothing else in
/// either repository would notice them drifting apart. A shared vector
/// is the only thing that turns that into a test failure instead of
/// "every photo report is suddenly unauthenticated in production".
///
/// An identical copy lives in `onym-ios`. Changing one without the
/// other must break both sides.
#[cfg(test)]
mod cross_implementation_fixture {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        preimage: String,
        signer_public_key_hex: String,
        signature_base64: String,
    }

    fn fixture() -> Fixture {
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/media-commitment-v2.json"
        ))
        .expect("the shared fixture must exist; deleting it removes the only drift detector");
        serde_json::from_slice(&raw).expect("fixture is valid JSON")
    }

    /// The signature in the fixture verifies over the preimage bytes
    /// exactly as `file_report` checks a real one — over the disclosed
    /// string verbatim, with no reconstruction or re-encoding.
    #[test]
    fn the_fixture_signature_verifies_over_the_preimage_verbatim() {
        use base64::Engine;
        let fixture = fixture();
        let key_bytes: [u8; 32] = hex::decode(&fixture.signer_public_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let signature_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&fixture.signature_base64)
            .unwrap()
            .try_into()
            .unwrap();

        key.verify_strict(fixture.preimage.as_bytes(), &Signature::from_bytes(&signature_bytes))
            .expect("the vector's signature must verify over its exact preimage bytes");
    }

    /// And this crate reads the commitment the Swift signer produced.
    #[test]
    fn the_fixture_preimage_parses_as_a_media_commitment() {
        let fixture = fixture();
        let Disclosed::Media(items) = parse_disclosed(&fixture.preimage).unwrap() else {
            panic!("the shared vector must be read as media evidence");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].mime_type, "image/jpeg");
        assert_eq!(items[0].plaintext_byte_length, 421_337);
        assert_eq!(items[0].width, Some(1200));
        assert_eq!(items[0].height, Some(1600));
        assert_eq!(items[0].plaintext_sha256, "1a".repeat(32));
    }

    /// The escaped slash is not cosmetic. The Swift encoder does not set
    /// `withoutEscapingSlashes`, so a MIME type arrives as
    /// `image\/jpeg` — and since the signature covers these bytes
    /// verbatim, "tidying" it on either side invalidates every proof.
    #[test]
    fn the_media_type_slash_is_escaped_in_the_signed_bytes() {
        assert!(fixture().preimage.contains(r"image\/jpeg"));
    }
}
