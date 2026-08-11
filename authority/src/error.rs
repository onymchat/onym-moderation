//! Errors, mapped onto the contract's error vocabulary (Moderation.md
//! §10) and HTTP status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),

    /// A presented signature does not verify over the reconstructed
    /// bytes.
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    /// §10 `reporter_unconsented` — reporting requires a mandate
    /// naming this authority. Standing follows the reporter's mandate.
    #[error("reporter_unconsented")]
    ReporterUnconsented,

    /// §10 `no_jurisdiction` — the accused holds no mandate naming
    /// this authority. The honest disposition is refusal: abuse from a
    /// user of another interface is outside this authority's reach.
    #[error("no_jurisdiction")]
    NoJurisdiction,

    /// §10 `authenticity_unverified` — content without a proof binding
    /// it to the accused's key is a complaint, not evidence, and
    /// cannot alone support a verdict.
    #[error("authenticity_unverified: {0}")]
    AuthenticityUnverified(String),

    /// §10 `class_outside_mandate` — the class is not one the accused
    /// consented to, or not one this manifest declares.
    #[error("class_outside_mandate: {0}")]
    ClassOutsideMandate(String),

    /// §10 `window_closed` — a late appeal is refused. (A late
    /// *response* enters the record at the authority's discretion, so
    /// it does not produce this.)
    #[error("window_closed: {0}")]
    WindowClosed(String),

    /// The case exists but the requested transition is not available
    /// from its current stage.
    #[error("case_state: {0}")]
    CaseState(String),

    /// Evidence names a blob this authority does not hold. The bytes
    /// travel on their own content-addressed route, so a report can
    /// legitimately arrive before its upload finished — the client's
    /// remedy is to upload and re-file the identical report.
    #[error("media_missing: {0}")]
    MediaMissing(String),

    /// The uploaded bytes are not something this authority will decode:
    /// a media type outside the allowlist, an image it cannot parse, or
    /// dimensions outside the declared bounds. Note that a *mismatch*
    /// against the sender's signed commitment is not this — that is
    /// `authenticity_unverified`, because the failure is the proof, not
    /// the format.
    #[error("media_unsupported: {0}")]
    MediaUnsupported(String),

    /// The upload exceeds the evidence-blob ceiling.
    #[error("media_too_large: {0}")]
    MediaTooLarge(String),

    /// The uploader already holds as many unfiled uploads as this
    /// authority will hold for one key. Deliberately not
    /// `media_too_large`: nothing is wrong with the image, and a client
    /// reading only the status would otherwise shrink it and retry
    /// forever against a limit that is not about size.
    #[error("media_quota_exceeded: {0}")]
    MediaQuotaExceeded(String),

    /// This deployment's pinned model profile cannot review an image,
    /// so it does not accept image evidence at all.
    ///
    /// Distinct from `media_class_refused`, which says a *class* takes
    /// no media anywhere. This one is a property of the authority: the
    /// same report filed at an authority pinned to an image-capable
    /// profile would be accepted.
    #[error("media_unreviewable: {0}")]
    MediaUnreviewable(String),

    /// The class does not accept media evidence at this authority.
    /// `csam` is refused deliberately: accepting the bytes would make
    /// this authority a custodian of illegal imagery before it has the
    /// retention, deletion, and statutory-reporting machinery that
    /// custody requires. Refusing is not a judgement about the report.
    #[error("media_class_refused: {0}")]
    MediaClassRefused(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadRequest(_) => "bad_request",
            Error::SignatureInvalid(_) => "signature_invalid",
            Error::ReporterUnconsented => "reporter_unconsented",
            Error::NoJurisdiction => "no_jurisdiction",
            Error::AuthenticityUnverified(_) => "authenticity_unverified",
            Error::ClassOutsideMandate(_) => "class_outside_mandate",
            Error::WindowClosed(_) => "window_closed",
            Error::CaseState(_) => "case_state",
            Error::MediaMissing(_) => "media_missing",
            Error::MediaUnsupported(_) => "media_unsupported",
            Error::MediaTooLarge(_) => "media_too_large",
            Error::MediaQuotaExceeded(_) => "media_quota_exceeded",
            Error::MediaUnreviewable(_) => "media_unreviewable",
            Error::MediaClassRefused(_) => "media_class_refused",
            Error::NotFound(_) => "not_found",
            Error::Internal(_) => "internal_error",
        }
    }

    fn status(&self) -> StatusCode {
        // Each refusal gets a status that says which *kind* of refusal
        // it is. Collapsing them all into 400 made "your JSON is
        // malformed" indistinguishable from "this case was already
        // decided" without parsing the body, which is exactly the
        // distinction a client needs to know whether retrying, fixing,
        // or giving up is the right response. The §10 code in the body
        // stays authoritative.
        match self {
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            // Well-formed, but the content does not prove what it
            // claims to prove.
            Error::AuthenticityUnverified(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::SignatureInvalid(_) => StatusCode::UNAUTHORIZED,
            // The window existed and has passed — not something a
            // corrected request can recover.
            Error::WindowClosed(_) => StatusCode::GONE,
            // The case is real but not in a stage that admits this.
            Error::CaseState(_) => StatusCode::CONFLICT,
            // Refusals of standing and jurisdiction are not the
            // caller's fault to fix by retrying; they say this
            // authority has no power here.
            Error::ReporterUnconsented | Error::NoJurisdiction | Error::ClassOutsideMandate(_) => {
                StatusCode::FORBIDDEN
            }
            // The report is well-formed and the proof is fine; the
            // bytes it names simply are not here yet. Deliberately not
            // 409: clients already read a conflict on this route as
            // "these exact bytes are already on file", which is a
            // terminal, benign state — the opposite of this one, which
            // is fixed by uploading and re-filing. 424 says the request
            // depended on something that did not happen.
            Error::MediaMissing(_) => StatusCode::FAILED_DEPENDENCY,
            Error::MediaUnsupported(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Error::MediaTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            // Retryable, but only after the caller files or abandons
            // what it is already holding.
            Error::MediaQuotaExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            Error::MediaUnreviewable(_) | Error::MediaClassRefused(_) => StatusCode::FORBIDDEN,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::warn!(error = %self, "request refused");
        }
        let body = Json(json!({ "error": self.code(), "message": self.to_string() }));
        (status, body).into_response()
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Internal(format!("store: {e}"))
    }
}
