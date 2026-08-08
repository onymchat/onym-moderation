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
            Error::NotFound(_) => "not_found",
            Error::Internal(_) => "internal_error",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(_)
            | Error::AuthenticityUnverified(_)
            | Error::ClassOutsideMandate(_)
            | Error::WindowClosed(_)
            | Error::CaseState(_) => StatusCode::BAD_REQUEST,
            Error::SignatureInvalid(_) => StatusCode::UNAUTHORIZED,
            // Refusals of standing and jurisdiction are not the
            // caller's fault to fix by retrying; they say this
            // authority has no power here.
            Error::ReporterUnconsented | Error::NoJurisdiction => StatusCode::FORBIDDEN,
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
