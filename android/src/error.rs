//! Errors, and their mapping onto the contract's error vocabulary
//! (Moderation.md §10) and HTTP status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),

    /// The presented identity signature does not verify over the
    /// reconstructed payload.
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    /// Contract error `verdict_invalid` — bad shape, signature, or
    /// bounds. Never executed.
    #[error("verdict_invalid: {0}")]
    VerdictInvalid(String),

    /// The verdict is structurally valid but its signed causal time is
    /// still ahead of this interface's bounded clock-skew allowance.
    /// Retrying the same bytes later can succeed, so authorities must
    /// not count this as a permanent refusal.
    #[error("verdict_not_yet_valid: {0}")]
    VerdictNotYetValid(String),

    /// Contract error `no_mandate` — the verdict references a mandate
    /// this vendor never countersigned.
    #[error("no_mandate")]
    NoMandate,

    /// Contract error `class_outside_mandate`.
    #[error("class_outside_mandate: {0}")]
    ClassOutsideMandate(String),

    /// Contract error `mark_write_failed` — Google refused the write
    /// (or the Play Integrity API was unreachable). The verdict
    /// remains valid and the write is retried on the next token
    /// presentation.
    #[error("mark_write_failed: {0}")]
    MarkWriteFailed(String),

    /// The caller is issuing requests faster than this deployment
    /// serves them (the challenge endpoint's throttle). Retryable
    /// after backing off; the authority's delivery classifier already
    /// treats `rate_limited` as a retry, never a refusal.
    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// The contract's error identifier, so a conforming authority or
    /// auditor sees the vocabulary from §10 rather than prose.
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadRequest(_) => "bad_request",
            Error::SignatureInvalid(_) => "signature_invalid",
            Error::VerdictInvalid(_) => "verdict_invalid",
            Error::VerdictNotYetValid(_) => "verdict_not_yet_valid",
            Error::NoMandate => "no_mandate",
            Error::ClassOutsideMandate(_) => "class_outside_mandate",
            Error::MarkWriteFailed(_) => "mark_write_failed",
            Error::RateLimited(_) => "rate_limited",
            Error::Internal(_) => "internal_error",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(_)
            | Error::VerdictInvalid(_)
            | Error::NoMandate
            | Error::ClassOutsideMandate(_) => StatusCode::BAD_REQUEST,
            Error::VerdictNotYetValid(_) => StatusCode::TOO_EARLY,
            Error::SignatureInvalid(_) => StatusCode::UNAUTHORIZED,
            // The verdict is valid; Google is unavailable. Retryable.
            Error::MarkWriteFailed(_) => StatusCode::SERVICE_UNAVAILABLE,
            Error::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        // Internal detail stays in the log, not the response body.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed");
        } else {
            tracing::warn!(error = %self, "request refused");
        }
        let body = Json(json!({
            "error": self.code(),
            "message": self.to_string(),
        }));
        (status, body).into_response()
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Internal(format!("store: {e}"))
    }
}
