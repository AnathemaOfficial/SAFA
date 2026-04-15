use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AmaError {
    #[error("malformed request: {message}")]
    BadRequest { message: String },

    #[error("impossible")]
    Impossible,

    #[error("validation error: {message}")]
    Validation {
        error_class: String,
        message: String,
    },

    #[error("conflict: {message}")]
    Conflict { message: String },

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("unsupported media type")]
    UnsupportedMediaType,

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("service unavailable: {message}")]
    ServiceUnavailable { message: String },
}

impl AmaError {
    pub fn http_status_and_body(&self) -> (u16, serde_json::Value) {
        match self {
            AmaError::Impossible => (403, json!({"status": "impossible"})),
            AmaError::BadRequest { message } => (
                400,
                json!({"status": "error", "error_class": "bad_request", "message": message}),
            ),
            AmaError::Validation {
                error_class,
                message,
            } => (
                422,
                json!({"status": "error", "error_class": error_class, "message": message}),
            ),
            AmaError::Conflict { message } => (
                409,
                json!({"status": "error", "error_class": "conflict", "message": message}),
            ),
            AmaError::PayloadTooLarge => (
                413,
                json!({"status": "error", "error_class": "payload_too_large", "message": "payload exceeds limit"}),
            ),
            AmaError::UnsupportedMediaType => (
                415,
                json!({"status": "error", "error_class": "unsupported_media_type", "message": "expected application/json"}),
            ),
            AmaError::RateLimited => (
                429,
                json!({"status": "error", "error_class": "rate_limited", "message": "rate limit exceeded"}),
            ),
            AmaError::ServiceUnavailable { message } => (
                503,
                json!({"status": "error", "error_class": "service_unavailable", "message": message}),
            ),
        }
    }
}
