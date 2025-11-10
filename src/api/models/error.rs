// API Error Models

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// API Error Response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorResponse {
    /// HTTP status code
    pub status: u16,

    /// Error code
    pub error: String,

    /// Error message
    pub message: String,

    /// Optional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Rate Limit Error Response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RateLimitErrorResponse {
    /// Error message
    pub error: String,

    /// Rate limit (requests per window)
    pub limit: u32,

    /// Window duration in seconds
    pub window_seconds: u64,

    /// Seconds until rate limit resets
    pub retry_after: u64,
}

/// API Error Types
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimited(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Scanner error: {0}")]
    Scanner(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

impl ApiError {
    /// Convert to HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Scanner(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
        }
    }

    /// Get error code string
    pub fn error_code(&self) -> &str {
        match self {
            ApiError::BadRequest(_) => "BAD_REQUEST",
            ApiError::Unauthorized(_) => "UNAUTHORIZED",
            ApiError::Forbidden(_) => "FORBIDDEN",
            ApiError::NotFound(_) => "NOT_FOUND",
            ApiError::Conflict(_) => "CONFLICT",
            ApiError::RateLimited(_) => "RATE_LIMITED",
            ApiError::Internal(_) => "INTERNAL_ERROR",
            ApiError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            ApiError::Database(_) => "DATABASE_ERROR",
            ApiError::Scanner(_) => "SCANNER_ERROR",
            ApiError::Validation(_) => "VALIDATION_ERROR",
            ApiError::Timeout(_) => "TIMEOUT",
        }
    }
}

impl ApiErrorResponse {
    /// Create new error response
    pub fn new(status: StatusCode, error: &str, message: String) -> Self {
        Self {
            status: status.as_u16(),
            error: error.to_string(),
            message,
            details: None,
        }
    }

    /// Create with details
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Unauthorized error
    pub fn unauthorized(message: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message.to_string())
    }

    /// Bad request error
    pub fn bad_request(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message.to_string())
    }

    /// Not found error
    pub fn not_found(message: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message.to_string())
    }

    /// Rate limited error
    pub fn rate_limited(message: &str) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            message.to_string(),
        )
    }

    /// Internal error
    pub fn internal(message: &str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            message.to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        let message = self.to_string();

        let body = ApiErrorResponse::new(status, error_code, message);

        (status, Json(body)).into_response()
    }
}

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

// Conversion from anyhow::Error
impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}
