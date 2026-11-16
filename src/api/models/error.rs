// API Error Models

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
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
    fn metadata(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            ApiError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            ApiError::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            ApiError::ServiceUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
            }
            ApiError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
            ApiError::Scanner(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SCANNER_ERROR"),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            ApiError::Timeout(_) => (StatusCode::REQUEST_TIMEOUT, "TIMEOUT"),
        }
    }

    /// Convert to HTTP status code
    pub fn status_code(&self) -> StatusCode {
        self.metadata().0
    }

    /// Get error code string
    pub fn error_code(&self) -> &str {
        self.metadata().1
    }

    pub(crate) fn internal_with_diagnostic(
        operation: &'static str,
        cause_code: &'static str,
    ) -> Self {
        let span = tracing::Span::current();
        span.record("error_operation", operation);
        span.record("error_cause_code", cause_code);
        Self::Internal("internal operation failed".to_string())
    }

    fn response_message(&self) -> String {
        match self {
            Self::Internal(_) | Self::Database(_) | Self::Scanner(_) => {
                "Internal server error".to_string()
            }
            Self::ServiceUnavailable(_) => "Service unavailable".to_string(),
            _ => self.to_string(),
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
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            message.to_string(),
        )
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
        if status.is_server_error() {
            let error_type = match &self {
                Self::Database(_) => "database",
                Self::Scanner(_) => "scanner",
                Self::ServiceUnavailable(_) => "dependency",
                _ => "internal",
            };
            if status == StatusCode::SERVICE_UNAVAILABLE {
                tracing::warn!(
                    event_name = "api.error.response",
                    status_code = status.as_u16(),
                    error_code,
                    error_type,
                    outcome = "error",
                    "API request failed"
                );
            } else {
                tracing::error!(
                    event_name = "api.error.response",
                    status_code = status.as_u16(),
                    error_code,
                    error_type,
                    outcome = "error",
                    "API request failed"
                );
            }
        }
        let message = self.response_message();

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_api_error_status_and_code() {
        let err = ApiError::NotFound("missing".to_string());
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(err.error_code(), "NOT_FOUND");

        let err = ApiError::RateLimited("slow".to_string());
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.error_code(), "RATE_LIMITED");
    }

    #[test]
    fn test_api_error_response_builders() {
        let resp = ApiErrorResponse::bad_request("oops");
        assert_eq!(resp.status, 400);
        assert_eq!(resp.error, "BAD_REQUEST");
        assert_eq!(resp.message, "oops");

        let resp = ApiErrorResponse::unauthorized("nope").with_details("detail".to_string());
        assert_eq!(resp.status, 401);
        assert_eq!(resp.error, "UNAUTHORIZED");
        assert_eq!(resp.details.as_deref(), Some("detail"));
    }

    #[test]
    fn test_api_error_timeout_mapping() {
        let err = ApiError::Timeout("slow".to_string());
        assert_eq!(err.status_code(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(err.error_code(), "TIMEOUT");

        let resp = ApiErrorResponse::internal("oops");
        assert_eq!(resp.status, 500);
        assert_eq!(resp.error, "INTERNAL_ERROR");
    }

    #[test]
    fn test_rate_limited_builder() {
        let resp = ApiErrorResponse::rate_limited("slow down");
        assert_eq!(resp.status, 429);
        assert_eq!(resp.error, "RATE_LIMITED");
        assert_eq!(resp.message, "slow down");
    }

    #[tokio::test]
    async fn internal_error_responses_hide_diagnostic_details() {
        let errors = [
            ApiError::Internal("private database path".to_string()),
            ApiError::Database(sqlx::Error::Protocol("private SQL details".to_string())),
            ApiError::Scanner("private target details".to_string()),
            ApiError::ServiceUnavailable("private queue path".to_string()),
        ];

        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();
        let responses = tracing::subscriber::with_default(subscriber, || {
            errors
                .into_iter()
                .chain([ApiError::BadRequest("invalid input".to_string())])
                .enumerate()
                .map(|(index, error)| {
                    let request_span = tracing::info_span!(
                        "http.request",
                        request_id = "test-request-id",
                        http.route = "/api/v1/stats",
                        error_operation = tracing::field::Empty,
                        error_cause_code = tracing::field::Empty
                    );
                    let _entered = request_span.enter();
                    let error = if index == 0 {
                        ApiError::internal_with_diagnostic("query_top_domains", "database_error")
                    } else {
                        error
                    };
                    error.into_response()
                })
                .collect::<Vec<_>>()
        });

        for (index, response) in responses.into_iter().enumerate() {
            let body = to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("response body should be readable");
            let body: serde_json::Value =
                serde_json::from_slice(&body).expect("response should be JSON");
            if index < 4 {
                let expected_message = if index == 3 {
                    "Service unavailable"
                } else {
                    "Internal server error"
                };
                assert_eq!(body["message"], expected_message);
                assert!(!body.to_string().contains("private"));
            } else {
                assert_eq!(body["message"], "Bad request: invalid input");
            }
        }

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0]["level"], "ERROR");
        assert_eq!(events[0]["fields"]["error_code"], "INTERNAL_ERROR");
        assert_eq!(events[0]["fields"]["error_type"], "internal");
        assert_eq!(events[0]["spans"][0]["request_id"], "test-request-id");
        assert_eq!(events[0]["spans"][0]["http.route"], "/api/v1/stats");
        assert_eq!(
            events[0]["spans"][0]["error_operation"],
            "query_top_domains"
        );
        assert_eq!(events[0]["spans"][0]["error_cause_code"], "database_error");
        assert_eq!(events[1]["fields"]["error_code"], "DATABASE_ERROR");
        assert_eq!(events[1]["fields"]["error_type"], "database");
        assert_eq!(events[2]["fields"]["error_code"], "SCANNER_ERROR");
        assert_eq!(events[2]["fields"]["error_type"], "scanner");
        assert_eq!(events[3]["level"], "WARN");
        assert_eq!(events[3]["fields"]["error_code"], "SERVICE_UNAVAILABLE");
        assert_eq!(events[3]["fields"]["error_type"], "dependency");
        assert!(
            events
                .iter()
                .all(|event| event["fields"]["outcome"] == "error")
        );
        assert!(!output.contains("private"));
    }
}
