#[test]
fn test_api_error_status_codes() {
    use axum::http::StatusCode;
    use cipherrun::api::models::error::ApiError;

    assert_eq!(
        ApiError::BadRequest("test".to_string()).status_code(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ApiError::Unauthorized("test".to_string()).status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        ApiError::Forbidden("test".to_string()).status_code(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        ApiError::NotFound("test".to_string()).status_code(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ApiError::RateLimited("test".to_string()).status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        ApiError::Internal("test".to_string()).status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        ApiError::ServiceUnavailable("test".to_string()).status_code(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn test_api_error_codes() {
    use cipherrun::api::models::error::ApiError;

    assert_eq!(
        ApiError::BadRequest("test".to_string()).error_code(),
        "BAD_REQUEST"
    );
    assert_eq!(
        ApiError::Unauthorized("test".to_string()).error_code(),
        "UNAUTHORIZED"
    );
    assert_eq!(
        ApiError::Forbidden("test".to_string()).error_code(),
        "FORBIDDEN"
    );
    assert_eq!(
        ApiError::NotFound("test".to_string()).error_code(),
        "NOT_FOUND"
    );
    assert_eq!(
        ApiError::RateLimited("test".to_string()).error_code(),
        "RATE_LIMITED"
    );
    assert_eq!(
        ApiError::Internal("test".to_string()).error_code(),
        "INTERNAL_ERROR"
    );
}
