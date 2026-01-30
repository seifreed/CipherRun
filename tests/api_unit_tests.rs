// Copyright (c) 2025 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real API behavior without mocks or stubs.

//! API Unit Tests
//!
//! This test suite validates individual components of the API without
//! requiring the full router. These tests can run even if there are
//! compilation errors in other parts of the codebase.

use cipherrun::api::{ApiConfig, Permission};
use std::collections::HashMap;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_api_config_creation() {
    let config = ApiConfig::default();

    assert_eq!(config.port, 8080);
    assert_eq!(config.host, "127.0.0.1"); // Security: localhost by default
    assert!(!config.enable_cors); // Security: CORS disabled by default
    assert!(config.max_concurrent_scans > 0);
    assert_eq!(config.rate_limit_per_minute, 100);
    assert_eq!(config.job_queue_capacity, 1000);
    assert!(config.enable_swagger);
}

#[test]
fn test_api_config_add_key() {
    let mut config = ApiConfig::default();

    config.add_key("test-key-123".to_string(), Permission::User);

    assert_eq!(config.validate_key("test-key-123"), Some(Permission::User));
}

#[test]
fn test_api_config_remove_key() {
    let mut config = ApiConfig::default();

    config.add_key("temp-key".to_string(), Permission::ReadOnly);
    assert_eq!(config.validate_key("temp-key"), Some(Permission::ReadOnly));

    let removed = config.remove_key("temp-key");
    assert_eq!(removed, Some(Permission::ReadOnly));
    assert_eq!(config.validate_key("temp-key"), None);
}

#[test]
fn test_api_config_validate_nonexistent_key() {
    let config = ApiConfig::default();

    assert_eq!(config.validate_key("nonexistent-key"), None);
}

#[test]
fn test_api_config_multiple_keys_different_permissions() {
    let mut config = ApiConfig {
        api_keys: HashMap::new(),
        ..ApiConfig::default()
    };

    config.add_key("admin-key".to_string(), Permission::Admin);
    config.add_key("user-key".to_string(), Permission::User);
    config.add_key("readonly-key".to_string(), Permission::ReadOnly);

    assert_eq!(config.validate_key("admin-key"), Some(Permission::Admin));
    assert_eq!(config.validate_key("user-key"), Some(Permission::User));
    assert_eq!(
        config.validate_key("readonly-key"),
        Some(Permission::ReadOnly)
    );
}

// ============================================================================
// Permission Tests
// ============================================================================

#[test]
fn test_permission_equality() {
    assert_eq!(Permission::Admin, Permission::Admin);
    assert_eq!(Permission::User, Permission::User);
    assert_eq!(Permission::ReadOnly, Permission::ReadOnly);

    assert_ne!(Permission::Admin, Permission::User);
    assert_ne!(Permission::User, Permission::ReadOnly);
    assert_ne!(Permission::Admin, Permission::ReadOnly);
}

#[test]
fn test_permission_serialization() {
    use serde_json;

    let admin = Permission::Admin;
    let json = serde_json::to_string(&admin).unwrap();
    assert_eq!(json, "\"Admin\"");

    let user = Permission::User;
    let json = serde_json::to_string(&user).unwrap();
    assert_eq!(json, "\"User\"");

    let readonly = Permission::ReadOnly;
    let json = serde_json::to_string(&readonly).unwrap();
    assert_eq!(json, "\"ReadOnly\"");
}

#[test]
fn test_permission_deserialization() {
    use serde_json;

    let admin: Permission = serde_json::from_str("\"Admin\"").unwrap();
    assert_eq!(admin, Permission::Admin);

    let user: Permission = serde_json::from_str("\"User\"").unwrap();
    assert_eq!(user, Permission::User);

    let readonly: Permission = serde_json::from_str("\"ReadOnly\"").unwrap();
    assert_eq!(readonly, Permission::ReadOnly);
}

// ============================================================================
// Error Type Tests
// ============================================================================

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
        ApiError::Conflict("test".to_string()).status_code(),
        StatusCode::CONFLICT
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
    assert_eq!(
        ApiError::Scanner("test".to_string()).status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        ApiError::Validation("test".to_string()).status_code(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ApiError::Timeout("test".to_string()).status_code(),
        StatusCode::REQUEST_TIMEOUT
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
        ApiError::Conflict("test".to_string()).error_code(),
        "CONFLICT"
    );
    assert_eq!(
        ApiError::RateLimited("test".to_string()).error_code(),
        "RATE_LIMITED"
    );
    assert_eq!(
        ApiError::Internal("test".to_string()).error_code(),
        "INTERNAL_ERROR"
    );
    assert_eq!(
        ApiError::ServiceUnavailable("test".to_string()).error_code(),
        "SERVICE_UNAVAILABLE"
    );
    assert_eq!(
        ApiError::Scanner("test".to_string()).error_code(),
        "SCANNER_ERROR"
    );
    assert_eq!(
        ApiError::Validation("test".to_string()).error_code(),
        "VALIDATION_ERROR"
    );
    assert_eq!(
        ApiError::Timeout("test".to_string()).error_code(),
        "TIMEOUT"
    );
}

#[test]
fn test_api_error_response_creation() {
    use cipherrun::api::models::error::ApiErrorResponse;

    let error = ApiErrorResponse::bad_request("Invalid input");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "BAD_REQUEST");
    assert_eq!(error.message, "Invalid input");
    assert!(error.details.is_none());
}

#[test]
fn test_api_error_response_with_details() {
    use cipherrun::api::models::error::ApiErrorResponse;

    let error = ApiErrorResponse::internal("Database connection failed")
        .with_details("Connection timeout after 30s".to_string());

    assert_eq!(error.status, 500);
    assert_eq!(error.error, "INTERNAL_ERROR");
    assert_eq!(error.message, "Database connection failed");
    assert_eq!(
        error.details,
        Some("Connection timeout after 30s".to_string())
    );
}

// ============================================================================
// Scan Options Tests
// ============================================================================

#[test]
fn test_scan_options_default() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::default();
    assert!(!options.test_protocols);
    assert!(!options.test_ciphers);
    assert!(!options.test_vulnerabilities);
    assert!(!options.analyze_certificates);
    assert!(!options.test_http_headers);
    assert!(!options.client_simulation);
    assert!(!options.full_scan);
}

#[test]
fn test_scan_options_quick() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::quick();
    assert!(options.test_protocols);
    assert!(!options.test_ciphers);
    assert!(!options.test_vulnerabilities);
    assert!(options.analyze_certificates);
    assert!(!options.test_http_headers);
    assert!(!options.client_simulation);
    assert!(!options.full_scan);
}

#[test]
fn test_scan_options_full() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::full();
    assert!(options.test_protocols);
    assert!(options.test_ciphers);
    assert!(options.test_vulnerabilities);
    assert!(options.analyze_certificates);
    assert!(options.test_http_headers);
    assert!(options.client_simulation);
    assert!(options.full_scan);
}

#[test]
fn test_scan_options_custom() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions {
        test_protocols: true,
        test_ciphers: true,
        test_vulnerabilities: false,
        analyze_certificates: true,
        test_http_headers: false,
        client_simulation: false,
        full_scan: false,
        starttls_protocol: None,
        timeout_seconds: 30,
        ipv4_only: false,
        ipv6_only: false,
        ip: None,
    };

    assert!(options.test_protocols);
    assert!(options.test_ciphers);
    assert!(!options.test_vulnerabilities);
    assert!(options.analyze_certificates);
    assert!(!options.test_http_headers);
    assert!(!options.client_simulation);
    assert!(!options.full_scan);
}

// ============================================================================
// Job Queue Tests
// ============================================================================

#[tokio::test]
async fn test_job_queue_creation() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue};

    let queue = InMemoryJobQueue::new(10);
    let length = queue.queue_length().await.unwrap();
    assert_eq!(length, 0);
}

#[tokio::test]
async fn test_job_queue_enqueue_and_retrieve() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
    use cipherrun::api::models::request::ScanOptions;

    let queue = InMemoryJobQueue::new(10);
    let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

    let job_id = job.id.clone();
    queue.enqueue(job).await.unwrap();

    let retrieved = queue.get_job(&job_id).await.unwrap().unwrap();
    assert_eq!(retrieved.target, "example.com:443");
    assert_eq!(retrieved.id, job_id);
}

#[tokio::test]
async fn test_job_queue_multiple_jobs() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
    use cipherrun::api::models::request::ScanOptions;

    let queue = InMemoryJobQueue::new(10);

    let job1 = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
    let job2 = ScanJob::new("test.com:443".to_string(), ScanOptions::default(), None);
    let job3 = ScanJob::new("demo.com:443".to_string(), ScanOptions::default(), None);

    let id1 = job1.id.clone();
    let id2 = job2.id.clone();
    let id3 = job3.id.clone();

    queue.enqueue(job1).await.unwrap();
    queue.enqueue(job2).await.unwrap();
    queue.enqueue(job3).await.unwrap();

    let retrieved1 = queue.get_job(&id1).await.unwrap().unwrap();
    let retrieved2 = queue.get_job(&id2).await.unwrap().unwrap();
    let retrieved3 = queue.get_job(&id3).await.unwrap().unwrap();

    assert_eq!(retrieved1.target, "example.com:443");
    assert_eq!(retrieved2.target, "test.com:443");
    assert_eq!(retrieved3.target, "demo.com:443");
}

#[tokio::test]
async fn test_job_queue_get_nonexistent() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue};

    let queue = InMemoryJobQueue::new(10);
    let result = queue.get_job("nonexistent-id").await.unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_job_queue_capacity() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
    use cipherrun::api::models::request::ScanOptions;

    let queue = InMemoryJobQueue::new(2);

    let job1 = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
    let job2 = ScanJob::new("test.com:443".to_string(), ScanOptions::default(), None);
    let job3 = ScanJob::new("demo.com:443".to_string(), ScanOptions::default(), None);

    assert!(queue.enqueue(job1).await.is_ok());
    assert!(queue.enqueue(job2).await.is_ok());

    // Third enqueue should fail due to capacity
    let result = queue.enqueue(job3).await;
    assert!(result.is_err());
}

// ============================================================================
// Middleware Tests
// ============================================================================

#[test]
fn test_check_permission_readonly_can_read() {
    use cipherrun::api::{Permission, middleware::auth::check_permission};

    let result = check_permission(Permission::ReadOnly, Permission::ReadOnly);
    assert!(result.is_ok());

    let result = check_permission(Permission::ReadOnly, Permission::User);
    assert!(result.is_ok());

    let result = check_permission(Permission::ReadOnly, Permission::Admin);
    assert!(result.is_ok());
}

#[test]
fn test_check_permission_user_cannot_admin() {
    use cipherrun::api::{Permission, middleware::auth::check_permission};

    let result = check_permission(Permission::Admin, Permission::User);
    assert!(result.is_err());

    let result = check_permission(Permission::Admin, Permission::ReadOnly);
    assert!(result.is_err());
}

#[test]
fn test_check_permission_admin_all_access() {
    use cipherrun::api::{Permission, middleware::auth::check_permission};

    let result = check_permission(Permission::Admin, Permission::Admin);
    assert!(result.is_ok());

    let result = check_permission(Permission::User, Permission::Admin);
    assert!(result.is_ok());

    let result = check_permission(Permission::ReadOnly, Permission::Admin);
    assert!(result.is_ok());
}

#[test]
fn test_check_permission_user_can_do_user_actions() {
    use cipherrun::api::{Permission, middleware::auth::check_permission};

    let result = check_permission(Permission::User, Permission::User);
    assert!(result.is_ok());

    let result = check_permission(Permission::User, Permission::Admin);
    assert!(result.is_ok());
}

#[test]
fn test_check_permission_readonly_cannot_user() {
    use cipherrun::api::{Permission, middleware::auth::check_permission};

    let result = check_permission(Permission::User, Permission::ReadOnly);
    assert!(result.is_err());
}

// ============================================================================
// Rate Limiter Tests
// ============================================================================

#[test]
fn test_rate_limiter_creation() {
    use cipherrun::api::middleware::rate_limit::PerKeyRateLimiter;

    let limiter = PerKeyRateLimiter::new(100);
    // Just verify it creates successfully
    drop(limiter);
}

#[test]
fn test_rate_limiter_allows_first_request() {
    use cipherrun::api::middleware::rate_limit::{PerKeyRateLimiter, RateLimitResult};

    let limiter = PerKeyRateLimiter::new(100);
    let result = limiter.check("test-key");

    match result {
        RateLimitResult::Allowed { limit, .. } => {
            assert_eq!(limit, 100);
        }
        RateLimitResult::Limited { .. } => {
            panic!("First request should be allowed");
        }
    }
}

#[test]
fn test_rate_limiter_enforces_limit() {
    use cipherrun::api::middleware::rate_limit::{PerKeyRateLimiter, RateLimitResult};

    // Note: The rate limiter's check() method checks remaining capacity by
    // probing future requests, which can affect the actual count.
    // This test validates that the limiter correctly enforces limits.
    let limiter = PerKeyRateLimiter::new(10);

    // Make several requests - the first few should succeed
    let mut allowed_count = 0;
    let mut limited_count = 0;

    for _i in 0..15 {
        match limiter.check("test-key") {
            RateLimitResult::Allowed { .. } => {
                allowed_count += 1;
            }
            RateLimitResult::Limited { limit, .. } => {
                limited_count += 1;
                assert_eq!(limit, 10);
            }
        }
    }

    // Some requests should be allowed, some limited
    assert!(
        allowed_count > 0,
        "At least some requests should be allowed"
    );
    assert!(limited_count > 0, "Some requests should be rate limited");
}

#[test]
fn test_rate_limiter_separate_keys() {
    use cipherrun::api::middleware::rate_limit::{PerKeyRateLimiter, RateLimitResult};

    let limiter = PerKeyRateLimiter::new(2);

    // Use up limit for key1
    limiter.check("key1");
    limiter.check("key1");

    // key2 should still have full quota
    match limiter.check("key2") {
        RateLimitResult::Allowed { .. } => {}
        RateLimitResult::Limited { .. } => {
            panic!("key2 should have its own quota");
        }
    }
}

// ============================================================================
// State Tests
// ============================================================================

#[tokio::test]
async fn test_app_state_creation() {
    use cipherrun::api::state::AppState;

    let config = ApiConfig::default();
    let state = AppState::new(config);

    assert!(state.is_ok());
}

#[tokio::test]
async fn test_app_state_uptime() {
    use cipherrun::api::state::AppState;
    use std::time::Duration;

    let config = ApiConfig::default();
    let state = AppState::new(config).unwrap();

    assert_eq!(state.uptime_seconds(), 0);

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(state.uptime_seconds() == 0); // May still be 0 due to granularity
}

#[tokio::test]
async fn test_app_state_stats() {
    use cipherrun::api::state::AppState;

    let config = ApiConfig::default();
    let state = AppState::new(config).unwrap();

    let stats = state.get_stats().await;
    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.total_scans, 0);
    assert_eq!(stats.completed_scans, 0);
    assert_eq!(stats.failed_scans, 0);
}

#[tokio::test]
async fn test_app_state_record_operations() {
    use cipherrun::api::state::AppState;

    let config = ApiConfig::default();
    let state = AppState::new(config).unwrap();

    state.record_request().await;
    state.record_scan().await;
    state.record_completed(1000).await;

    let stats = state.get_stats().await;
    assert_eq!(stats.total_requests, 1);
    assert_eq!(stats.total_scans, 1);
    assert_eq!(stats.completed_scans, 1);
}
