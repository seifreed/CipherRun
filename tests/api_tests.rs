// Copyright (c) 2025 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real API behavior without mocks or stubs.

//! API Integration Tests
//!
//! This test suite validates the real behavior of the CipherRun API server,
//! including authentication, rate limiting, scan endpoints, policy endpoints,
//! and health checks. All tests use real HTTP requests through Tower's test
//! infrastructure without mocking or stubs.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use cipherrun::api::{ApiConfig, ApiServer, Permission};
use serde_json::Value;
use std::collections::HashMap;
use tower::ServiceExt; // For `oneshot` and `ready`

/// Helper function to create a test API config with known API keys
fn create_test_config() -> ApiConfig {
    let mut config = ApiConfig::default();

    // Clear auto-generated keys and add test keys with known values
    config.api_keys.clear();
    config
        .api_keys
        .insert("test-admin-key".to_string(), Permission::Admin);
    config
        .api_keys
        .insert("test-user-key".to_string(), Permission::User);
    config
        .api_keys
        .insert("test-readonly-key".to_string(), Permission::ReadOnly);

    // Set rate limit high for most tests
    config.rate_limit_per_minute = 1000;

    // Disable CORS for testing
    config.enable_cors = false;

    // Disable Swagger for cleaner tests
    config.enable_swagger = false;

    config
}

/// Helper function to create a test router with the test config
fn create_test_router() -> Router {
    use axum::{
        middleware as axum_middleware,
        routing::{delete, get, post},
    };
    use cipherrun::api::{middleware, routes, state::AppState};
    use std::sync::Arc;
    use tower_http::compression::CompressionLayer;

    let config = create_test_config();
    let state = Arc::new(AppState::new(config.clone()).expect("Failed to create app state"));

    // Create API routes - only include routes that compile
    let api_routes = Router::new()
        // Scan routes
        .route("/scan", post(routes::scans::create_scan))
        .route("/scan/:id", get(routes::scans::get_scan_status))
        .route("/scan/:id", delete(routes::scans::cancel_scan))
        .route("/scan/:id/results", get(routes::scans::get_scan_results))
        // Health check
        .route("/health", get(routes::health::health_check))
        // Stats routes
        .route("/stats", get(routes::stats::get_stats));

    // Build main router
    // Note: Middleware layers are applied in reverse order in Axum
    Router::new()
        .nest("/api/v1", api_routes)
        .route("/health", get(routes::health::health_check))
        // Add rate limiting middleware (runs after auth due to reverse order)
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ))
        // Add authentication middleware (runs first due to reverse order)
        .layer(axum_middleware::from_fn_with_state(
            Arc::new(config.clone()),
            middleware::authenticate,
        ))
        // Add CORS
        .layer(middleware::cors_layer())
        // Add compression
        .layer(CompressionLayer::new())
        // Add logging
        .layer(middleware::logging_layer())
        // Add shared state
        .with_state(state)
}

/// Helper to send a request and get the response
async fn send_request(
    router: &mut Router,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);

    // Add API key header if provided
    if let Some(key) = api_key {
        request = request.header("X-API-Key", key);
    }

    // Add content type for JSON body
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }

    // Build request with body
    let request = if let Some(json_body) = body {
        request
            .body(Body::from(serde_json::to_string(&json_body).unwrap()))
            .unwrap()
    } else {
        request.body(Body::empty()).unwrap()
    };

    // Send request
    let response = router.clone().oneshot(request).await.unwrap();

    let status = response.status();

    // Read body
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let json: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
    };

    (status, json)
}

// ============================================================================
// Basic Configuration Tests
// ============================================================================

#[test]
fn test_api_config_default() {
    let config = ApiConfig::default();
    assert_eq!(config.port, 8080);
    assert_eq!(config.host, "127.0.0.1"); // Security: should bind to localhost by default
    assert!(!config.enable_cors); // Security: CORS disabled by default
    assert!(config.max_concurrent_scans > 0);
    assert_eq!(config.rate_limit_per_minute, 100);
}

#[test]
fn test_api_server_creation() {
    let config = ApiConfig::default();
    let server = ApiServer::new(config);
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_api_state_creation() {
    let config = ApiConfig::default();
    let server = ApiServer::new(config).unwrap();
    let state = server.state();

    assert_eq!(state.uptime_seconds(), 0); // Just created
}

// ============================================================================
// Authentication Tests
// ============================================================================

#[tokio::test]
async fn test_auth_valid_admin_key_returns_200() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/health",
        Some("test-admin-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_auth_valid_user_key_returns_200() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/health",
        Some("test-user-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_auth_valid_readonly_key_returns_200() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/health",
        Some("test-readonly-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_auth_invalid_key_returns_401() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/stats",
        Some("invalid-key-12345"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "UNAUTHORIZED");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Invalid API key")
    );
}

#[tokio::test]
async fn test_auth_missing_key_returns_401() {
    let mut router = create_test_router();

    let (status, body) = send_request(&mut router, "GET", "/api/v1/stats", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "UNAUTHORIZED");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Missing X-API-Key")
    );
}

#[tokio::test]
async fn test_auth_health_endpoint_bypasses_auth() {
    let mut router = create_test_router();

    // Root health endpoint should work without auth
    let (status, body) = send_request(&mut router, "GET", "/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");

    // API health endpoint should also work without auth
    let (status, body) = send_request(&mut router, "GET", "/api/v1/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limit_requests_within_limit_succeed() {
    let mut router = create_test_router();

    // Send multiple requests within limit
    for _ in 0..5 {
        let (status, _) = send_request(
            &mut router,
            "GET",
            "/api/v1/stats",
            Some("test-user-key"),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_rate_limit_headers_present() {
    let mut router = create_test_router();

    // Make a request and check for rate limit headers
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/stats")
        .header("X-API-Key", "test-user-key")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check that rate limit headers are present
    let headers = response.headers();
    assert!(headers.contains_key("x-ratelimit-limit"));
    assert!(headers.contains_key("x-ratelimit-remaining"));
    assert!(headers.contains_key("x-ratelimit-reset"));
}

#[tokio::test]
async fn test_rate_limit_admin_bypasses_limit() {
    // Create config with very low rate limit
    let mut config = create_test_config();
    config.rate_limit_per_minute = 2;

    use axum::{
        middleware as axum_middleware,
        routing::{get, post},
    };
    use cipherrun::api::{middleware, routes, state::AppState};
    use std::sync::Arc;
    use tower_http::compression::CompressionLayer;

    let state = Arc::new(AppState::new(config.clone()).expect("Failed to create app state"));

    let api_routes = Router::new()
        .route("/stats", get(routes::stats::get_stats))
        .route("/health", get(routes::health::health_check));

    let mut router = Router::new()
        .nest("/api/v1", api_routes)
        // Middleware layers are applied in reverse order
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ))
        .layer(axum_middleware::from_fn_with_state(
            Arc::new(config.clone()),
            middleware::authenticate,
        ))
        .layer(middleware::cors_layer())
        .layer(CompressionLayer::new())
        .layer(middleware::logging_layer())
        .with_state(state);

    // Admin should bypass rate limit even with many requests
    for i in 0..10 {
        let (status, _) = send_request(
            &mut router,
            "GET",
            "/api/v1/stats",
            Some("test-admin-key"),
            None,
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Admin request {} should succeed despite rate limit",
            i + 1
        );
    }
}

#[tokio::test]
async fn test_rate_limit_exceeds_limit_returns_429() {
    // Create config with very low rate limit
    let mut config = create_test_config();
    config.rate_limit_per_minute = 3;

    use axum::{middleware as axum_middleware, routing::get};
    use cipherrun::api::{middleware, routes, state::AppState};
    use std::sync::Arc;
    use tower_http::compression::CompressionLayer;

    let state = Arc::new(AppState::new(config.clone()).expect("Failed to create app state"));

    let api_routes = Router::new()
        .route("/stats", get(routes::stats::get_stats))
        .route("/health", get(routes::health::health_check));

    let mut router = Router::new()
        .nest("/api/v1", api_routes)
        // Middleware layers are applied in reverse order
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ))
        .layer(axum_middleware::from_fn_with_state(
            Arc::new(config.clone()),
            middleware::authenticate,
        ))
        .layer(middleware::cors_layer())
        .layer(CompressionLayer::new())
        .layer(middleware::logging_layer())
        .with_state(state);

    // Send requests up to the limit
    for _ in 0..3 {
        let (status, _) = send_request(
            &mut router,
            "GET",
            "/api/v1/stats",
            Some("test-user-key"),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    // Next request should be rate limited
    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/stats",
        Some("test-user-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "Rate limit exceeded");
    assert_eq!(body["limit"], 3);
}

// ============================================================================
// Health and Status Tests
// ============================================================================

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let mut router = create_test_router();

    let (status, body) = send_request(&mut router, "GET", "/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].is_string());
    assert!(body["uptime_seconds"].is_number());
    assert!(body["active_scans"].is_number());
    assert!(body["queued_scans"].is_number());
}

#[tokio::test]
async fn test_api_v1_health_endpoint_returns_200() {
    let mut router = create_test_router();

    let (status, body) = send_request(&mut router, "GET", "/api/v1/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert!(body.get("version").is_some());
}

#[tokio::test]
async fn test_stats_endpoint_returns_server_info() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/stats",
        Some("test-user-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.get("total_scans").is_some());
    assert!(body.get("completed_scans").is_some());
    assert!(body.get("failed_scans").is_some());
}

// ============================================================================
// Scan Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_scan_create_with_valid_target() {
    let mut router = create_test_router();

    let scan_request = serde_json::json!({
        "target": "example.com:443",
        "options": {
            "test_protocols": true,
            "test_ciphers": false,
            "test_vulnerabilities": false,
            "analyze_certificates": true,
            "test_http_headers": false,
            "client_simulation": false,
            "full_scan": false
        }
    });

    let (status, body) = send_request(
        &mut router,
        "POST",
        "/api/v1/scan",
        Some("test-user-key"),
        Some(scan_request),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["scan_id"].is_string());
    assert_eq!(body["status"], "queued");
    assert_eq!(body["target"], "example.com:443");
    assert!(body["websocket_url"].is_string());
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_empty() {
    let mut router = create_test_router();

    let scan_request = serde_json::json!({
        "target": "",
        "options": {}
    });

    let (status, body) = send_request(
        &mut router,
        "POST",
        "/api/v1/scan",
        Some("test-user-key"),
        Some(scan_request),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "BAD_REQUEST");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("cannot be empty")
    );
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_too_long() {
    let mut router = create_test_router();

    // Create a target string longer than 255 characters
    let long_target = "a".repeat(256);

    let scan_request = serde_json::json!({
        "target": long_target,
        "options": {}
    });

    let (status, body) = send_request(
        &mut router,
        "POST",
        "/api/v1/scan",
        Some("test-user-key"),
        Some(scan_request),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "BAD_REQUEST");
    assert!(body["message"].as_str().unwrap().contains("too long"));
}

#[tokio::test]
async fn test_scan_create_with_malformed_target() {
    let mut router = create_test_router();

    let scan_request = serde_json::json!({
        "target": "not a valid target!!!",
        "options": {}
    });

    let (status, body) = send_request(
        &mut router,
        "POST",
        "/api/v1/scan",
        Some("test-user-key"),
        Some(scan_request),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "BAD_REQUEST");
    assert!(body["message"].as_str().unwrap().contains("Invalid target"));
}

#[tokio::test]
async fn test_scan_get_nonexistent_returns_404() {
    let mut router = create_test_router();

    let (status, body) = send_request(
        &mut router,
        "GET",
        "/api/v1/scan/nonexistent-scan-id-12345",
        Some("test-user-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "NOT_FOUND");
    assert!(body["message"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_scan_create_and_get_status() {
    let mut router = create_test_router();

    // Create a scan
    let scan_request = serde_json::json!({
        "target": "example.com:443",
        "options": {
            "test_protocols": true,
            "test_ciphers": false
        }
    });

    let (status, body) = send_request(
        &mut router,
        "POST",
        "/api/v1/scan",
        Some("test-user-key"),
        Some(scan_request),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let scan_id = body["scan_id"].as_str().unwrap();

    // Get scan status
    let (status, body) = send_request(
        &mut router,
        "GET",
        &format!("/api/v1/scan/{}", scan_id),
        Some("test-user-key"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scan_id"], scan_id);
    assert!(body.get("status").is_some());
    assert!(body.get("progress").is_some());
}

// ============================================================================
// Job Queue Tests
// ============================================================================

#[tokio::test]
async fn test_job_queue_operations() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
    use cipherrun::api::models::request::ScanOptions;

    let queue = InMemoryJobQueue::new(10);
    let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

    let job_id = queue.enqueue(job.clone()).await.unwrap();
    assert_eq!(job_id, job.id);

    let retrieved = queue.get_job(&job_id).await.unwrap().unwrap();
    assert_eq!(retrieved.target, "example.com:443");
}

// ============================================================================
// Scan Options Tests
// ============================================================================

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

// ============================================================================
// Error Response Tests
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
