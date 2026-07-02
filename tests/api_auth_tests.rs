use axum::http::StatusCode;

mod common;

async fn assert_healthy_response(app: &axum::Router, path: &str, api_key: Option<&str>) {
    let (status, body) = common::api::send_get_json(app, path, api_key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

async fn assert_auth_error(
    app: &axum::Router,
    path: &str,
    api_key: Option<&str>,
    expected_message_fragment: &str,
) {
    let (status, body) = common::api::send_get_json(app, path, api_key).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "UNAUTHORIZED");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains(expected_message_fragment)
    );
}

#[tokio::test]
async fn test_auth_valid_admin_key_returns_200() {
    let app = common::api::test_api_router();
    assert_healthy_response(&app, "/api/v1/health", Some("test-admin-key")).await;
}

#[tokio::test]
async fn test_auth_valid_user_key_returns_200() {
    let app = common::api::test_api_router();
    assert_healthy_response(&app, "/api/v1/health", Some("test-user-key")).await;
}

#[tokio::test]
async fn test_auth_valid_readonly_key_returns_200() {
    let app = common::api::test_api_router();
    assert_healthy_response(&app, "/api/v1/health", Some("test-readonly-key")).await;
}

#[tokio::test]
async fn test_auth_invalid_key_returns_401() {
    let app = common::api::test_api_router();
    assert_auth_error(
        &app,
        "/api/v1/stats",
        Some("invalid-key-12345"),
        "Invalid API key",
    )
    .await;
}

#[tokio::test]
async fn test_auth_missing_key_returns_401() {
    let app = common::api::test_api_router();
    assert_auth_error(&app, "/api/v1/stats", None, "Missing API key").await;
}

#[tokio::test]
async fn test_auth_health_endpoint_bypasses_auth() {
    let app = common::api::test_api_router();
    assert_healthy_response(&app, "/health", None).await;
    assert_healthy_response(&app, "/api/v1/health", None).await;
}

#[tokio::test]
async fn test_auth_docs_prefix_collision_requires_auth() {
    let app = common::api::test_api_router();
    assert_auth_error(&app, "/api/docsx", None, "Missing API key").await;
}

fn scan_payload() -> serde_json::Value {
    common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "test_ciphers": false,
            "test_vulnerabilities": false,
            "analyze_certificates": false,
            "test_http_headers": false,
            "client_simulation": false,
            "full_scan": false
        }),
    )
}

#[tokio::test]
async fn test_auth_readonly_key_cannot_create_scan_returns_403() {
    let app = common::api::test_api_router();
    let (status, body) =
        common::api::create_scan(&app, Some("test-readonly-key"), scan_payload()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "FORBIDDEN");
}

#[tokio::test]
async fn test_auth_user_key_can_create_scan_returns_201() {
    let app = common::api::test_api_router();
    let (status, _body) =
        common::api::create_scan(&app, Some("test-user-key"), scan_payload()).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn test_auth_readonly_key_cannot_cancel_scan_returns_403() {
    let app = common::api::test_api_router();
    let (status, body) = common::api::send_json(
        &app,
        "DELETE",
        "/api/v1/scan/some-id",
        Some("test-readonly-key"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "FORBIDDEN");
}

#[tokio::test]
async fn test_auth_readonly_key_can_read_stats_returns_200() {
    let app = common::api::test_api_router();
    let (status, _body) =
        common::api::send_get_json(&app, "/api/v1/stats", Some("test-readonly-key")).await;
    assert_eq!(status, StatusCode::OK);
}
