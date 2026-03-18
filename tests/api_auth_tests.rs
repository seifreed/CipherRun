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
    assert_auth_error(&app, "/api/v1/stats", None, "Missing X-API-Key").await;
}

#[tokio::test]
async fn test_auth_health_endpoint_bypasses_auth() {
    let app = common::api::test_api_router();
    assert_healthy_response(&app, "/health", None).await;
    assert_healthy_response(&app, "/api/v1/health", None).await;
}
