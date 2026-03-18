use axum::http::StatusCode;
use serde_json::Value;

mod common;

fn create_test_router() -> axum::Router {
    common::api::test_api_router()
}

async fn send_request(
    router: &mut axum::Router,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    common::api::send_json(router, method, path, api_key, body).await
}

async fn create_scan(
    router: &mut axum::Router,
    api_key: Option<&str>,
    payload: Value,
) -> (StatusCode, Value) {
    common::api::create_scan(router, api_key, payload).await
}

fn scan_request_payload(target: impl Into<String>, options: Value) -> Value {
    common::api::scan_request_payload(target, options)
}

fn assert_bad_request_message(body: &Value, expected_message_fragment: &str) {
    assert_eq!(body["error"], "BAD_REQUEST");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains(expected_message_fragment)
    );
}

#[tokio::test]
async fn test_scan_create_with_valid_target() {
    let mut router = create_test_router();

    let scan_request = scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "test_ciphers": false,
            "test_vulnerabilities": false,
            "analyze_certificates": true,
            "test_http_headers": false,
            "client_simulation": false,
            "full_scan": false
        }),
    );

    let (status, body) = create_scan(&mut router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["scan_id"].is_string());
    assert_eq!(body["status"], "queued");
    assert_eq!(body["target"], "example.com:443");
    assert!(body["websocket_url"].is_string());
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_empty() {
    let mut router = create_test_router();
    let scan_request = scan_request_payload("", serde_json::json!({}));
    let (status, body) = create_scan(&mut router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "cannot be empty");
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_too_long() {
    let mut router = create_test_router();
    let long_target = "a".repeat(256);
    let scan_request = scan_request_payload(long_target, serde_json::json!({}));
    let (status, body) = create_scan(&mut router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "too long");
}

#[tokio::test]
async fn test_scan_create_with_malformed_target() {
    let mut router = create_test_router();
    let scan_request = scan_request_payload("not a valid target!!!", serde_json::json!({}));
    let (status, body) = create_scan(&mut router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Invalid target");
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
    let scan_request = scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "test_ciphers": false
        }),
    );

    let (status, body) = create_scan(&mut router, Some("test-user-key"), scan_request).await;
    assert_eq!(status, StatusCode::OK);
    let scan_id = body["scan_id"].as_str().unwrap();

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
