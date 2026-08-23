use axum::http::StatusCode;
use serde_json::Value;

mod common;

async fn create_scan_idempotently(
    router: &axum::Router,
    idempotency_key: &str,
    payload: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    use axum::{body::Body, http::Request};

    let response = common::api::send(
        router,
        Request::builder()
            .method("POST")
            .uri("/api/v1/scan")
            .header("X-API-Key", "test-user-key")
            .header("Idempotency-Key", idempotency_key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap(),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
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
    let router = common::api::test_api_router();

    let scan_request = common::api::scan_request_payload(
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

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(body["scan_id"].is_string());
    assert_eq!(body["status"], "queued");
    assert_eq!(body["target"], "example.com:443");
    assert!(body["websocket_url"].is_string());
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_empty() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload("", serde_json::json!({}));
    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "cannot be empty");
}

#[tokio::test]
async fn test_scan_create_with_invalid_target_too_long() {
    let router = common::api::test_api_router();
    let long_target = "a".repeat(256);
    let scan_request = common::api::scan_request_payload(long_target, serde_json::json!({}));
    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "too long");
}

#[tokio::test]
async fn test_scan_create_with_malformed_target() {
    let router = common::api::test_api_router();
    let scan_request =
        common::api::scan_request_payload("not a valid target!!!", serde_json::json!({}));
    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Invalid target");
}

#[tokio::test]
async fn test_scan_create_rejects_conflicting_ip_family_options() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "ipv4_only": true,
            "ipv6_only": true
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Cannot enable both IPv4-only and IPv6-only scanning");
}

#[tokio::test]
async fn test_scan_create_rejects_zero_timeout() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "timeout_seconds": 0
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Socket timeout must be greater than 0 seconds");
}

#[tokio::test]
async fn test_scan_create_rejects_private_ip_override() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "ip": "127.0.0.1"
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Invalid IP override");
}

#[tokio::test]
async fn test_scan_create_rejects_private_webhook_url() {
    let router = common::api::test_api_router();
    let scan_request = serde_json::json!({
        "target": "example.com:443",
        "options": {
            "test_protocols": true
        },
        "webhook_url": "https://localhost/callback"
    });

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Invalid webhook_url");
}

#[tokio::test]
async fn test_scan_create_rejects_malformed_ip_override() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "ip": "not-an-ip"
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_bad_request_message(&body, "Invalid IP override");
}

#[tokio::test]
async fn test_scan_create_accepts_starttls_protocol_only() {
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "mail.example.com:25",
        serde_json::json!({
            "starttls_protocol": "smtp"
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(body["scan_id"].is_string());
    assert_eq!(body["target"], "mail.example.com:25");
}

#[tokio::test]
async fn test_scan_delete_nonexistent_returns_404() {
    let router = common::api::test_api_router();
    let (status, body) = common::api::send_json(
        &router,
        "DELETE",
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
async fn test_scan_get_nonexistent_returns_404() {
    let router = common::api::test_api_router();
    let (status, body) = common::api::send_json(
        &router,
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
    let router = common::api::test_api_router();
    let scan_request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({
            "test_protocols": true,
            "test_ciphers": false
        }),
    );

    let (status, body) =
        common::api::create_scan(&router, Some("test-user-key"), scan_request).await;
    assert_eq!(status, StatusCode::CREATED);
    let scan_id = body["scan_id"].as_str().unwrap();

    let (status, body) = common::api::send_json(
        &router,
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

#[tokio::test]
async fn test_scan_create_idempotency_replays_and_rejects_payload_change() {
    let router = common::api::test_api_router();
    let request = common::api::scan_request_payload(
        "example.com:443",
        serde_json::json!({ "test_protocols": true }),
    );

    let (first_status, first) = create_scan_idempotently(&router, "request-1", &request).await;
    let (replay_status, replay) = create_scan_idempotently(&router, "request-1", &request).await;
    assert_eq!(first_status, StatusCode::CREATED);
    assert_eq!(replay_status, StatusCode::CREATED);
    assert_eq!(first["scan_id"], replay["scan_id"]);

    let changed = common::api::scan_request_payload(
        "other.example:443",
        serde_json::json!({ "test_protocols": true }),
    );
    let (conflict_status, conflict) =
        create_scan_idempotently(&router, "request-1", &changed).await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"], "CONFLICT");
}
