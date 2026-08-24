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
async fn test_auth_query_key_is_rejected_everywhere() {
    let app = common::api::test_api_router();
    for path in [
        "/api/v1/stats?api_key=test-user-key",
        "/api/v1/scan/scan-id/stream?api_key=test-user-key",
    ] {
        let (status, body) = common::api::send_get_json(&app, path, None).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["message"]
                .as_str()
                .expect("error message should be a string")
                .contains("no longer supported")
        );
    }
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
async fn test_scan_webhook_requires_signing_secret() {
    let app = common::api::test_api_router();
    let mut payload = scan_payload();
    payload["webhook_url"] = serde_json::json!("https://example.com/hook");

    let (status, body) = common::api::create_scan(&app, Some("test-user-key"), payload).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("webhook_signing_secret_file")
    );
}

#[tokio::test]
async fn test_scan_owner_isolation_and_admin_access() {
    let app = common::api::test_api_router();
    let (status, created) =
        common::api::create_scan(&app, Some("test-user-key"), scan_payload()).await;
    assert_eq!(status, StatusCode::CREATED);
    let scan_id = created["scan_id"].as_str().expect("scan id should exist");
    let path = format!("/api/v1/scan/{scan_id}");

    let (owner_status, _) = common::api::send_get_json(&app, &path, Some("test-user-key")).await;
    let (other_status, _) = common::api::send_get_json(&app, &path, Some("test-other-key")).await;
    let (admin_status, _) = common::api::send_get_json(&app, &path, Some("test-admin-key")).await;

    assert_eq!(owner_status, StatusCode::OK);
    assert_eq!(other_status, StatusCode::NOT_FOUND);
    assert_eq!(admin_status, StatusCode::OK);
}

#[tokio::test]
async fn test_stream_ticket_respects_scan_ownership() {
    let app = common::api::test_api_router();
    let (status, created) =
        common::api::create_scan(&app, Some("test-user-key"), scan_payload()).await;
    assert_eq!(status, StatusCode::CREATED);
    let scan_id = created["scan_id"].as_str().expect("scan id should exist");
    let path = format!("/api/v1/scan/{scan_id}/stream-ticket");

    let (owner_status, ticket) =
        common::api::send_json(&app, "POST", &path, Some("test-user-key"), None).await;
    let (other_status, _) =
        common::api::send_json(&app, "POST", &path, Some("test-other-key"), None).await;

    assert_eq!(owner_status, StatusCode::OK);
    assert!(ticket["ticket"].is_string());
    assert_eq!(other_status, StatusCode::NOT_FOUND);
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

#[tokio::test]
async fn test_admin_can_create_rotate_and_revoke_credential() {
    let app = common::api::test_api_router();
    let payload = serde_json::json!({
        "key_id": "runtime-key",
        "principal_id": "runtime-principal",
        "tenant_id": "tenant-a",
        "permission": "User"
    });
    let (status, created) = common::api::send_json(
        &app,
        "POST",
        "/api/v1/credentials",
        Some("test-admin-key"),
        Some(payload),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = created["secret"].as_str().expect("secret is returned once");
    assert!(created["credential"]["secret_hash"].is_null());

    let (old_status, _) = common::api::send_get_json(&app, "/api/v1/stats", Some(secret)).await;
    assert_eq!(old_status, StatusCode::OK);

    let (rotate_status, rotated) = common::api::send_json(
        &app,
        "POST",
        "/api/v1/credentials/runtime-key/rotate",
        Some("test-admin-key"),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(rotate_status, StatusCode::OK);
    let rotated_secret = rotated["secret"].as_str().expect("rotated secret returned");
    let (old_after_rotate, _) =
        common::api::send_get_json(&app, "/api/v1/stats", Some(secret)).await;
    let (new_after_rotate, _) =
        common::api::send_get_json(&app, "/api/v1/stats", Some(rotated_secret)).await;
    assert_eq!(old_after_rotate, StatusCode::UNAUTHORIZED);
    assert_eq!(new_after_rotate, StatusCode::OK);

    let (revoke_status, _) = common::api::send_json(
        &app,
        "POST",
        "/api/v1/credentials/runtime-key/revoke",
        Some("test-admin-key"),
        None,
    )
    .await;
    assert_eq!(revoke_status, StatusCode::OK);
    let (revoked_status, _) =
        common::api::send_get_json(&app, "/api/v1/stats", Some(rotated_secret)).await;
    assert_eq!(revoked_status, StatusCode::UNAUTHORIZED);
}
