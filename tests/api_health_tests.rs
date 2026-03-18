use axum::http::StatusCode;

mod common;

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let app = common::api::test_api_router();

    let (status, body) = common::api::send_get_json(&app, "/health", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].is_string());
    assert!(body["uptime_seconds"].is_number());
    assert!(body["active_scans"].is_number());
    assert!(body["queued_scans"].is_number());
}

#[tokio::test]
async fn test_api_v1_health_endpoint_returns_200() {
    let app = common::api::test_api_router();

    let (status, body) = common::api::send_get_json(&app, "/api/v1/health", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert!(body.get("version").is_some());
}

#[tokio::test]
async fn test_stats_endpoint_returns_server_info() {
    let app = common::api::test_api_router();

    let (status, body) =
        common::api::send_get_json(&app, "/api/v1/stats", Some("test-user-key")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.get("total_scans").is_some());
    assert!(body.get("completed_scans").is_some());
    assert!(body.get("failed_scans").is_some());
}
