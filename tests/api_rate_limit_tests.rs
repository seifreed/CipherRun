use axum::http::StatusCode;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn test_rate_limit_requests_within_limit_succeed() {
    let app = common::api::test_api_router();

    for _ in 0..5 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_rate_limit_headers_present() {
    let app = common::api::test_api_router();
    let request = common::api::authenticated_request("GET", "/api/v1/stats", "test-user-key");
    let response = app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(headers.contains_key("x-ratelimit-limit"));
    assert!(headers.contains_key("x-ratelimit-remaining"));
    assert!(headers.contains_key("x-ratelimit-reset"));
}

#[tokio::test]
async fn test_rate_limit_admin_bypasses_limit() {
    let app = common::api::test_api_router_with_rate_limit(2);

    for i in 0..10 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-admin-key"), None)
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
    let app = common::api::test_api_router_with_rate_limit(3);

    for _ in 0..3 {
        let (status, _) =
            common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, body) =
        common::api::send_json(&app, "GET", "/api/v1/stats", Some("test-user-key"), None).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "Rate limit exceeded");
    assert_eq!(body["limit"], 3);
}
