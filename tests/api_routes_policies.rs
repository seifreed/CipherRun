use std::sync::Arc;

use axum::{routing::{get, post}, Router};
use tower::ServiceExt;

use cipherrun::api::config::ApiConfig;
use cipherrun::api::models::request::{PolicyEvaluationRequest, PolicyRequest};
use cipherrun::api::routes::policies;
use cipherrun::api::state::AppState;

#[tokio::test]
async fn test_policies_no_policy_dir_returns_500() {
    let config = ApiConfig::default();
    let state = Arc::new(AppState::new(config).unwrap());

    let app = Router::new()
        .route("/policies", post(policies::create_policy))
        .route("/policies/:id", get(policies::get_policy))
        .route("/policies/:id/evaluate", post(policies::evaluate_policy))
        .with_state(state);

    let request = PolicyRequest {
        name: "Test".to_string(),
        description: None,
        rules: "rules: []".to_string(),
        enabled: true,
    };

    let body = serde_json::to_string(&request).unwrap();
    let response = app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/policies")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    let response = app.clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/policies/test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    let eval_request = PolicyEvaluationRequest {
        target: "example.com:443".to_string(),
        options: Default::default(),
    };
    let body = serde_json::to_string(&eval_request).unwrap();
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/policies/test/evaluate")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}
