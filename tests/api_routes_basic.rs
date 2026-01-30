use std::sync::Arc;

use axum::{routing::get, Router};
use tower::ServiceExt;

use cipherrun::api::config::ApiConfig;
use cipherrun::api::routes::{health, stats};
use cipherrun::api::state::AppState;

#[tokio::test]
async fn test_health_route_no_db() {
    let config = ApiConfig::default();
    let state = Arc::new(AppState::new(config).unwrap());

    let app = Router::new()
        .route("/health", get(health::health_check))
        .with_state(state);

    let response = app
        .oneshot(axum::http::Request::builder().uri("/health").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_stats_route_no_db() {
    let config = ApiConfig::default();
    let state = Arc::new(AppState::new(config).unwrap());

    let app = Router::new()
        .route("/stats", get(stats::get_stats))
        .with_state(state);

    let response = app
        .oneshot(axum::http::Request::builder().uri("/stats").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
