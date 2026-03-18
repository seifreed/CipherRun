use axum::{Router, routing::get};

use cipherrun::api::routes::{health, stats};

mod common;

#[tokio::test]
async fn test_health_route_no_db() {
    let state = common::api::test_api_state();

    let app = Router::new()
        .route("/health", get(health::health_check))
        .with_state(state);

    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/health")).await,
        axum::http::StatusCode::OK
    );
}

#[tokio::test]
async fn test_stats_route_no_db() {
    let state = common::api::test_api_state();

    let app = Router::new()
        .route("/stats", get(stats::get_stats))
        .with_state(state);

    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/stats")).await,
        axum::http::StatusCode::OK
    );
}
