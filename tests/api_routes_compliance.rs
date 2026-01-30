use std::sync::Arc;

use axum::{routing::get, Router};
use tower::ServiceExt;

use cipherrun::api::config::ApiConfig;
use cipherrun::api::routes::compliance;
use cipherrun::api::state::AppState;

#[tokio::test]
async fn test_compliance_missing_target_returns_400() {
    let config = ApiConfig::default();
    let state = Arc::new(AppState::new(config).unwrap());

    let app = Router::new()
        .route("/compliance/:framework", get(compliance::check_compliance))
        .with_state(state);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/compliance/pci-dss-v4")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}
