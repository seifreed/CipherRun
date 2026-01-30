use std::sync::Arc;

use axum::{routing::get, Router};
use tower::ServiceExt;

use cipherrun::api::config::ApiConfig;
use cipherrun::api::routes::certificates;
use cipherrun::api::state::AppState;

#[tokio::test]
async fn test_certificates_no_db_returns_500() {
    let config = ApiConfig::default();
    let state = Arc::new(AppState::new(config).unwrap());

    let app = Router::new()
        .route("/certificates", get(certificates::list_certificates))
        .route("/certificates/:fingerprint", get(certificates::get_certificate))
        .with_state(state);

    let response = app.clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/certificates")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/certificates/abcd")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}
