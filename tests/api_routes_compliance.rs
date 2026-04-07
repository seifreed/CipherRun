use axum::{Router, routing::get};

use cipherrun::api::routes::compliance;

mod common;

#[tokio::test]
async fn test_compliance_missing_target_returns_400() {
    let state = common::api::test_api_state();

    let app = Router::new()
        .route("/compliance/{framework}", get(compliance::check_compliance))
        .with_state(state);

    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/compliance/pci-dss-v4")).await,
        axum::http::StatusCode::BAD_REQUEST
    );
}
