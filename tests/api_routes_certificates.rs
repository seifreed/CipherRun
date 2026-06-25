use axum::{Router, routing::get};

use cipherrun::api::routes::certificates;

mod common;

#[tokio::test]
async fn test_certificates_no_db_returns_503() {
    let state = common::api::test_api_state();

    let app = Router::new()
        .route("/certificates", get(certificates::list_certificates))
        .route(
            "/certificates/{fingerprint}",
            get(certificates::get_certificate),
        )
        .with_state(state);

    // An unconfigured database is a deliberate deployment state (see /health
    // reporting it as "not_configured" while healthy), so requesting a
    // DB-backed endpoint is Service Unavailable, not an Internal Server Error.
    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/certificates")).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/certificates/abcd")).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
}
