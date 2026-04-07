use axum::{Router, routing::get};

use cipherrun::api::routes::certificates;

mod common;

#[tokio::test]
async fn test_certificates_no_db_returns_500() {
    let state = common::api::test_api_state();

    let app = Router::new()
        .route("/certificates", get(certificates::list_certificates))
        .route(
            "/certificates/{fingerprint}",
            get(certificates::get_certificate),
        )
        .with_state(state);

    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/certificates")).await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/certificates/abcd")).await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}
