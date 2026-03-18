use axum::{
    Router,
    routing::{get, post},
};

use cipherrun::api::models::request::{PolicyEvaluationRequest, PolicyRequest};
use cipherrun::api::routes::policies;

mod common;

#[tokio::test]
async fn test_policies_no_policy_dir_returns_500() {
    let state = common::api::test_api_state();

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

    assert_eq!(
        common::api::send_status(
            &app,
            common::api::json_request("POST", "/policies", &request)
        )
        .await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/policies/test")).await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );

    let eval_request = PolicyEvaluationRequest {
        target: "example.com:443".to_string(),
        options: Default::default(),
    };
    assert_eq!(
        common::api::send_status(
            &app,
            common::api::json_request("POST", "/policies/test/evaluate", &eval_request)
        )
        .await,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}
