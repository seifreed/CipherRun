use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use cipherrun::api::state::AppState;
use cipherrun::api::{ApiConfig, Permission};
use serde::Serialize;
use serde_json::Value;
use tower::ServiceExt;

#[allow(dead_code)]
pub fn test_api_state_owned() -> AppState {
    AppState::new(ApiConfig::default()).unwrap()
}

#[allow(dead_code)]
pub fn test_api_state() -> Arc<AppState> {
    Arc::new(test_api_state_owned())
}

#[allow(dead_code)]
pub fn test_api_config() -> ApiConfig {
    let mut config = ApiConfig::default();
    config.api_keys.clear();
    config
        .api_keys
        .insert("test-admin-key".to_string(), Permission::Admin);
    config
        .api_keys
        .insert("test-user-key".to_string(), Permission::User);
    config
        .api_keys
        .insert("test-readonly-key".to_string(), Permission::ReadOnly);
    config.rate_limit_per_minute = 1000;
    config.enable_cors = false;
    config.enable_swagger = false;
    config
}

#[allow(dead_code)]
pub fn test_api_router() -> Router {
    test_api_router_with_config(test_api_config())
}

#[allow(dead_code)]
pub fn test_api_router_with_rate_limit(rate_limit_per_minute: u32) -> Router {
    let mut config = test_api_config();
    config.rate_limit_per_minute = rate_limit_per_minute;
    test_api_router_with_config(config)
}

#[allow(dead_code)]
pub fn test_api_router_with_config(config: ApiConfig) -> Router {
    use axum::{
        middleware as axum_middleware,
        routing::{delete, get, post},
    };
    use cipherrun::api::{middleware, routes};
    use tower_http::compression::CompressionLayer;

    let state = Arc::new(AppState::new(config.clone()).expect("Failed to create app state"));

    let api_routes = Router::new()
        .route("/scan", post(routes::scans::create_scan))
        .route("/scan/:id", get(routes::scans::get_scan_status))
        .route("/scan/:id", delete(routes::scans::cancel_scan))
        .route("/scan/:id/results", get(routes::scans::get_scan_results))
        .route("/health", get(routes::health::health_check))
        .route("/stats", get(routes::stats::get_stats));

    Router::new()
        .nest("/api/v1", api_routes)
        .route("/health", get(routes::health::health_check))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ))
        .layer(axum_middleware::from_fn_with_state(
            Arc::new(config.clone()),
            middleware::authenticate,
        ))
        .layer(middleware::cors_layer())
        .layer(CompressionLayer::new())
        .layer(middleware::logging_layer())
        .with_state(state)
}

#[allow(dead_code)]
pub fn request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[allow(dead_code)]
pub fn authenticated_request(method: &str, uri: &str, api_key: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", api_key)
        .body(Body::empty())
        .unwrap()
}

#[allow(dead_code)]
pub fn json_request<T: Serialize>(method: &str, uri: &str, payload: &T) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(payload).unwrap()))
        .unwrap()
}

#[allow(dead_code)]
pub async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

#[allow(dead_code)]
pub async fn send_status(app: &Router, request: Request<Body>) -> StatusCode {
    send(app, request).await.status()
}

#[allow(dead_code)]
pub async fn send_json(
    app: &Router,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);

    if let Some(key) = api_key {
        request = request.header("X-API-Key", key);
    }

    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }

    let request = if let Some(json_body) = body {
        request
            .body(Body::from(serde_json::to_string(&json_body).unwrap()))
            .unwrap()
    } else {
        request.body(Body::empty()).unwrap()
    };

    let response = send(app, request).await;
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let json = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
    };

    (status, json)
}

#[allow(dead_code)]
pub async fn send_get_json(app: &Router, path: &str, api_key: Option<&str>) -> (StatusCode, Value) {
    send_json(app, "GET", path, api_key, None).await
}

#[allow(dead_code)]
pub async fn create_scan(
    app: &Router,
    api_key: Option<&str>,
    payload: Value,
) -> (StatusCode, Value) {
    send_json(app, "POST", "/api/v1/scan", api_key, Some(payload)).await
}

#[allow(dead_code)]
pub fn scan_request_payload(target: impl Into<String>, options: Value) -> Value {
    serde_json::json!({
        "target": target.into(),
        "options": options
    })
}
