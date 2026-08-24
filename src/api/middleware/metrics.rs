use crate::api::state::AppState;
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

pub async fn metrics(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    state.record_request().await;
    let mut response = next.run(request).await;
    state
        .record_response(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
        .await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("X-Request-ID", value);
    }
    response
}
