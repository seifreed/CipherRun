use crate::api::state::AppState;
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use std::sync::Arc;
use std::time::Instant;

pub async fn metrics(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    state.record_request().await;
    let response = next.run(request).await;
    state
        .record_response(start.elapsed().as_millis() as u64)
        .await;
    response
}
