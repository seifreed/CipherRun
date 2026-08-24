use crate::api::state::{AppState, AuditEvent};
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
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    state.record_request().await;
    let mut response = next.run(request).await;
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.record_response(duration_ms).await;
    let status = response.status().as_u16();
    state.stats.write().await.record_audit(AuditEvent {
        request_id: request_id.clone(),
        method: method.clone(),
        path: path.clone(),
        status,
        duration_ms,
        recorded_at: chrono::Utc::now(),
    });
    tracing::info!(
        target: "audit",
        request_id = %request_id,
        method = %method,
        path = %path,
        status,
        duration_ms,
        "api request"
    );
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("X-Request-ID", value);
    }
    response
}
