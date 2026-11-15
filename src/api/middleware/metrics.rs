use crate::api::middleware::{AuthExtension, proxy::client_ip};
use crate::api::state::{AppState, AuditEvent};
use axum::{
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

pub async fn metrics(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str())
        .unwrap_or("<unmatched>")
        .to_string();
    let client_ip = client_ip(&request, &state).map(|ip| ip.to_string());
    let owner = request
        .extensions()
        .get::<AuthExtension>()
        .map(|auth| (auth.principal_id.clone(), auth.tenant_id.clone()));
    state
        .record_request_for_owner(
            owner
                .as_ref()
                .map(|(principal_id, _)| principal_id.as_str()),
            owner
                .as_ref()
                .and_then(|(_, tenant_id)| tenant_id.as_deref()),
        )
        .await;
    let request_span = tracing::info_span!(
        "http.request",
        service = "cipherrun",
        component = "api",
        request_id = %request_id,
        http.method = %method,
        http.route = %path,
    );
    let mut response = next.run(request).instrument(request_span).await;
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    state
        .record_response_for_owner(
            owner
                .as_ref()
                .map(|(principal_id, _)| principal_id.as_str()),
            owner
                .as_ref()
                .and_then(|(_, tenant_id)| tenant_id.as_deref()),
            duration_ms,
        )
        .await;
    let status = response.status().as_u16();
    state.stats.write().await.record_audit(AuditEvent {
        request_id: request_id.clone(),
        method: method.clone(),
        path: path.clone(),
        status,
        duration_ms,
        client_ip: client_ip.clone(),
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

#[cfg(test)]
mod tests {
    use super::metrics;
    use crate::api::{ApiConfig, state::AppState};
    use axum::{Router, body::Body, middleware, routing::get};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn request_id_matches_audit_event_and_path_is_route_template() {
        let state = Arc::new(AppState::new(ApiConfig::default()).unwrap());
        let app = Router::new()
            .route("/history/{domain}", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state.clone(), metrics));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/history/private.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let request_id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        let stats = state.stats.read().await;
        let event = stats.audit_events.back().unwrap();
        assert_eq!(event.request_id, request_id);
        assert_eq!(event.path, "/history/{domain}");
        assert!(!event.path.contains("private.example"));
    }
}
