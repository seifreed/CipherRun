use crate::api::middleware::{AuthExtension, proxy::client_ip};
use crate::api::state::{AppState, AuditEvent};
use axum::{
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::Response,
};
#[cfg(feature = "otel")]
use opentelemetry::{
    propagation::{Extractor, TextMapPropagator},
    trace::TraceContextExt,
};
#[cfg(feature = "otel")]
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
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
    #[cfg(feature = "otel")]
    if let Some(parent) = remote_parent_context(request.headers()) {
        if request_span.set_parent(parent).is_err() {
            tracing::warn!(
                event_name = "trace_context.rejected",
                "Failed to apply trace parent"
            );
        }
    }
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

#[cfg(feature = "otel")]
fn remote_parent_context(headers: &axum::http::HeaderMap) -> Option<opentelemetry::Context> {
    let context = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
    context.span().span_context().is_valid().then_some(context)
}

#[cfg(feature = "otel")]
struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

#[cfg(feature = "otel")]
impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::metrics;
    use crate::api::{ApiConfig, state::AppState};
    use axum::{Router, body::Body, middleware, routing::get};
    #[cfg(feature = "otel")]
    use opentelemetry::trace::TraceContextExt;
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

    #[cfg(feature = "otel")]
    #[test]
    fn extracts_valid_w3c_traceparent_without_logging_header_values() {
        let headers = axum::http::HeaderMap::from_iter([(
            axum::http::header::HeaderName::from_static("traceparent"),
            axum::http::HeaderValue::from_static(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
        )]);

        let parent = super::remote_parent_context(&headers).unwrap();
        let span_context = parent.span().span_context().clone();
        assert_eq!(
            span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(span_context.span_id().to_string(), "00f067aa0ba902b7");
    }
}
