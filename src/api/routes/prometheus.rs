use crate::api::state::AppState;
use axum::{extract::State, http::header, response::IntoResponse};
use std::sync::Arc;

/// Export bounded process and scan counters in Prometheus text format.
pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.get_stats().await;
    let active = state.active_scans().await.unwrap_or_default();
    let queued = state.queued_scans().await.unwrap_or_default();
    let body = format!(
        "# HELP cipherrun_requests_total Total HTTP requests received.\n\
# TYPE cipherrun_requests_total counter\n\
cipherrun_requests_total {}\n\
# HELP cipherrun_responses_total Total HTTP responses produced.\n\
# TYPE cipherrun_responses_total counter\n\
cipherrun_responses_total {}\n\
# HELP cipherrun_scans_total Total scans accepted.\n\
# TYPE cipherrun_scans_total counter\n\
cipherrun_scans_total {}\n\
# HELP cipherrun_scans_completed_total Total scans completed successfully.\n\
# TYPE cipherrun_scans_completed_total counter\n\
cipherrun_scans_completed_total {}\n\
# HELP cipherrun_scans_failed_total Total scans that failed.\n\
# TYPE cipherrun_scans_failed_total counter\n\
cipherrun_scans_failed_total {}\n\
# HELP cipherrun_scans_active Current running scans.\n\
# TYPE cipherrun_scans_active gauge\n\
cipherrun_scans_active {}\n\
# HELP cipherrun_scans_queued Current queued scans.\n\
# TYPE cipherrun_scans_queued gauge\n\
cipherrun_scans_queued {}\n",
        stats.total_requests,
        stats.total_responses,
        stats.total_scans,
        stats.completed_scans,
        stats.failed_scans,
        active,
        queued,
    );
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;

    #[tokio::test]
    async fn metrics_export_uses_prometheus_text_format() {
        let state = Arc::new(AppState::new(ApiConfig::default()).unwrap());
        state.stats.write().await.increment_requests();
        let response = metrics(State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }
}
