use crate::api::state::{AppState, HTTP_RESPONSE_DURATION_BUCKETS_MS};
use axum::{extract::State, http::header, response::IntoResponse};
use std::fmt::Write as _;
use std::sync::Arc;

/// Export bounded process and scan counters in Prometheus text format.
pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.get_stats().await;
    let active = state.active_scans().await.unwrap_or_default();
    let queued = state.queued_scans().await.unwrap_or_default();
    let mut body = format!(
        "# HELP cipherrun_requests_total Total HTTP requests received.\n\
# TYPE cipherrun_requests_total counter\n\
cipherrun_requests_total {}\n\
# HELP cipherrun_responses_total Total HTTP responses produced.\n\
# TYPE cipherrun_responses_total counter\n\
cipherrun_responses_total {}\n\
# HELP cipherrun_http_responses_4xx_total Total HTTP responses with 4xx status.\n\
# TYPE cipherrun_http_responses_4xx_total counter\n\
cipherrun_http_responses_4xx_total {}\n\
# HELP cipherrun_http_responses_5xx_total Total HTTP responses with 5xx status.\n\
# TYPE cipherrun_http_responses_5xx_total counter\n\
cipherrun_http_responses_5xx_total {}\n\
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
        stats.http_responses_4xx,
        stats.http_responses_5xx,
        stats.total_scans,
        stats.completed_scans,
        stats.failed_scans,
        active,
        queued,
    );
    body.push_str(
        "# HELP cipherrun_http_response_duration_milliseconds HTTP response duration in milliseconds.\n\
# TYPE cipherrun_http_response_duration_milliseconds histogram\n",
    );
    let mut cumulative_bucket_count = 0u64;
    for (upper_bound, count) in HTTP_RESPONSE_DURATION_BUCKETS_MS
        .iter()
        .zip(stats.http_response_duration_buckets)
    {
        cumulative_bucket_count = cumulative_bucket_count.saturating_add(count);
        writeln!(
            body,
            "cipherrun_http_response_duration_milliseconds_bucket{{le=\"{upper_bound}\"}} {cumulative_bucket_count}"
        )
        .expect("writing Prometheus metrics to a String cannot fail");
    }
    writeln!(
        body,
        "cipherrun_http_response_duration_milliseconds_bucket{{le=\"+Inf\"}} {}\ncipherrun_http_response_duration_milliseconds_sum {}\ncipherrun_http_response_duration_milliseconds_count {}",
        stats.total_responses, stats.total_response_time_ms, stats.total_responses
    )
    .expect("writing Prometheus metrics to a String cannot fail");
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
        {
            let mut stats = state.stats.write().await;
            stats.increment_requests();
            stats.record_http_response(5, 404);
            stats.record_http_response(6, 200);
            stats.record_http_response(6_000, 503);
        }
        let response = metrics(State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("cipherrun_http_responses_4xx_total 1\n"));
        assert!(body.contains("cipherrun_http_responses_5xx_total 1\n"));
        assert!(
            body.contains("cipherrun_http_response_duration_milliseconds_bucket{le=\"5\"} 1\n")
        );
        assert!(
            body.contains("cipherrun_http_response_duration_milliseconds_bucket{le=\"10\"} 2\n")
        );
        assert!(
            body.contains("cipherrun_http_response_duration_milliseconds_bucket{le=\"+Inf\"} 3\n")
        );
        assert!(body.contains("cipherrun_http_response_duration_milliseconds_sum 6011\n"));
        assert!(body.contains("cipherrun_http_response_duration_milliseconds_count 3\n"));
    }
}
