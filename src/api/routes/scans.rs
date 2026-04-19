// Scan Routes

use crate::api::{
    adapters::scan as scan_adapter,
    jobs::{ScanJob, executor::validate_webhook_url},
    models::{
        error::{ApiError, ApiErrorResponse},
        request::ScanRequest,
        response::{ScanResponse, ScanStatus, ScanStatusResponse},
    },
    presenters::scans::{present_queued_scan, present_scan_status},
    presenters::target_input::{scan_request_from_target, scan_request_from_target_and_options},
    state::AppState,
    ws::progress::scan_websocket_handler,
};
use axum::{
    Json,
    extract::{Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::info;

fn normalize_scan_options(
    options: Option<crate::api::models::request::ScanOptions>,
) -> Result<crate::api::models::request::ScanOptions, ApiError> {
    match options {
        None => Ok(crate::api::models::request::ScanOptions::full()),
        Some(options) if options.has_requested_scan_work() => Ok(options),
        Some(_) => Err(ApiError::BadRequest(
            "Scan options must enable at least one scan phase".to_string(),
        )),
    }
}

/// Create a new scan
///
/// Queues a new scan job and returns the scan ID
#[utoipa::path(
    post,
    path = "/api/v1/scan",
    tag = "scans",
    request_body = ScanRequest,
    responses(
        (status = 201, description = "Scan queued successfully", body = ScanResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 503, description = "Queue is full", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn create_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanResponse>), ApiError> {
    info!("Creating new scan for target: {}", request.target);

    // Basic empty check
    if request.target.is_empty() {
        return Err(ApiError::BadRequest("Target cannot be empty".to_string()));
    }

    // Validate the public target first so malformed/blocked targets are rejected
    // before evaluating scan options.
    scan_request_from_target(&request.target)?;

    let options = normalize_scan_options(request.options)?;
    let validated_request = scan_request_from_target_and_options(&request.target, &options)?;
    let final_target = validated_request.target.clone().ok_or_else(|| {
        ApiError::Internal("Validated scan request is missing target".to_string())
    })?;

    if let Some(webhook_url) = request.webhook_url.as_deref() {
        validate_webhook_url(webhook_url)
            .await
            .map_err(|error| ApiError::BadRequest(format!("Invalid webhook_url: {}", error)))?;
    }

    info!("Validated target: {}", final_target);

    // Create scan job with validated target
    let job = ScanJob::new(final_target.clone(), options, request.webhook_url);

    // Enqueue via adapter
    let scan_id = scan_adapter::enqueue_scan(state.job_queue.as_ref(), job).await?;
    state.record_scan().await;
    let queued_job = scan_adapter::get_scan(state.job_queue.as_ref(), &scan_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(present_queued_scan(&queued_job, final_target)),
    ))
}

/// Get scan status
///
/// Returns the current status and progress of a scan
#[utoipa::path(
    get,
    path = "/api/v1/scan/{id}",
    tag = "scans",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan status", body = ScanStatusResponse),
        (status = 404, description = "Scan not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ScanStatusResponse>, ApiError> {
    // Get job via adapter
    let job = scan_adapter::get_scan(state.job_queue.as_ref(), &id).await?;

    Ok(Json(present_scan_status(job)))
}

/// Get scan results
///
/// Returns the complete scan results for a completed scan
#[utoipa::path(
    get,
    path = "/api/v1/scan/{id}/results",
    tag = "scans",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan results", body = serde_json::Value),
        (status = 404, description = "Scan not found", body = ApiErrorResponse),
        (status = 400, description = "Scan not completed", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_scan_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get job via adapter
    let job = scan_adapter::get_scan(state.job_queue.as_ref(), &id).await?;

    // Check if scan is completed
    if !matches!(job.status, ScanStatus::Completed) {
        return Err(ApiError::BadRequest(format!(
            "Scan is not completed yet (status: {:?})",
            job.status
        )));
    }

    // Get results
    let results = job
        .results
        .ok_or_else(|| ApiError::Internal("Scan completed but results not found".to_string()))?;

    // Convert to JSON
    let json = serde_json::to_value(&results)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize results: {}", e)))?;

    Ok(Json(json))
}

/// Cancel a scan
///
/// Cancels a queued or running scan
#[utoipa::path(
    delete,
    path = "/api/v1/scan/{id}",
    tag = "scans",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan cancelled"),
        (status = 404, description = "Scan not found", body = ApiErrorResponse),
        (status = 400, description = "Scan cannot be cancelled", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn cancel_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let job = scan_adapter::get_scan(state.job_queue.as_ref(), &id).await?;

    if !matches!(job.status, ScanStatus::Queued | ScanStatus::Running) {
        return Err(ApiError::BadRequest(
            "Scan cannot be cancelled (already completed, failed, or cancelled)".to_string(),
        ));
    }

    let cancelled = state
        .job_queue
        .cancel_job(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if cancelled {
        Ok(Json(serde_json::json!({
            "message": "Scan cancelled successfully",
            "scan_id": id
        })))
    } else {
        Err(ApiError::BadRequest(
            "Scan cannot be cancelled (already completed, failed, or cancelled)".to_string(),
        ))
    }
}

/// WebSocket endpoint for scan progress
///
/// Streams real-time progress updates for a specific scan
#[utoipa::path(
    get,
    path = "/api/v1/scan/{id}/stream",
    tag = "scans",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 101, description = "WebSocket connection established"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Failed to access scan state", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    match scan_adapter::get_scan(state.job_queue.as_ref(), &scan_id).await {
        Ok(_) => {
            let ws_state = Arc::new(crate::api::ws::progress::WsState {
                progress_tx: state.progress_tx.clone(),
            });

            ws.on_upgrade(move |socket| scan_websocket_handler(socket, scan_id, ws_state))
        }
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{JobQueue, ScanExecutor};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::models::request::ScanOptions;
    use crate::api::state::ApiStats;
    use async_trait::async_trait;
    use axum::{Router, http::StatusCode, routing::get};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::net::TcpListener;
    use tokio::sync::{RwLock, oneshot};
    use tokio_tungstenite::{connect_async, tungstenite::Error as WsError};

    fn build_state() -> Arc<AppState> {
        Arc::new(AppState::new(ApiConfig::default()).expect("state should build"))
    }

    fn build_state_with_queue(job_queue: Arc<dyn JobQueue>) -> Arc<AppState> {
        let config = Arc::new(ApiConfig::default());
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));

        Arc::new(AppState {
            config,
            job_queue,
            progress_tx: executor.progress_broadcaster(),
            executor,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: None,
        })
    }

    fn valid_hostname_253() -> String {
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )
    }

    #[tokio::test]
    async fn test_create_scan_empty_target() {
        let state = build_state();
        let request = ScanRequest {
            target: "".to_string(),
            options: Some(ScanOptions::default()),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("empty target should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_target_too_long() {
        let state = build_state();
        let request = ScanRequest {
            target: "a".repeat(256),
            options: Some(ScanOptions::default()),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("too long target should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_allows_max_hostname_with_port() {
        let state = build_state();
        let request = ScanRequest {
            target: format!("{}:443", valid_hostname_253()),
            options: Some(ScanOptions::full()),
            webhook_url: None,
        };

        let (_, Json(response)) = create_scan(State(state), Json(request))
            .await
            .expect("max hostname with port should succeed");
        assert!(response.target.ends_with(":443"));
    }

    #[tokio::test]
    async fn test_create_scan_canonicalizes_ipv6_target_without_port() {
        let state = build_state();
        let request = ScanRequest {
            target: "2001:4860:4860::8888".to_string(),
            options: Some(ScanOptions::full()),
            webhook_url: None,
        };

        let (_, Json(response)) = create_scan(State(state), Json(request))
            .await
            .expect("public IPv6 target without port should succeed");

        assert_eq!(response.target, "[2001:4860:4860::8888]:443");
    }

    #[tokio::test]
    async fn test_get_scan_status_not_found() {
        let state = build_state();
        let err = get_scan_status(State(state), Path("missing".to_string()))
            .await
            .expect_err("missing job should fail");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_get_scan_results_not_completed() {
        let state = build_state();
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let id = job.id.clone();
        state
            .job_queue
            .enqueue(job)
            .await
            .expect("enqueue should succeed");

        let err = get_scan_results(State(state), Path(id))
            .await
            .expect_err("not completed should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_cancel_scan_returns_not_found_for_missing_job() {
        let state = build_state();

        let err = cancel_scan(State(state), Path("missing".to_string()))
            .await
            .expect_err("missing scan should fail");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_cancel_scan_returns_bad_request_for_completed_job() {
        let state = build_state();
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::full(), None);
        let id = job.id.clone();
        job.mark_completed(crate::scanner::ScanResults::default());
        state
            .job_queue
            .enqueue(job)
            .await
            .expect("enqueue should succeed");

        let err = cancel_scan(State(state), Path(id))
            .await
            .expect_err("completed scan should not be cancellable");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_defaults_missing_options_to_full_scan() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: None,
            webhook_url: None,
        };

        let (_, Json(response)) = create_scan(State(state.clone()), Json(request))
            .await
            .expect("request should succeed");
        let job = state
            .job_queue
            .get_job(&response.scan_id)
            .await
            .expect("job lookup should succeed")
            .expect("job should exist");

        assert!(job.options.full_scan);
        assert!(job.options.analyze_certificates);
    }

    #[tokio::test]
    async fn test_create_scan_rejects_explicit_empty_options() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions::default()),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("empty options should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_rejects_conflicting_ip_family_options() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions {
                test_protocols: true,
                ipv4_only: true,
                ipv6_only: true,
                ..Default::default()
            }),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("conflicting IP family options should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_rejects_zero_timeout() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions {
                test_protocols: true,
                timeout_seconds: 0,
                ..Default::default()
            }),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("zero timeout should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_rejects_private_ip_override() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions {
                test_protocols: true,
                ip: Some("127.0.0.1".to_string()),
                ..Default::default()
            }),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("private IP override should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_rejects_malformed_ip_override() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions {
                test_protocols: true,
                ip: Some("not-an-ip".to_string()),
                ..Default::default()
            }),
            webhook_url: None,
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("malformed IP override should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_create_scan_rejects_invalid_webhook_url() {
        let state = build_state();
        let request = ScanRequest {
            target: "example.com".to_string(),
            options: Some(ScanOptions {
                test_protocols: true,
                ..Default::default()
            }),
            webhook_url: Some("https://localhost/callback".to_string()),
        };

        let err = create_scan(State(state), Json(request))
            .await
            .expect_err("private webhook target should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    struct FailingGetJobQueue;

    #[async_trait]
    impl JobQueue for FailingGetJobQueue {
        async fn enqueue(&self, _job: ScanJob) -> crate::Result<String> {
            panic!("enqueue should not be called")
        }

        async fn dequeue(&self) -> crate::Result<Option<ScanJob>> {
            panic!("dequeue should not be called")
        }

        async fn get_job(&self, _id: &str) -> crate::Result<Option<ScanJob>> {
            Err(crate::TlsError::Other("queue backend failed".to_string()))
        }

        async fn update_job(&self, _job: &ScanJob) -> crate::Result<()> {
            panic!("update_job should not be called")
        }

        async fn update_job_preserving_cancelled(&self, _job: &ScanJob) -> crate::Result<bool> {
            panic!("update_job_preserving_cancelled should not be called")
        }

        async fn cancel_job(&self, _id: &str) -> crate::Result<bool> {
            panic!("cancel_job should not be called")
        }

        async fn queue_length(&self) -> crate::Result<usize> {
            panic!("queue_length should not be called")
        }

        async fn list_jobs(&self) -> crate::Result<Vec<ScanJob>> {
            panic!("list_jobs should not be called")
        }

        async fn active_jobs_count(&self) -> crate::Result<usize> {
            panic!("active_jobs_count should not be called")
        }
    }

    async fn start_ws_test_server(state: Arc<AppState>) -> (String, oneshot::Sender<()>) {
        let app = Router::new()
            .route("/api/v1/scan/{id}/stream", get(websocket_handler))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("address should resolve");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });

        tokio::spawn(async move {
            let _ = server.await;
        });

        (format!("ws://{}/api/v1/scan", addr), shutdown_tx)
    }

    #[tokio::test]
    async fn test_websocket_handler_returns_not_found_for_missing_scan() {
        let state = build_state();
        let (base_url, shutdown) = start_ws_test_server(state).await;
        let err = connect_async(format!("{}/missing/stream", base_url))
            .await
            .expect_err("missing scan should reject websocket upgrade");

        match err {
            WsError::Http(response) => assert_eq!(response.status(), StatusCode::NOT_FOUND),
            other => panic!("unexpected websocket error: {}", other),
        }

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_websocket_handler_returns_internal_error_on_queue_failure() {
        let queue: Arc<dyn JobQueue> = Arc::new(FailingGetJobQueue);
        let state = build_state_with_queue(queue);
        let (base_url, shutdown) = start_ws_test_server(state).await;
        let err = connect_async(format!("{}/broken/stream", base_url))
            .await
            .expect_err("queue failure should reject websocket upgrade");

        match err {
            WsError::Http(response) => {
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR)
            }
            other => panic!("unexpected websocket error: {}", other),
        }

        let _ = shutdown.send(());
    }
}
