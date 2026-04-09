// Scan Routes

use crate::api::{
    adapters::scan as scan_adapter,
    jobs::ScanJob,
    models::{
        error::{ApiError, ApiErrorResponse},
        request::ScanRequest,
        response::{ScanResponse, ScanStatus, ScanStatusResponse},
    },
    presenters::scans::{present_queued_scan, present_scan_status},
    state::AppState,
    ws::progress::scan_websocket_handler,
};
use crate::security::validate_target;
use crate::utils::network::canonical_target;
use axum::{
    Json,
    extract::{Path, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::info;

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
) -> Result<Json<ScanResponse>, ApiError> {
    info!("Creating new scan for target: {}", request.target);

    // SECURITY: Comprehensive input validation (CWE-20, CWE-918)
    // Validates format, length, and prevents SSRF attacks

    // Basic empty check
    if request.target.is_empty() {
        return Err(ApiError::BadRequest("Target cannot be empty".to_string()));
    }

    // SECURITY: Validate target format and prevent SSRF
    // By default, we block private IPs. If internal scanning is needed,
    // this should be configured through a separate, authorized API endpoint
    let (validated_hostname, validated_port) = validate_target(&request.target, false)
        .map_err(|e| ApiError::BadRequest(format!("Invalid target: {}", e)))?;

    // Always store and return the canonical authority form so IPv6 remains unambiguous.
    let final_target = canonical_target(&validated_hostname, validated_port.unwrap_or(443));

    info!("Validated target: {}", final_target);

    // Create scan job with validated target
    let job = ScanJob::new(final_target.clone(), request.options, request.webhook_url);

    // Enqueue via adapter
    let scan_id = scan_adapter::enqueue_scan(state.job_queue.as_ref(), job).await?;
    state.record_scan().await;
    let queued_job = scan_adapter::get_scan(state.job_queue.as_ref(), &scan_id).await?;

    Ok(Json(present_queued_scan(&queued_job, final_target)))
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
            "Scan cannot be cancelled (already completed or not found)".to_string(),
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
        (status = 404, description = "Scan not found")
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
    // Verify scan exists
    if let Ok(Some(_)) = state.job_queue.get_job(&scan_id).await {
        // Create WsState for the handler
        let ws_state = Arc::new(crate::api::ws::progress::WsState {
            progress_tx: state.progress_tx.clone(),
        });

        ws.on_upgrade(move |socket| scan_websocket_handler(socket, scan_id, ws_state))
    } else {
        // Return 404 if scan not found
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::models::request::ScanOptions;

    fn build_state() -> Arc<AppState> {
        Arc::new(AppState::new(ApiConfig::default()).expect("state should build"))
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
            options: ScanOptions::default(),
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
            options: ScanOptions::default(),
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
            options: ScanOptions::default(),
            webhook_url: None,
        };

        let response = create_scan(State(state), Json(request))
            .await
            .expect("max hostname with port should succeed");
        assert!(response.target.ends_with(":443"));
    }

    #[tokio::test]
    async fn test_create_scan_canonicalizes_ipv6_target_without_port() {
        let state = build_state();
        let request = ScanRequest {
            target: "2001:4860:4860::8888".to_string(),
            options: ScanOptions::default(),
            webhook_url: None,
        };

        let response = create_scan(State(state), Json(request))
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
}
