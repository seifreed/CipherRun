// Scan Routes

use crate::api::{
    jobs::ScanJob,
    models::{
        error::{ApiError, ApiErrorResponse},
        request::ScanRequest,
        response::{ScanResponse, ScanStatus, ScanStatusResponse},
    },
    state::AppState,
    ws::progress::scan_websocket_handler,
};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
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

    // Validate target
    if request.target.is_empty() {
        return Err(ApiError::BadRequest("Target cannot be empty".to_string()));
    }

    // Record scan in stats
    state.record_scan().await;

    // Create scan job
    let job = ScanJob::new(request.target.clone(), request.options, request.webhook_url);

    let scan_id = job.id.clone();
    let queued_at = job.queued_at;

    // Enqueue job
    state
        .job_queue
        .enqueue(job)
        .await
        .map_err(|e| ApiError::ServiceUnavailable(format!("Failed to queue scan: {}", e)))?;

    // Generate WebSocket URL
    let websocket_url = format!("/api/v1/scan/{}/stream", scan_id);

    Ok(Json(ScanResponse {
        scan_id,
        status: ScanStatus::Queued,
        target: request.target,
        websocket_url: Some(websocket_url),
        queued_at,
        estimated_completion: None,
    }))
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
    // Get job from queue
    let job = state
        .job_queue
        .get_job(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;

    // Build results URL if completed
    let results_url = if matches!(job.status, ScanStatus::Completed) {
        Some(format!("/api/v1/scan/{}/results", id))
    } else {
        None
    };

    Ok(Json(ScanStatusResponse {
        scan_id: job.id,
        status: job.status,
        progress: job.progress,
        current_stage: job.current_stage,
        eta_seconds: job.eta_seconds,
        started_at: job.started_at,
        completed_at: job.completed_at,
        error: job.error,
        results_url,
    }))
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
    // Get job from queue
    let job = state
        .job_queue
        .get_job(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;

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
