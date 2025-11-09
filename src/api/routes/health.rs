// Health Check Route

use crate::api::{models::response::HealthResponse, state::AppState};
use axum::{extract::State, Json};
use std::sync::Arc;

/// Health check endpoint
///
/// Returns the health status of the API service
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let active_scans = state.active_scans().await;
    let queued_scans = state.queued_scans().await;

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime_seconds(),
        active_scans,
        queued_scans,
        database: None, // TODO: Add database health check
    })
}
