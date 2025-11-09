// Scan History Routes

use crate::api::{
    models::{error::{ApiError, ApiErrorResponse}, response::ScanHistoryResponse},
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_port() -> u16 {
    443
}

fn default_limit() -> usize {
    10
}

/// Get scan history
///
/// Returns scan history for a specific domain
#[utoipa::path(
    get,
    path = "/api/v1/history/{domain}",
    tag = "history",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("port" = Option<u16>, Query, description = "Port number (default: 443)"),
        ("limit" = Option<usize>, Query, description = "Number of results (default: 10)")
    ),
    responses(
        (status = 200, description = "Scan history", body = ScanHistoryResponse),
        (status = 404, description = "No history found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_history(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<ScanHistoryResponse>, ApiError> {
    // TODO: Implement database query for scan history
    // For now, return empty history

    Ok(Json(ScanHistoryResponse {
        domain,
        port: query.port,
        total_scans: 0,
        scans: vec![],
    }))
}
