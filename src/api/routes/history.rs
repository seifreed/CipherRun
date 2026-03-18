// Scan History Routes

use crate::api::adapters::history::{history_service_from_state, load_scan_history};
use crate::api::adapters::history_query::history_query_from_api;
use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        response::ScanHistoryResponse,
    },
    presenters::history::present_scan_history,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, Query, State},
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_query_defaults() {
        let query: HistoryQuery =
            serde_json::from_str("{}").expect("test assertion should succeed");
        assert_eq!(query.port, 443);
        assert_eq!(query.limit, 10);
    }
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
    let service = history_service_from_state(&state)?;
    let history_query = history_query_from_api(domain.clone(), &query);
    let scans = load_scan_history(&service, &history_query).await?;

    Ok(Json(present_scan_history(domain, query.port, scans)))
}
