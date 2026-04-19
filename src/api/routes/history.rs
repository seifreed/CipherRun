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
use crate::security::{validate_hostname, validate_port};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::sync::Arc;

/// Maximum allowed limit for history queries to prevent DoS
const MAX_HISTORY_LIMIT: usize = 1000;

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

impl HistoryQuery {
    /// Validate query parameters against the API contract.
    fn validate(self) -> Result<Self, ApiError> {
        validate_port(self.port).map_err(|err| ApiError::BadRequest(err.to_string()))?;

        if self.limit == 0 || self.limit > MAX_HISTORY_LIMIT {
            return Err(ApiError::BadRequest(format!(
                "Invalid limit: must be between 1 and {}.",
                MAX_HISTORY_LIMIT
            )));
        }

        Ok(self)
    }
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

    #[test]
    fn test_history_query_limit_bounds() {
        let query = HistoryQuery {
            port: 443,
            limit: MAX_HISTORY_LIMIT,
        };
        let validated = query.validate().expect("validation should succeed");
        assert_eq!(validated.limit, MAX_HISTORY_LIMIT);

        let query = HistoryQuery {
            port: 443,
            limit: 0,
        };
        let err = query.validate().expect_err("zero limit should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_history_query_rejects_limit_above_contract_max() {
        let query = HistoryQuery {
            port: 443,
            limit: MAX_HISTORY_LIMIT + 1,
        };

        let err = query.validate().expect_err("limit above max should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_history_query_rejects_invalid_port() {
        let query = HistoryQuery { port: 0, limit: 10 };

        let err = query.validate().expect_err("port zero should fail");
        assert!(matches!(err, ApiError::BadRequest(_)));
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
        ("domain" = String, Path, description = "Hostname or IP address"),
        ("port" = Option<u16>, Query, description = "Port number (default: 443, valid range: 1-65535)"),
        ("limit" = Option<usize>, Query, description = "Number of results (default: 10, min: 1, max: 1000)")
    ),
    responses(
        (status = 200, description = "Scan history", body = ScanHistoryResponse),
        (status = 400, description = "Invalid query parameters", body = ApiErrorResponse),
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
    let query = query.validate()?;

    validate_hostname(&domain).map_err(|err| ApiError::BadRequest(err.to_string()))?;

    let service = history_service_from_state(&state)?;
    let history_query = history_query_from_api(domain.clone(), &query);
    let scans = load_scan_history(&service, &history_query).await?;

    if scans.is_empty() {
        return Err(ApiError::NotFound(format!(
            "No scan history found for {}:{}",
            domain, query.port
        )));
    }

    Ok(Json(present_scan_history(domain, query.port, scans)))
}
