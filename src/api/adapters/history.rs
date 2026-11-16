use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{ScanHistoryPage, ScanHistoryPort, ScanHistoryQuery};
use crate::db::ScanHistoryService;

pub async fn load_scan_history(
    reader: &impl ScanHistoryPort,
    query: &ScanHistoryQuery,
) -> Result<ScanHistoryPage, ApiError> {
    reader.get_history(query).await.map_err(|error| {
        ApiError::internal_with_diagnostic("load_scan_history", error.observability_code())
    })
}

pub fn history_service_from_state(state: &AppState) -> Result<ScanHistoryService<'_>, ApiError> {
    let db_pool = state.db_pool.as_ref().ok_or_else(|| {
        ApiError::service_unavailable_with_diagnostic(
            "load_scan_history",
            "database_not_configured",
        )
    })?;

    Ok(ScanHistoryService::new(db_pool))
}
