use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{ScanHistoryEntry, ScanHistoryPort, ScanHistoryQuery};
use crate::db::ScanHistoryService;

pub async fn load_scan_history(
    reader: &(impl ScanHistoryPort + Sync),
    query: &ScanHistoryQuery,
) -> Result<Vec<ScanHistoryEntry>, ApiError> {
    reader
        .get_history(query)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to query history: {}", e)))
}

pub fn history_service_from_state(state: &AppState) -> Result<ScanHistoryService<'_>, ApiError> {
    let db_pool = state
        .db_pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Database not configured".to_string()))?;

    Ok(ScanHistoryService::new(db_pool))
}
