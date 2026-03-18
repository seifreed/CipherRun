use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{
    CertificateInventoryPage, CertificateInventoryPort, CertificateInventoryQuery,
    CertificateInventoryRecord,
};
use crate::db::CertificateInventoryService;

pub async fn load_inventory_page(
    reader: &(impl CertificateInventoryPort + Sync),
    query: &CertificateInventoryQuery,
) -> Result<CertificateInventoryPage, ApiError> {
    reader
        .list_certificates(query)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to fetch certificates: {}", e)))
}

pub async fn load_inventory_record(
    reader: &(impl CertificateInventoryPort + Sync),
    fingerprint: &str,
) -> Result<Option<CertificateInventoryRecord>, ApiError> {
    reader
        .get_certificate(fingerprint)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to fetch certificate: {}", e)))
}

pub fn inventory_service_from_state(
    state: &AppState,
) -> Result<CertificateInventoryService<'_>, ApiError> {
    let db_pool = state
        .db_pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Database not configured".to_string()))?;

    Ok(CertificateInventoryService::new(db_pool))
}
