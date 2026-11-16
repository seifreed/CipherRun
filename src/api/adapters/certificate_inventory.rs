use crate::api::{models::error::ApiError, state::AppState};
use crate::application::{
    CertificateInventoryPage, CertificateInventoryPort, CertificateInventoryQuery,
    CertificateInventoryRecord,
};
use crate::db::CertificateInventoryService;

pub async fn load_inventory_page(
    reader: &impl CertificateInventoryPort,
    query: &CertificateInventoryQuery,
) -> Result<CertificateInventoryPage, ApiError> {
    reader.list_certificates(query).await.map_err(|error| {
        ApiError::internal_with_diagnostic("list_certificates", error.observability_code())
    })
}

pub async fn load_inventory_record(
    reader: &impl CertificateInventoryPort,
    fingerprint: &str,
) -> Result<Option<CertificateInventoryRecord>, ApiError> {
    reader.get_certificate(fingerprint).await.map_err(|error| {
        ApiError::internal_with_diagnostic("get_certificate", error.observability_code())
    })
}

pub async fn load_inventory_record_for_owner(
    reader: &impl CertificateInventoryPort,
    fingerprint: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
) -> Result<Option<CertificateInventoryRecord>, ApiError> {
    reader
        .get_certificate_for_owner(fingerprint, principal_id, tenant_id)
        .await
        .map_err(|error| {
            ApiError::internal_with_diagnostic(
                "get_certificate_for_owner",
                error.observability_code(),
            )
        })
}

pub fn inventory_service_from_state(
    state: &AppState,
) -> Result<CertificateInventoryService<'_>, ApiError> {
    let db_pool = state.db_pool.as_ref().ok_or_else(|| {
        ApiError::service_unavailable_with_diagnostic(
            "load_certificate_inventory",
            "database_not_configured",
        )
    })?;

    Ok(CertificateInventoryService::new(db_pool))
}
