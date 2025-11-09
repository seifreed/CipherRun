// Certificate Routes

use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        request::CertificateQuery,
        response::{CertificateListResponse, CertificateSummary},
    },
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use std::sync::Arc;

/// List certificates
///
/// Returns a paginated list of certificates from the inventory
#[utoipa::path(
    get,
    path = "/api/v1/certificates",
    tag = "certificates",
    params(
        CertificateQuery
    ),
    responses(
        (status = 200, description = "Certificate list", body = CertificateListResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn list_certificates(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CertificateQuery>,
) -> Result<Json<CertificateListResponse>, ApiError> {
    // TODO: Implement database query
    // For now, return empty list

    Ok(Json(CertificateListResponse {
        total: 0,
        offset: query.offset,
        limit: query.limit,
        certificates: vec![],
    }))
}

/// Get certificate details
///
/// Returns detailed information about a specific certificate
#[utoipa::path(
    get,
    path = "/api/v1/certificates/{fingerprint}",
    tag = "certificates",
    params(
        ("fingerprint" = String, Path, description = "Certificate SHA-256 fingerprint")
    ),
    responses(
        (status = 200, description = "Certificate details", body = CertificateSummary),
        (status = 404, description = "Certificate not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_certificate(
    State(state): State<Arc<AppState>>,
    Path(fingerprint): Path<String>,
) -> Result<Json<CertificateSummary>, ApiError> {
    // TODO: Implement database query
    Err(ApiError::NotFound(format!(
        "Certificate {} not found",
        fingerprint
    )))
}
