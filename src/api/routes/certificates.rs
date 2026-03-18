// Certificate Routes

use crate::api::adapters::certificate_inventory::{
    inventory_service_from_state, load_inventory_page, load_inventory_record,
};

use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        request::CertificateQuery,
        response::{CertificateListResponse, CertificateSummary},
    },
    presenters::certificates::present_certificate_list,
    state::AppState,
};
use crate::application::{
    CertificateInventoryQuery, CertificateInventoryRecord, CertificateInventorySort,
};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use std::sync::Arc;

fn inventory_query_from_api(query: &CertificateQuery) -> CertificateInventoryQuery {
    let sort = match query.sort.as_str() {
        "expiry_desc" => CertificateInventorySort::ExpiryDesc,
        "issued_asc" => CertificateInventorySort::IssuedAsc,
        "issued_desc" => CertificateInventorySort::IssuedDesc,
        _ => CertificateInventorySort::ExpiryAsc,
    };

    CertificateInventoryQuery {
        limit: query.limit,
        offset: query.offset,
        sort,
        hostname: query.hostname.clone(),
        expiring_within_days: query.expiring_within_days,
    }
}

fn present_inventory_record(record: CertificateInventoryRecord) -> CertificateSummary {
    crate::api::presenters::certificates::present_certificate_summary(
        crate::api::presenters::certificates::CertificateView {
            fingerprint: record.fingerprint,
            subject: record.subject,
            issuer: record.issuer,
            not_before: record.not_before,
            not_after: record.not_after,
            san_json: record.san_json,
            hostnames: record.hostnames,
        },
    )
}

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
    let inventory_service = inventory_service_from_state(&state)?;
    let inventory_page =
        load_inventory_page(&inventory_service, &inventory_query_from_api(&query)).await?;

    Ok(Json(present_certificate_list(
        inventory_page.total,
        query.offset,
        query.limit,
        inventory_page
            .certificates
            .into_iter()
            .map(present_inventory_record)
            .collect(),
    )))
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
    let inventory_service = inventory_service_from_state(&state)?;
    let cert = load_inventory_record(&inventory_service, &fingerprint)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Certificate {} not found", fingerprint)))?;

    Ok(Json(present_inventory_record(cert)))
}

#[cfg(test)]
mod tests {
    use crate::api::presenters::certificates::{CertificateView, present_certificate_summary};
    use chrono::Utc;

    #[test]
    fn presenter_extracts_cn_with_cn() {
        let subject = "C=US, O=Example Org, CN=example.com";
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: subject.to_string(),
            issuer: "issuer".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            san_json: None,
            hostnames: Vec::new(),
        });
        assert_eq!(summary.common_name, "example.com");
    }

    #[test]
    fn presenter_falls_back_to_subject_without_cn() {
        let subject = "O=Example Org, OU=Security";
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: subject.to_string(),
            issuer: "issuer".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            san_json: None,
            hostnames: Vec::new(),
        });
        assert_eq!(summary.common_name, subject);
    }
}
