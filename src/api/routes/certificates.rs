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
use crate::security::validate_hostname;
use crate::utils::network::normalize_dns_hostname;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use std::sync::Arc;

const MAX_CERTIFICATE_LIMIT: usize = 1000;

fn inventory_query_from_api(
    query: &CertificateQuery,
) -> Result<CertificateInventoryQuery, ApiError> {
    let hostname = if let Some(hostname) = query.hostname.as_deref() {
        validate_hostname(hostname)
            .map_err(|err| ApiError::BadRequest(format!("Invalid hostname filter: {}", err)))?;
        Some(normalize_dns_hostname(hostname.to_string()))
    } else {
        None
    };

    if query.limit == 0 || query.limit > MAX_CERTIFICATE_LIMIT {
        return Err(ApiError::BadRequest(format!(
            "Invalid limit: must be between 1 and {}.",
            MAX_CERTIFICATE_LIMIT
        )));
    }
    if i64::try_from(query.offset).is_err() {
        return Err(ApiError::BadRequest(
            "Invalid offset: value is too large.".to_string(),
        ));
    }

    let sort = match query.sort.as_str() {
        "expiry_desc" => CertificateInventorySort::ExpiryDesc,
        "issued_asc" => CertificateInventorySort::IssuedAsc,
        "issued_desc" => CertificateInventorySort::IssuedDesc,
        "expiry_asc" => CertificateInventorySort::ExpiryAsc,
        other => {
            return Err(ApiError::BadRequest(format!(
                "Invalid sort '{}'. Supported values: expiry_asc, expiry_desc, issued_asc, issued_desc",
                other
            )));
        }
    };

    Ok(CertificateInventoryQuery {
        limit: query.limit,
        offset: query.offset,
        sort,
        hostname,
        expiring_within_days: query.expiring_within_days,
    })
}

fn present_inventory_record(
    record: CertificateInventoryRecord,
) -> Result<CertificateSummary, ApiError> {
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
    .map_err(|e| ApiError::Internal(e.to_string()))
}

fn validate_certificate_fingerprint(fingerprint: &str) -> Result<(), ApiError> {
    let normalized = fingerprint.replace(':', "");
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }

    Err(ApiError::BadRequest(
        "Invalid certificate fingerprint: expected SHA-256 hex fingerprint".to_string(),
    ))
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
        (status = 200, description = "Certificate list", body = CertificateListResponse),
        (status = 400, description = "Invalid query parameters", body = ApiErrorResponse)
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
    let inventory_query = inventory_query_from_api(&query)?;
    let inventory_page = load_inventory_page(&inventory_service, &inventory_query).await?;

    Ok(Json(present_certificate_list(
        inventory_page.total,
        query.offset,
        query.limit,
        inventory_page
            .certificates
            .into_iter()
            .map(present_inventory_record)
            .collect::<Result<Vec<_>, _>>()?,
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
        (status = 400, description = "Invalid fingerprint", body = ApiErrorResponse),
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
    validate_certificate_fingerprint(&fingerprint)?;

    let inventory_service = inventory_service_from_state(&state)?;
    let cert = load_inventory_record(&inventory_service, &fingerprint)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Certificate {} not found", fingerprint)))?;

    Ok(Json(present_inventory_record(cert)?))
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CERTIFICATE_LIMIT, inventory_query_from_api, validate_certificate_fingerprint,
    };
    use crate::api::models::request::CertificateQuery;
    use crate::api::presenters::certificates::{CertificateView, present_certificate_summary};
    use crate::application::CertificateInventorySort;
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
        })
        .expect("empty SAN should present");
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
        })
        .expect("empty SAN should present");
        assert_eq!(summary.common_name, subject);
    }

    #[test]
    fn inventory_query_accepts_supported_sort_values() {
        let query = CertificateQuery {
            sort: "issued_desc".to_string(),
            ..Default::default()
        };

        let inventory_query =
            inventory_query_from_api(&query).expect("sort should map successfully");

        assert_eq!(inventory_query.sort, CertificateInventorySort::IssuedDesc);
    }

    #[test]
    fn inventory_query_rejects_invalid_sort_values() {
        let query = CertificateQuery {
            sort: "invalid".to_string(),
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn inventory_query_accepts_contract_max_limit() {
        let query = CertificateQuery {
            limit: MAX_CERTIFICATE_LIMIT,
            ..Default::default()
        };

        let inventory_query =
            inventory_query_from_api(&query).expect("max limit should be accepted");

        assert_eq!(inventory_query.limit, MAX_CERTIFICATE_LIMIT);
    }

    #[test]
    fn inventory_query_rejects_zero_limit() {
        let query = CertificateQuery {
            limit: 0,
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn inventory_query_rejects_limit_above_contract_max() {
        let query = CertificateQuery {
            limit: MAX_CERTIFICATE_LIMIT + 1,
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn inventory_query_rejects_offset_too_large_for_database() {
        let query = CertificateQuery {
            offset: usize::MAX,
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn inventory_query_rejects_hostname_with_port() {
        let query = CertificateQuery {
            hostname: Some("example.com:443".to_string()),
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn inventory_query_accepts_rooted_fqdn_hostname_filter() {
        let query = CertificateQuery {
            hostname: Some("example.com.".to_string()),
            ..Default::default()
        };

        let inventory_query =
            inventory_query_from_api(&query).expect("rooted FQDN should be accepted");
        assert_eq!(inventory_query.hostname.as_deref(), Some("example.com"));
    }

    #[test]
    fn inventory_query_rejects_invalid_hostname_filter() {
        let query = CertificateQuery {
            hostname: Some("example..com".to_string()),
            ..Default::default()
        };

        assert!(inventory_query_from_api(&query).is_err());
    }

    #[test]
    fn certificate_fingerprint_accepts_sha256_hex_forms() {
        let plain = "a".repeat(64);
        let colon_separated = (0..32).map(|_| "aa").collect::<Vec<_>>().join(":");

        assert!(validate_certificate_fingerprint(&plain).is_ok());
        assert!(validate_certificate_fingerprint(&colon_separated).is_ok());
    }

    #[test]
    fn certificate_fingerprint_rejects_non_sha256_values() {
        assert!(validate_certificate_fingerprint("abc123").is_err());
        assert!(validate_certificate_fingerprint(&"g".repeat(64)).is_err());
        assert!(validate_certificate_fingerprint("").is_err());
    }
}
