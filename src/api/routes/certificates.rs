// Certificate Routes

use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        request::CertificateQuery,
        response::{CertificateListResponse, CertificateSummary},
    },
    state::AppState,
};
use crate::db::DatabasePool;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use sqlx::Row;
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
    // Get database pool
    let db_pool = state
        .db_pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Database not configured".to_string()))?;

    // Build query with filters
    let mut where_clauses = Vec::new();
    let mut params: Vec<String> = Vec::new();

    // Filter by hostname if provided
    if let Some(ref hostname) = query.hostname {
        where_clauses.push("EXISTS (SELECT 1 FROM scan_certificates sc JOIN scans s ON sc.scan_id = s.scan_id WHERE sc.cert_id = c.cert_id AND s.target_hostname = ?)");
        params.push(hostname.clone());
    }

    // Filter by expiring within days if provided
    if let Some(days) = query.expiring_within_days {
        let cutoff_date = Utc::now() + chrono::Duration::days(days as i64);
        where_clauses.push("c.not_after <= ?");
        params.push(cutoff_date.to_rfc3339());
    }

    let where_clause = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Determine sort order
    let order_by = match query.sort.as_str() {
        "expiry_desc" => "c.not_after DESC",
        "issued_asc" => "c.not_before ASC",
        "issued_desc" => "c.not_before DESC",
        _ => "c.not_after ASC", // expiry_asc (default)
    };

    // Query certificates based on database type
    let (total, certificates) = match db_pool.as_ref() {
        DatabasePool::Postgres(pool) => {
            // Get total count
            let count_query = format!(
                "SELECT COUNT(*) as count FROM certificates c {}",
                where_clause
            );
            let mut count_stmt = sqlx::query(&count_query);
            for param in &params {
                count_stmt = count_stmt.bind(param);
            }
            let total: i64 = count_stmt
                .fetch_one(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to count certificates: {}", e)))?
                .get("count");

            // Get certificates with pagination
            let list_query = format!(
                r#"
                SELECT
                    c.fingerprint_sha256,
                    c.subject,
                    c.issuer,
                    c.not_before,
                    c.not_after,
                    c.san_domains,
                    ARRAY_AGG(DISTINCT s.target_hostname) as hostnames
                FROM certificates c
                LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                LEFT JOIN scans s ON sc.scan_id = s.scan_id
                {}
                GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
                ORDER BY {}
                LIMIT $1 OFFSET $2
                "#,
                where_clause, order_by
            );

            let stmt = sqlx::query(&list_query)
                .bind(query.limit as i64)
                .bind(query.offset as i64);

            let rows = stmt
                .fetch_all(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to fetch certificates: {}", e)))?;

            let certs = rows
                .into_iter()
                .map(|row| {
                    let fingerprint: String = row.get("fingerprint_sha256");
                    let subject: String = row.get("subject");
                    let issuer: String = row.get("issuer");
                    let not_before: chrono::DateTime<Utc> = row.get("not_before");
                    let not_after: chrono::DateTime<Utc> = row.get("not_after");
                    let san_json: Option<String> = row.try_get("san_domains").ok();
                    let hostnames: Option<Vec<String>> = row.try_get("hostnames").ok();

                    let san: Vec<String> = san_json
                        .and_then(|j| serde_json::from_str(&j).ok())
                        .unwrap_or_default();

                    let common_name = extract_cn_from_subject(&subject);
                    let now = Utc::now();
                    let days_until_expiry = (not_after - now).num_days();

                    CertificateSummary {
                        fingerprint,
                        common_name,
                        san,
                        issuer,
                        valid_from: not_before,
                        valid_until: not_after,
                        days_until_expiry,
                        is_expired: not_after < now,
                        is_expiring_soon: (0..30).contains(&days_until_expiry),
                        hostnames: hostnames.unwrap_or_default(),
                    }
                })
                .collect();

            (total as usize, certs)
        }
        DatabasePool::Sqlite(pool) => {
            // Get total count
            let count_query = format!(
                "SELECT COUNT(*) as count FROM certificates c {}",
                where_clause
            );
            let mut count_stmt = sqlx::query(&count_query);
            for param in &params {
                count_stmt = count_stmt.bind(param);
            }
            let total: i64 = count_stmt
                .fetch_one(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to count certificates: {}", e)))?
                .get("count");

            // Get certificates with pagination
            let list_query = format!(
                r#"
                SELECT
                    c.fingerprint_sha256,
                    c.subject,
                    c.issuer,
                    c.not_before,
                    c.not_after,
                    c.san_domains,
                    GROUP_CONCAT(DISTINCT s.target_hostname) as hostnames
                FROM certificates c
                LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                LEFT JOIN scans s ON sc.scan_id = s.scan_id
                {}
                GROUP BY c.cert_id
                ORDER BY {}
                LIMIT ? OFFSET ?
                "#,
                where_clause, order_by
            );

            let stmt = sqlx::query(&list_query)
                .bind(query.limit as i64)
                .bind(query.offset as i64);

            let rows = stmt
                .fetch_all(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to fetch certificates: {}", e)))?;

            let certs = rows
                .into_iter()
                .map(|row| {
                    let fingerprint: String = row.get("fingerprint_sha256");
                    let subject: String = row.get("subject");
                    let issuer: String = row.get("issuer");
                    let not_before: chrono::DateTime<Utc> = row.get("not_before");
                    let not_after: chrono::DateTime<Utc> = row.get("not_after");
                    let san_json: Option<String> = row.try_get("san_domains").ok();
                    let hostnames_str: Option<String> = row.try_get("hostnames").ok();

                    let san: Vec<String> = san_json
                        .and_then(|j| serde_json::from_str(&j).ok())
                        .unwrap_or_default();

                    let hostnames: Vec<String> = hostnames_str
                        .map(|s| s.split(',').map(|h| h.to_string()).collect())
                        .unwrap_or_default();

                    let common_name = extract_cn_from_subject(&subject);
                    let now = Utc::now();
                    let days_until_expiry = (not_after - now).num_days();

                    CertificateSummary {
                        fingerprint,
                        common_name,
                        san,
                        issuer,
                        valid_from: not_before,
                        valid_until: not_after,
                        days_until_expiry,
                        is_expired: not_after < now,
                        is_expiring_soon: (0..30).contains(&days_until_expiry),
                        hostnames,
                    }
                })
                .collect();

            (total as usize, certs)
        }
    };

    Ok(Json(CertificateListResponse {
        total,
        offset: query.offset,
        limit: query.limit,
        certificates,
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
    // Get database pool
    let db_pool = state
        .db_pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Database not configured".to_string()))?;

    // Query certificate based on database type
    let cert = match db_pool.as_ref() {
        DatabasePool::Postgres(pool) => {
            let row = sqlx::query(
                r#"
                SELECT
                    c.fingerprint_sha256,
                    c.subject,
                    c.issuer,
                    c.not_before,
                    c.not_after,
                    c.san_domains,
                    ARRAY_AGG(DISTINCT s.target_hostname) as hostnames
                FROM certificates c
                LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                LEFT JOIN scans s ON sc.scan_id = s.scan_id
                WHERE c.fingerprint_sha256 = $1
                GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
                "#,
            )
            .bind(&fingerprint)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to fetch certificate: {}", e)))?
            .ok_or_else(|| ApiError::NotFound(format!("Certificate {} not found", fingerprint)))?;

            let subject: String = row.get("subject");
            let issuer: String = row.get("issuer");
            let not_before: chrono::DateTime<Utc> = row.get("not_before");
            let not_after: chrono::DateTime<Utc> = row.get("not_after");
            let san_json: Option<String> = row.try_get("san_domains").ok();
            let hostnames: Option<Vec<String>> = row.try_get("hostnames").ok();

            let san: Vec<String> = san_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();

            let common_name = extract_cn_from_subject(&subject);
            let now = Utc::now();
            let days_until_expiry = (not_after - now).num_days();

            CertificateSummary {
                fingerprint: fingerprint.clone(),
                common_name,
                san,
                issuer,
                valid_from: not_before,
                valid_until: not_after,
                days_until_expiry,
                is_expired: not_after < now,
                is_expiring_soon: (0..30).contains(&days_until_expiry),
                hostnames: hostnames.unwrap_or_default(),
            }
        }
        DatabasePool::Sqlite(pool) => {
            let row = sqlx::query(
                r#"
                SELECT
                    c.fingerprint_sha256,
                    c.subject,
                    c.issuer,
                    c.not_before,
                    c.not_after,
                    c.san_domains,
                    GROUP_CONCAT(DISTINCT s.target_hostname) as hostnames
                FROM certificates c
                LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                LEFT JOIN scans s ON sc.scan_id = s.scan_id
                WHERE c.fingerprint_sha256 = ?
                GROUP BY c.cert_id
                "#,
            )
            .bind(&fingerprint)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to fetch certificate: {}", e)))?
            .ok_or_else(|| ApiError::NotFound(format!("Certificate {} not found", fingerprint)))?;

            let subject: String = row.get("subject");
            let issuer: String = row.get("issuer");
            let not_before: chrono::DateTime<Utc> = row.get("not_before");
            let not_after: chrono::DateTime<Utc> = row.get("not_after");
            let san_json: Option<String> = row.try_get("san_domains").ok();
            let hostnames_str: Option<String> = row.try_get("hostnames").ok();

            let san: Vec<String> = san_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();

            let hostnames: Vec<String> = hostnames_str
                .map(|s| s.split(',').map(|h| h.to_string()).collect())
                .unwrap_or_default();

            let common_name = extract_cn_from_subject(&subject);
            let now = Utc::now();
            let days_until_expiry = (not_after - now).num_days();

            CertificateSummary {
                fingerprint: fingerprint.clone(),
                common_name,
                san,
                issuer,
                valid_from: not_before,
                valid_until: not_after,
                days_until_expiry,
                is_expired: not_after < now,
                is_expiring_soon: (0..30).contains(&days_until_expiry),
                hostnames,
            }
        }
    };

    Ok(Json(cert))
}

/// Extract Common Name from X.509 subject string
fn extract_cn_from_subject(subject: &str) -> String {
    subject
        .split(',')
        .find(|part| part.trim().starts_with("CN="))
        .and_then(|cn_part| cn_part.split('=').nth(1))
        .unwrap_or(subject)
        .trim()
        .to_string()
}
