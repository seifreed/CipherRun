// Scan History Routes

use crate::api::{
    models::{
        error::{ApiError, ApiErrorResponse},
        response::ScanHistoryResponse,
    },
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
    // Get database pool or return error
    let db = state
        .db_pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("Database not configured".to_string()))?;

    // Query scan history from database
    let scans = query_scan_history(db, &domain, query.port, query.limit as i64)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to query history: {}", e)))?;

    let total_scans = scans.len();

    Ok(Json(ScanHistoryResponse {
        domain,
        port: query.port,
        total_scans,
        scans,
    }))
}

/// Query scan history from database
async fn query_scan_history(
    db: &crate::db::connection::DatabasePool,
    hostname: &str,
    port: u16,
    limit: i64,
) -> crate::Result<Vec<crate::api::models::response::ScanHistoryItem>> {
    use crate::db::connection::DatabasePool;
    use sqlx::Row;

    let port_i32 = port as i32;

    match db {
        DatabasePool::Postgres(pool) => {
            let rows = sqlx::query(
                r#"
                SELECT scan_id, scan_timestamp, overall_grade, overall_score,
                       scan_duration_ms
                FROM scans
                WHERE target_hostname = $1 AND target_port = $2
                ORDER BY scan_timestamp DESC
                LIMIT $3
                "#,
            )
            .bind(hostname)
            .bind(port_i32)
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
            })?;

            Ok(rows
                .into_iter()
                .map(|row| crate::api::models::response::ScanHistoryItem {
                    scan_id: row.get::<i64, _>("scan_id") as u64,
                    timestamp: row.get("scan_timestamp"),
                    grade: row.get("overall_grade"),
                    score: row.get::<Option<i32>, _>("overall_score").map(|s| s as u8),
                    duration_ms: row
                        .get::<Option<i64>, _>("scan_duration_ms")
                        .map(|d| d as u64),
                })
                .collect())
        }
        DatabasePool::Sqlite(pool) => {
            let rows = sqlx::query(
                r#"
                SELECT scan_id, scan_timestamp, overall_grade, overall_score,
                       scan_duration_ms
                FROM scans
                WHERE target_hostname = ? AND target_port = ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
                "#,
            )
            .bind(hostname)
            .bind(port_i32)
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
            })?;

            Ok(rows
                .into_iter()
                .map(|row| crate::api::models::response::ScanHistoryItem {
                    scan_id: row.get::<i64, _>("scan_id") as u64,
                    timestamp: row.get("scan_timestamp"),
                    grade: row.get("overall_grade"),
                    score: row.get::<Option<i32>, _>("overall_score").map(|s| s as u8),
                    duration_ms: row
                        .get::<Option<i64>, _>("scan_duration_ms")
                        .map(|d| d as u64),
                })
                .collect())
        }
    }
}
