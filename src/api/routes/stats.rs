// Statistics Routes

use crate::api::{
    models::response::{ApiUsageStats, DomainStats, StatsResponse},
    state::AppState,
};
use axum::{extract::State, Json};
use std::sync::Arc;

/// Get API statistics
///
/// Returns overall API usage and scan statistics
#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "stats",
    responses(
        (status = 200, description = "API statistics", body = StatsResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = state.get_stats().await;

    // Calculate average scan duration
    let avg_scan_duration_seconds = stats.avg_scan_duration() / 1000.0;

    // Get top domains from database if available
    let top_domains = if let Some(db) = &state.db_pool {
        // Query top 10 domains from database
        get_top_domains_from_db(db, 10).await.unwrap_or_default()
    } else {
        vec![] // No database configured
    };

    // Calculate API usage stats
    let requests_last_hour = stats.requests_in_last_hour();
    let avg_response_time = stats.avg_response_time_ms();

    let api_usage = ApiUsageStats {
        requests_last_hour,
        requests_last_day: stats.total_requests,
        avg_response_time_ms: avg_response_time,
    };

    Json(StatsResponse {
        total_scans: stats.total_scans,
        completed_scans: stats.completed_scans,
        failed_scans: stats.failed_scans,
        avg_scan_duration_seconds,
        scans_last_24h: stats.scans_last_24h(),
        scans_last_7d: stats.scans_last_7d(),
        top_domains,
        api_usage,
    })
}

/// Query top domains from database
async fn get_top_domains_from_db(
    db: &crate::db::connection::DatabasePool,
    limit: i64,
) -> crate::Result<Vec<DomainStats>> {
    use crate::db::connection::DatabasePool;
    use sqlx::Row;

    match db {
        DatabasePool::Postgres(pool) => {
            let rows = sqlx::query(
                r#"
                SELECT target_hostname, COUNT(*) as scan_count,
                       MAX(scan_timestamp) as last_scan
                FROM scans
                WHERE scan_timestamp > NOW() - INTERVAL '30 days'
                GROUP BY target_hostname
                ORDER BY scan_count DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query top domains: {}", e)))?;

            Ok(rows
                .into_iter()
                .map(|row| DomainStats {
                    domain: row.get("target_hostname"),
                    scan_count: row.get::<i64, _>("scan_count") as u64,
                    last_scan: row.get("last_scan"),
                })
                .collect())
        }
        DatabasePool::Sqlite(pool) => {
            let rows = sqlx::query(
                r#"
                SELECT target_hostname, COUNT(*) as scan_count,
                       MAX(scan_timestamp) as last_scan
                FROM scans
                WHERE scan_timestamp > datetime('now', '-30 days')
                GROUP BY target_hostname
                ORDER BY scan_count DESC
                LIMIT ?
                "#,
            )
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query top domains: {}", e)))?;

            Ok(rows
                .into_iter()
                .map(|row| DomainStats {
                    domain: row.get("target_hostname"),
                    scan_count: row.get::<i64, _>("scan_count") as u64,
                    last_scan: row.get("last_scan"),
                })
                .collect())
        }
    }
}
