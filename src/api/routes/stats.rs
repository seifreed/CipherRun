// Statistics Routes

use crate::api::{
    models::error::ApiError,
    models::response::{ApiUsageStats, DomainStats, StatsResponse},
    presenters::stats::{StatsParams, present_stats_response},
    state::AppState,
};
use axum::{Json, extract::State};
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
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatsResponse>, ApiError> {
    let stats = state.get_stats().await;

    // Calculate average scan duration
    let avg_scan_duration_seconds = stats.avg_scan_duration() / 1000.0;

    // Get top domains from database if available
    let top_domains = if let Some(db) = &state.db_pool {
        // Query top 10 domains from database
        get_top_domains_from_db(db, 10)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to load top domains: {}", e)))?
    } else {
        vec![] // No database configured
    };

    // Calculate API usage stats
    let requests_last_hour = stats.requests_in_last_hour();
    let avg_response_time = stats.avg_response_time_ms();

    let api_usage = ApiUsageStats {
        requests_last_hour,
        requests_last_day: stats.requests_in_last_day(),
        avg_response_time_ms: avg_response_time,
    };

    Ok(Json(present_stats_response(StatsParams {
        total_scans: stats.total_scans,
        completed_scans: stats.completed_scans,
        failed_scans: stats.failed_scans,
        avg_scan_duration_seconds,
        scans_last_24h: stats.scans_last_24h(),
        scans_last_7d: stats.scans_last_7d(),
        top_domains,
        api_usage,
    })))
}

/// Query top domains from database
async fn get_top_domains_from_db(
    db: &crate::db::connection::DatabasePool,
    limit: i64,
) -> crate::Result<Vec<DomainStats>> {
    let rows = db.get_top_domains(limit).await?;
    Ok(rows
        .into_iter()
        .map(|(domain, count, last_scan)| DomainStats {
            domain,
            scan_count: count as u64,
            last_scan,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{InMemoryJobQueue, ScanExecutor};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::state::{ApiStats, AppState};
    use crate::db::{DatabaseConfig, DatabasePool, run_migrations};
    use axum::extract::State;
    use chrono::Utc;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    use tokio::sync::RwLock;

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn create_unique_db_path() -> PathBuf {
        let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        let path = PathBuf::from(format!("/tmp/cipherrun-stats-test{}.db", counter));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-stats-test{}.db", counter));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn build_state() -> Arc<AppState> {
        let config = Arc::new(ApiConfig::default());
        let job_queue = Arc::new(InMemoryJobQueue::new(10));
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
        let progress_tx = executor.progress_broadcaster();

        Arc::new(AppState {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: None,
        })
    }

    async fn build_state_with_db() -> Arc<AppState> {
        let config = DatabaseConfig::sqlite(create_unique_db_path());
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");
        run_migrations(&pool)
            .await
            .expect("test assertion should succeed");

        let mut state = AppState::new(ApiConfig::default()).expect("test assertion should succeed");
        state.db_pool = Some(Arc::new(pool));
        Arc::new(state)
    }

    async fn insert_scan(pool: &DatabasePool, hostname: &str) {
        let now = Utc::now();
        if let DatabasePool::Sqlite(sqlite) = pool {
            sqlx::query(
                r#"
                INSERT INTO scans (target_hostname, target_port, scan_timestamp)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(hostname)
            .bind(443_i32)
            .bind(now)
            .execute(sqlite)
            .await
            .expect("test assertion should succeed");
        } else {
            panic!("expected sqlite pool");
        }
    }

    #[tokio::test]
    async fn test_get_stats_without_db() {
        let state = build_state();
        {
            let mut stats = state.stats.write().await;
            stats.increment_requests();
            stats.increment_scans();
            stats.record_completed_scan(1500);
        }

        let response = get_stats(State(state)).await.unwrap().0;
        assert_eq!(response.total_scans, 1);
        assert_eq!(response.completed_scans, 1);
        assert_eq!(response.failed_scans, 0);
        assert!(response.avg_scan_duration_seconds >= 1.0);
        assert!(response.top_domains.is_empty());
    }

    #[tokio::test]
    async fn test_get_stats_with_db_top_domains() {
        let state = build_state_with_db().await;
        let pool = state.db_pool.as_ref().unwrap().clone();

        insert_scan(&pool, "alpha.example").await;
        insert_scan(&pool, "alpha.example").await;
        insert_scan(&pool, "beta.example").await;

        let response = get_stats(State(state)).await.unwrap().0;
        assert!(response.top_domains.len() >= 2);
        assert_eq!(response.top_domains[0].domain, "alpha.example");
        assert_eq!(response.top_domains[0].scan_count, 2);
    }
}
