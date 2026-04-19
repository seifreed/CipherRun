// Health Check Route

use crate::api::{
    models::response::HealthResponse, presenters::health::present_health_response, state::AppState,
};
use axum::{Json, extract::State};
use std::sync::Arc;

/// Health check endpoint
///
/// Returns the health status of the API service
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse)
    )
)]
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let active_scans = state.active_scans().await;
    let queued_scans = state.queued_scans().await;
    let (queue_healthy, active_scans, queued_scans, queue_status) =
        match (active_scans, queued_scans) {
            (Ok(active_scans), Ok(queued_scans)) => (
                true,
                Some(active_scans),
                Some(queued_scans),
                Some("connected".to_string()),
            ),
            (active_result, queued_result) => {
                let mut errors = Vec::new();
                if let Err(error) = active_result {
                    errors.push(format!("active_scans failed: {}", error));
                }
                if let Err(error) = queued_result {
                    errors.push(format!("queued_scans failed: {}", error));
                }

                (
                    false,
                    None,
                    None,
                    Some(format!("error: {}", errors.join("; "))),
                )
            }
        };

    // Check database health if configured
    let (database_healthy, database_status) = if let Some(db) = &state.db_pool {
        match check_database_health(db).await {
            Ok(_) => (true, Some("connected".to_string())),
            Err(e) => (false, Some(format!("error: {}", e))),
        }
    } else {
        (true, Some("not_configured".to_string()))
    };

    let status = if queue_healthy && database_healthy {
        "healthy".to_string()
    } else {
        "degraded".to_string()
    };

    Json(present_health_response(
        status,
        env!("CARGO_PKG_VERSION").to_string(),
        state.uptime_seconds(),
        active_scans,
        queued_scans,
        database_status,
        queue_status,
    ))
}

/// Check database health with a simple query
async fn check_database_health(db: &crate::db::connection::DatabasePool) -> crate::Result<()> {
    db.health_check().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{JobQueue, ScanExecutor, ScanJob};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::models::response::ProgressMessage;
    use crate::api::state::ApiStats;
    use crate::db::{DatabaseConfig, DatabasePool};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{RwLock, broadcast};

    struct FailingQueue;

    #[async_trait]
    impl JobQueue for FailingQueue {
        async fn enqueue(&self, _job: ScanJob) -> crate::Result<String> {
            Err(crate::TlsError::Other("enqueue unavailable".to_string()))
        }

        async fn dequeue(&self) -> crate::Result<Option<ScanJob>> {
            Err(crate::TlsError::Other("dequeue unavailable".to_string()))
        }

        async fn get_job(&self, _id: &str) -> crate::Result<Option<ScanJob>> {
            Err(crate::TlsError::Other("get unavailable".to_string()))
        }

        async fn update_job(&self, _job: &ScanJob) -> crate::Result<()> {
            Err(crate::TlsError::Other("update unavailable".to_string()))
        }

        async fn update_job_preserving_cancelled(&self, _job: &ScanJob) -> crate::Result<bool> {
            Err(crate::TlsError::Other("update unavailable".to_string()))
        }

        async fn cancel_job(&self, _id: &str) -> crate::Result<bool> {
            Err(crate::TlsError::Other("cancel unavailable".to_string()))
        }

        async fn queue_length(&self) -> crate::Result<usize> {
            Err(crate::TlsError::Other("queue backend failed".to_string()))
        }

        async fn list_jobs(&self) -> crate::Result<Vec<ScanJob>> {
            Err(crate::TlsError::Other("list unavailable".to_string()))
        }

        async fn active_jobs_count(&self) -> crate::Result<usize> {
            Err(crate::TlsError::Other("queue backend failed".to_string()))
        }
    }

    #[tokio::test]
    async fn test_health_check_without_db() {
        let state = AppState::new(ApiConfig::default()).expect("state should build");
        let Json(response) = health_check(State(Arc::new(state))).await;

        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.database.as_deref(), Some("not_configured"));
        assert_eq!(response.queue.as_deref(), Some("connected"));
        assert_eq!(response.active_scans, Some(0));
        assert_eq!(response.queued_scans, Some(0));
    }

    #[tokio::test]
    async fn test_health_check_with_sqlite_db() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config).await.expect("db should build");

        let mut state = AppState::new(ApiConfig::default()).expect("state should build");
        state.db_pool = Some(Arc::new(pool));

        let Json(response) = health_check(State(Arc::new(state))).await;
        assert_eq!(response.status, "healthy");
        assert_eq!(response.database.as_deref(), Some("connected"));
    }

    #[tokio::test]
    async fn test_health_check_degrades_when_database_health_check_fails() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config).await.expect("db should build");
        pool.close().await;

        let mut state = AppState::new(ApiConfig::default()).expect("state should build");
        state.db_pool = Some(Arc::new(pool));

        let Json(response) = health_check(State(Arc::new(state))).await;

        assert_eq!(response.status, "degraded");
        assert_eq!(response.queue.as_deref(), Some("connected"));
        assert!(
            response
                .database
                .as_deref()
                .unwrap_or_default()
                .contains("Database health check failed")
        );
    }

    #[tokio::test]
    async fn test_health_check_degrades_when_queue_backend_fails() {
        let config = Arc::new(ApiConfig::default());
        let job_queue = Arc::new(FailingQueue);
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
        let progress_tx: broadcast::Sender<ProgressMessage> = executor.progress_broadcaster();

        let state = Arc::new(AppState {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: None,
        });

        let Json(response) = health_check(State(state)).await;

        assert_eq!(response.status, "degraded");
        assert_eq!(response.database.as_deref(), Some("not_configured"));
        assert_eq!(response.active_scans, None);
        assert_eq!(response.queued_scans, None);
        assert!(
            response
                .queue
                .as_deref()
                .unwrap_or_default()
                .contains("queue backend failed")
        );
    }
}
