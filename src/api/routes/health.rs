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
                tracing::warn!(
                    event_name = "health.queue.unavailable",
                    active_scans_failed = active_result.is_err(),
                    queued_scans_failed = queued_result.is_err(),
                    error_type = "queue_backend",
                    active_error_code = active_result
                        .as_ref()
                        .err()
                        .map(|error| error.observability_code())
                        .unwrap_or("none"),
                    queued_error_code = queued_result
                        .as_ref()
                        .err()
                        .map(|error| error.observability_code())
                        .unwrap_or("none"),
                    "Queue health check failed"
                );
                (false, None, None, Some("unavailable".to_string()))
            }
        };

    // Check database health if configured
    let (database_healthy, database_status) = if let Some(db) = &state.db_pool {
        match check_database_health(db).await {
            Ok(_) => (true, Some("connected".to_string())),
            Err(error) => {
                tracing::warn!(
                    event_name = "health.database.unavailable",
                    error_type = "database",
                    error_code = error.observability_code(),
                    "Database health check failed"
                );
                (false, Some("unavailable".to_string()))
            }
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
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::sync::{RwLock, broadcast};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailingQueue {
        fail_active_count: bool,
        fail_queued_count: bool,
    }

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
            if self.fail_queued_count {
                Err(crate::TlsError::Other(
                    "queue backend failed password=must-not-leak".to_string(),
                ))
            } else {
                Ok(0)
            }
        }

        async fn list_jobs(&self) -> crate::Result<Vec<ScanJob>> {
            Err(crate::TlsError::Other("list unavailable".to_string()))
        }

        async fn active_jobs_count(&self) -> crate::Result<usize> {
            if self.fail_active_count {
                Err(crate::TlsError::Other(
                    "queue backend failed password=must-not-leak".to_string(),
                ))
            } else {
                Ok(0)
            }
        }
    }

    fn state_with_queue(job_queue: Arc<dyn JobQueue>) -> Arc<AppState> {
        let config = Arc::new(ApiConfig::default());
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
        let progress_tx: broadcast::Sender<ProgressMessage> = executor.progress_broadcaster();

        Arc::new(AppState {
            credential_store: crate::api::config::ApiCredentialStore::new(&config),
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: None,
            stream_tickets: Arc::new(crate::api::ws::tickets::StreamTicketManager::new().unwrap()),
            results_store: None,
        })
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
        assert_eq!(response.database.as_deref(), Some("unavailable"));
    }

    #[tokio::test]
    async fn test_health_check_degrades_when_queue_backend_fails() {
        use tracing::instrument::WithSubscriber;

        let state = state_with_queue(Arc::new(FailingQueue {
            fail_active_count: true,
            fail_queued_count: true,
        }));

        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(output.clone())
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let Json(response) = async { health_check(State(state)).await }
            .with_subscriber(dispatch)
            .await;

        assert_eq!(response.status, "degraded");
        assert_eq!(response.database.as_deref(), Some("not_configured"));
        assert_eq!(response.active_scans, None);
        assert_eq!(response.queued_scans, None);
        assert_eq!(response.queue.as_deref(), Some("unavailable"));
        assert!(
            !response
                .queue
                .as_deref()
                .unwrap_or_default()
                .contains("must-not-leak")
        );
        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("health.queue.unavailable"), "{logs}");
        assert!(logs.contains("active_error_code=\"other\""), "{logs}");
        assert!(logs.contains("queued_error_code=\"other\""), "{logs}");
        assert!(!logs.contains("must-not-leak"), "{logs}");
    }

    #[tokio::test]
    async fn test_health_check_reports_only_the_queue_counter_that_failed() {
        use tracing::instrument::WithSubscriber;

        for (fail_active_count, fail_queued_count, active_failed, queued_failed) in
            [(false, true, false, true), (true, false, true, false)]
        {
            let state = state_with_queue(Arc::new(FailingQueue {
                fail_active_count,
                fail_queued_count,
            }));
            let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(output.clone())
                .finish();
            let Json(response) = async { health_check(State(state)).await }
                .with_subscriber(tracing::Dispatch::new(subscriber))
                .await;

            assert_eq!(response.status, "degraded");
            assert_eq!(response.active_scans, None);
            assert_eq!(response.queued_scans, None);
            let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            assert!(
                logs.contains(&format!("active_scans_failed={active_failed}")),
                "{logs}"
            );
            assert!(
                logs.contains(&format!("queued_scans_failed={queued_failed}")),
                "{logs}"
            );
            let active_code = if active_failed { "other" } else { "none" };
            let queued_code = if queued_failed { "other" } else { "none" };
            assert!(
                logs.contains(&format!("active_error_code=\"{active_code}\"")),
                "{logs}"
            );
            assert!(
                logs.contains(&format!("queued_error_code=\"{queued_code}\"")),
                "{logs}"
            );
            assert!(!logs.contains("must-not-leak"), "{logs}");
        }
    }
}
