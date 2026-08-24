use crate::api::config::ApiConfig;
use crate::api::jobs::{InMemoryJobQueue, ScanExecutor};
use crate::api::middleware::rate_limit::PerKeyRateLimiter;
use crate::api::state::{ApiStats, AppState};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

pub(crate) fn build_test_state() -> Arc<AppState> {
    let config = Arc::new(ApiConfig::default());
    let job_queue = Arc::new(InMemoryJobQueue::new(10));
    let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
    let progress_tx = executor.progress_broadcaster();

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
