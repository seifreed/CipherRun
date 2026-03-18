// API State Management

use crate::api::{
    config::ApiConfig,
    jobs::{InMemoryJobQueue, JobQueue, ScanExecutor},
    middleware::rate_limit::PerKeyRateLimiter,
    models::response::ProgressMessage,
};
use crate::db::DatabasePool;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

/// Shared application state
pub struct AppState {
    /// API configuration
    pub config: Arc<ApiConfig>,

    /// Job queue
    pub job_queue: Arc<dyn JobQueue>,

    /// Scan executor
    pub executor: Arc<ScanExecutor>,

    /// Progress broadcaster
    pub progress_tx: broadcast::Sender<ProgressMessage>,

    /// Server start time
    pub start_time: Instant,

    /// Statistics
    pub stats: Arc<tokio::sync::RwLock<ApiStats>>,

    /// Rate limiter for per-key rate limiting
    pub rate_limiter: Arc<PerKeyRateLimiter>,

    /// Database pool (optional)
    pub db_pool: Option<Arc<DatabasePool>>,

    /// Policy directory (optional)
    pub policy_dir: Option<PathBuf>,
}

/// API statistics
#[derive(Debug, Clone, Default)]
pub struct ApiStats {
    /// Total requests received
    pub total_requests: u64,

    /// Total scans created
    pub total_scans: u64,

    /// Completed scans
    pub completed_scans: u64,

    /// Failed scans
    pub failed_scans: u64,

    /// Total scan duration (for averaging)
    pub total_scan_duration_ms: u64,

    /// Requests in last hour (timestamp, count)
    pub requests_last_hour: Vec<(Instant, u64)>,

    /// Request timestamps for rolling-window stats
    pub request_timestamps: Vec<Instant>,

    /// Total response time for averaging
    pub total_response_time_ms: u64,

    /// Total responses counted for averaging
    pub total_responses: u64,

    /// Scan timestamps for rolling-window stats
    pub scan_timestamps: Vec<Instant>,
}

impl ApiStats {
    /// Increment request counter
    pub fn increment_requests(&mut self) {
        self.total_requests += 1;

        // Update hourly stats
        let now = Instant::now();
        self.requests_last_hour.push((now, 1));
        self.request_timestamps.push(now);

        // Clean up old entries (older than 1 hour). Guard against underflow on some platforms.
        if let Some(one_hour_ago) = now.checked_sub(std::time::Duration::from_secs(3600)) {
            self.requests_last_hour.retain(|(t, _)| *t > one_hour_ago);
        }
        self.prune_request_timestamps(now);
    }

    /// Increment scan counter
    pub fn increment_scans(&mut self) {
        self.total_scans += 1;
        let now = Instant::now();
        self.scan_timestamps.push(now);
        self.prune_scan_timestamps(now);
    }

    /// Record completed scan
    pub fn record_completed_scan(&mut self, duration_ms: u64) {
        self.completed_scans += 1;
        self.total_scan_duration_ms += duration_ms;
    }

    /// Record failed scan
    pub fn record_failed_scan(&mut self) {
        self.failed_scans += 1;
    }

    pub fn record_response(&mut self, response_time_ms: u64) {
        self.total_response_time_ms += response_time_ms;
        self.total_responses += 1;
    }

    /// Get average scan duration
    pub fn avg_scan_duration(&self) -> f64 {
        if self.completed_scans > 0 {
            self.total_scan_duration_ms as f64 / self.completed_scans as f64
        } else {
            0.0
        }
    }

    /// Get requests in last hour
    pub fn requests_in_last_hour(&self) -> u64 {
        self.requests_last_hour.iter().map(|(_, c)| c).sum()
    }

    /// Get average response time in milliseconds
    pub fn avg_response_time_ms(&self) -> f64 {
        if self.total_responses > 0 {
            self.total_response_time_ms as f64 / self.total_responses as f64
        } else {
            0.0
        }
    }

    pub fn requests_in_last_day(&self) -> u64 {
        let now = Instant::now();
        self.request_timestamps
            .iter()
            .filter(|ts| now.duration_since(**ts).as_secs() <= 24 * 60 * 60)
            .count() as u64
    }

    /// Get scans in last 24 hours
    pub fn scans_last_24h(&self) -> u64 {
        let now = Instant::now();
        self.scan_timestamps
            .iter()
            .filter(|ts| now.duration_since(**ts).as_secs() <= 24 * 60 * 60)
            .count() as u64
    }

    /// Get scans in last 7 days
    pub fn scans_last_7d(&self) -> u64 {
        let now = Instant::now();
        self.scan_timestamps
            .iter()
            .filter(|ts| now.duration_since(**ts).as_secs() <= 7 * 24 * 60 * 60)
            .count() as u64
    }

    fn prune_scan_timestamps(&mut self, now: Instant) {
        self.scan_timestamps
            .retain(|ts| now.duration_since(*ts).as_secs() <= 7 * 24 * 60 * 60);
    }

    fn prune_request_timestamps(&mut self, now: Instant) {
        self.request_timestamps
            .retain(|ts| now.duration_since(*ts).as_secs() <= 24 * 60 * 60);
    }
}

impl AppState {
    /// Create new application state
    pub fn new(config: ApiConfig) -> Result<Self> {
        let config = Arc::new(config);
        let stats = Arc::new(tokio::sync::RwLock::new(ApiStats::default()));

        // Create job queue
        let job_queue: Arc<dyn JobQueue> =
            Arc::new(InMemoryJobQueue::new(config.job_queue_capacity));

        // Create executor
        let executor = Arc::new(ScanExecutor::new(
            job_queue.clone(),
            config.max_concurrent_scans,
        )
        .with_stats(stats.clone()));

        // Get progress broadcaster
        let progress_tx = executor.progress_broadcaster();

        // Create rate limiter
        let rate_limiter = Arc::new(PerKeyRateLimiter::new(config.rate_limit_per_minute));

        Ok(Self {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats,
            rate_limiter,
            db_pool: None,
            policy_dir: None,
        })
    }

    /// Start the executor
    pub async fn start_executor(self: Arc<Self>) -> Result<()> {
        let executor = self.executor.clone();
        tokio::spawn(async move {
            if let Err(e) = executor.start().await {
                tracing::error!("Executor error: {}", e);
            }
        });

        Ok(())
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get active scans count
    pub async fn active_scans(&self) -> usize {
        self.job_queue.active_jobs_count().await.unwrap_or(0)
    }

    /// Get queued scans count
    pub async fn queued_scans(&self) -> usize {
        self.job_queue.queue_length().await.unwrap_or(0)
    }

    /// Subscribe to scan progress
    pub fn subscribe_progress(&self) -> broadcast::Receiver<ProgressMessage> {
        self.progress_tx.subscribe()
    }

    /// Increment request counter
    pub async fn record_request(&self) {
        let mut stats = self.stats.write().await;
        stats.increment_requests();
    }

    pub async fn record_response(&self, response_time_ms: u64) {
        let mut stats = self.stats.write().await;
        stats.record_response(response_time_ms);
    }

    /// Record new scan
    pub async fn record_scan(&self) {
        let mut stats = self.stats.write().await;
        stats.increment_scans();
    }

    /// Record completed scan
    pub async fn record_completed(&self, duration_ms: u64) {
        let mut stats = self.stats.write().await;
        stats.record_completed_scan(duration_ms);
    }

    /// Record failed scan
    pub async fn record_failed(&self) {
        let mut stats = self.stats.write().await;
        stats.record_failed_scan();
    }

    /// Get statistics snapshot
    pub async fn get_stats(&self) -> ApiStats {
        self.stats.read().await.clone()
    }

    /// Set database pool
    pub fn with_db_pool(mut self, pool: Arc<DatabasePool>) -> Self {
        self.db_pool = Some(pool);
        self
    }

    /// Set policy directory
    pub fn with_policy_dir(mut self, dir: PathBuf) -> Self {
        self.policy_dir = Some(dir);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_stats_request_tracking() {
        let mut stats = ApiStats::default();
        stats.increment_requests();

        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.requests_last_hour.len(), 1);
        assert_eq!(stats.requests_in_last_hour(), 1);
    }

    #[test]
    fn test_api_stats_scan_and_response_metrics() {
        let mut stats = ApiStats::default();
        stats.record_completed_scan(100);
        stats.record_completed_scan(200);
        stats.record_failed_scan();

        assert_eq!(stats.completed_scans, 2);
        assert_eq!(stats.failed_scans, 1);
        assert!((stats.avg_scan_duration() - 150.0).abs() < f64::EPSILON);

        assert_eq!(stats.avg_response_time_ms(), 0.0);
        stats.total_response_time_ms = 250;
        stats.total_responses = 10;
        assert!((stats.avg_response_time_ms() - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_api_stats_defaults_and_scan_counts() {
        let stats = ApiStats::default();
        assert_eq!(stats.avg_scan_duration(), 0.0);
        assert_eq!(stats.scans_last_24h(), 0);
        assert_eq!(stats.scans_last_7d(), 0);
    }
}
