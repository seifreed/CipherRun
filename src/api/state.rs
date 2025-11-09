// API State Management

use crate::api::{
    config::ApiConfig,
    jobs::{InMemoryJobQueue, JobQueue, ScanExecutor},
    models::response::ProgressMessage,
};
use anyhow::Result;
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
}

impl ApiStats {
    /// Increment request counter
    pub fn increment_requests(&mut self) {
        self.total_requests += 1;

        // Update hourly stats
        let now = Instant::now();
        self.requests_last_hour.push((now, 1));

        // Clean up old entries (older than 1 hour)
        let one_hour_ago = now - std::time::Duration::from_secs(3600);
        self.requests_last_hour.retain(|(t, _)| *t > one_hour_ago);
    }

    /// Increment scan counter
    pub fn increment_scans(&mut self) {
        self.total_scans += 1;
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
}

impl AppState {
    /// Create new application state
    pub fn new(config: ApiConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Create job queue
        let job_queue: Arc<dyn JobQueue> =
            Arc::new(InMemoryJobQueue::new(config.job_queue_capacity));

        // Create executor
        let executor = Arc::new(ScanExecutor::new(
            job_queue.clone(),
            config.max_concurrent_scans,
        ));

        // Get progress broadcaster
        let progress_tx = executor.progress_broadcaster();

        Ok(Self {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(tokio::sync::RwLock::new(ApiStats::default())),
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
}
