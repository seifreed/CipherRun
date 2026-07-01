// API State Management

use crate::Result;
use crate::api::{
    config::ApiConfig,
    jobs::{InMemoryJobQueue, JobQueue, ScanExecutor},
    middleware::rate_limit::PerKeyRateLimiter,
    models::response::ProgressMessage,
};
use crate::db::DatabasePool;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

/// Maximum number of timestamps to keep in memory
/// How often the per-key rate-limiter is swept to evict stale entries. Without
/// this the limiter's maps grow unbounded for the process lifetime.
const RATE_LIMITER_CLEANUP_INTERVAL_SECS: u64 = 300;

const MAX_TIMESTAMPS: usize = 100_000;

/// Maximum number of hourly stats entries
const MAX_HOURLY_ENTRIES: usize = 10_000;

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

    /// Requests in last hour (timestamp, count) - bounded collection
    pub requests_last_hour: VecDeque<(Instant, u64)>,

    /// Request timestamps for rolling-window stats - bounded collection
    pub request_timestamps: VecDeque<Instant>,

    /// Total response time for averaging
    pub total_response_time_ms: u64,

    /// Total responses counted for averaging
    pub total_responses: u64,

    /// Scan timestamps for rolling-window stats - bounded collection
    pub scan_timestamps: VecDeque<Instant>,
}

impl ApiStats {
    /// Increment request counter
    pub fn increment_requests(&mut self) {
        self.total_requests = self.total_requests.saturating_add(1);

        // Update hourly stats
        let now = Instant::now();
        self.requests_last_hour.push_back((now, 1));
        self.request_timestamps.push_back(now);

        // Clean up old entries (older than 1 hour). Guard against underflow on some platforms.
        if let Some(one_hour_ago) = now.checked_sub(crate::constants::STATS_HOURLY_WINDOW) {
            self.requests_last_hour.retain(|(t, _)| *t > one_hour_ago);
        }
        self.prune_request_timestamps(now);

        // Enforce memory bounds
        self.enforce_bounds();
    }

    /// Increment scan counter
    pub fn increment_scans(&mut self) {
        self.total_scans = self.total_scans.saturating_add(1);
        let now = Instant::now();
        self.scan_timestamps.push_back(now);
        self.prune_scan_timestamps(now);
        self.enforce_bounds();
    }

    /// Record completed scan
    pub fn record_completed_scan(&mut self, duration_ms: u64) {
        self.completed_scans = self.completed_scans.saturating_add(1);
        self.total_scan_duration_ms = self.total_scan_duration_ms.saturating_add(duration_ms);
    }

    /// Record failed scan
    pub fn record_failed_scan(&mut self) {
        self.failed_scans = self.failed_scans.saturating_add(1);
    }

    pub fn record_response(&mut self, response_time_ms: u64) {
        self.total_response_time_ms = self.total_response_time_ms.saturating_add(response_time_ms);
        self.total_responses = self.total_responses.saturating_add(1);
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
    ///
    /// Filters by time to avoid counting stale entries that haven't been pruned yet
    pub fn requests_in_last_hour(&self) -> u64 {
        let now = Instant::now();
        self.requests_last_hour
            .iter()
            .filter(|(t, _)| *t <= now && now.duration_since(*t).as_secs() <= 3600)
            .map(|(_, c)| c)
            .fold(0u64, |total, count| total.saturating_add(*count))
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

    /// Enforce memory bounds on timestamp collections
    fn enforce_bounds(&mut self) {
        // Prune by time first, then enforce size limits
        if self.requests_last_hour.len() > MAX_HOURLY_ENTRIES {
            let drain_count = self.requests_last_hour.len() - MAX_HOURLY_ENTRIES;
            self.requests_last_hour.drain(0..drain_count);
        }
        if self.request_timestamps.len() > MAX_TIMESTAMPS {
            let drain_count = self.request_timestamps.len() - MAX_TIMESTAMPS;
            self.request_timestamps.drain(0..drain_count);
        }
        if self.scan_timestamps.len() > MAX_TIMESTAMPS {
            let drain_count = self.scan_timestamps.len() - MAX_TIMESTAMPS;
            self.scan_timestamps.drain(0..drain_count);
        }
    }
}

impl AppState {
    /// Create new application state
    pub fn new(config: ApiConfig) -> Result<Self> {
        if config.port == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "port must be between 1 and 65535".to_string(),
            });
        }
        if config.rate_limit_per_minute == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "rate_limit_per_minute must be greater than 0".to_string(),
            });
        }
        if config.max_concurrent_scans == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "max_concurrent_scans must be greater than 0".to_string(),
            });
        }
        if config.job_queue_capacity == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "job_queue_capacity must be greater than 0".to_string(),
            });
        }
        if config.request_timeout_seconds == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "request_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if config.max_body_size == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "max_body_size must be greater than 0".to_string(),
            });
        }
        if config.ws_ping_interval_seconds == 0 {
            return Err(crate::error::TlsError::ConfigError {
                message: "ws_ping_interval_seconds must be greater than 0".to_string(),
            });
        }
        if config.api_keys.is_empty() {
            return Err(crate::error::TlsError::ConfigError {
                message: "api_keys must contain at least one key".to_string(),
            });
        }
        if config.api_keys.keys().any(|key| key.is_empty()) {
            return Err(crate::error::TlsError::ConfigError {
                message: "api_keys must not contain empty keys".to_string(),
            });
        }

        let config = Arc::new(config);
        let stats = Arc::new(tokio::sync::RwLock::new(ApiStats::default()));

        // Create job queue
        let job_queue: Arc<dyn JobQueue> =
            Arc::new(InMemoryJobQueue::new(config.job_queue_capacity));

        // Create executor
        let executor = Arc::new(
            ScanExecutor::new(job_queue.clone(), config.max_concurrent_scans)
                .with_stats(stats.clone()),
        );

        // Get progress broadcaster
        let progress_tx = executor.progress_broadcaster();

        // Create rate limiter
        let rate_limiter = Arc::new(PerKeyRateLimiter::new(config.rate_limit_per_minute));

        // Policy storage directory comes from the API config; when unset the
        // policy endpoints report 503 Service Unavailable.
        let policy_dir = config.policy_dir.clone();

        Ok(Self {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats,
            rate_limiter,
            db_pool: None,
            policy_dir,
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

        // Periodically evict stale rate-limiter entries. cleanup() is the only
        // mechanism that bounds the limiter's maps; without this sweeper they
        // grow for the lifetime of the process (one entry per distinct API key,
        // never freed) — a slow memory leak.
        let rate_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                RATE_LIMITER_CLEANUP_INTERVAL_SECS,
            ));
            ticker.tick().await; // first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                rate_limiter.cleanup();
            }
        });

        Ok(())
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get active scans count
    pub async fn active_scans(&self) -> Result<usize> {
        self.job_queue.active_jobs_count().await
    }

    /// Get queued scans count
    pub async fn queued_scans(&self) -> Result<usize> {
        self.job_queue.queue_length().await
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
    fn test_api_stats_requests_in_last_hour_saturates() {
        let now = Instant::now();
        let mut stats = ApiStats::default();
        stats.requests_last_hour.push_back((now, u64::MAX));
        stats.requests_last_hour.push_back((now, 1));

        assert_eq!(stats.requests_in_last_hour(), u64::MAX);
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
    fn test_api_stats_counters_saturate() {
        let mut stats = ApiStats {
            total_requests: u64::MAX,
            total_scans: u64::MAX,
            completed_scans: u64::MAX,
            failed_scans: u64::MAX,
            total_scan_duration_ms: u64::MAX - 5,
            total_response_time_ms: u64::MAX - 5,
            total_responses: u64::MAX,
            ..Default::default()
        };

        stats.increment_requests();
        stats.increment_scans();
        stats.record_completed_scan(10);
        stats.record_failed_scan();
        stats.record_response(10);

        assert_eq!(stats.total_requests, u64::MAX);
        assert_eq!(stats.total_scans, u64::MAX);
        assert_eq!(stats.completed_scans, u64::MAX);
        assert_eq!(stats.failed_scans, u64::MAX);
        assert_eq!(stats.total_scan_duration_ms, u64::MAX);
        assert_eq!(stats.total_response_time_ms, u64::MAX);
        assert_eq!(stats.total_responses, u64::MAX);
    }

    #[test]
    fn test_api_stats_defaults_and_scan_counts() {
        let stats = ApiStats::default();
        assert_eq!(stats.avg_scan_duration(), 0.0);
        assert_eq!(stats.scans_last_24h(), 0);
        assert_eq!(stats.scans_last_7d(), 0);
    }

    #[test]
    fn test_app_state_rejects_zero_rate_limit() {
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero rate limit should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("rate_limit_per_minute"));
    }

    #[test]
    fn test_app_state_rejects_zero_port() {
        let config = ApiConfig {
            port: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero API port should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("port"));
    }

    #[test]
    fn test_app_state_rejects_zero_max_concurrent_scans() {
        let config = ApiConfig {
            max_concurrent_scans: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero concurrency should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("max_concurrent_scans"));
    }

    #[test]
    fn test_app_state_rejects_zero_job_queue_capacity() {
        let config = ApiConfig {
            job_queue_capacity: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero queue capacity should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("job_queue_capacity"));
    }

    #[test]
    fn test_app_state_rejects_zero_ws_ping_interval() {
        let config = ApiConfig {
            ws_ping_interval_seconds: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero websocket ping interval should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("ws_ping_interval_seconds"));
    }

    #[test]
    fn test_app_state_rejects_zero_request_timeout() {
        let config = ApiConfig {
            request_timeout_seconds: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero request timeout should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("request_timeout_seconds"));
    }

    #[test]
    fn test_app_state_rejects_zero_max_body_size() {
        let config = ApiConfig {
            max_body_size: 0,
            ..Default::default()
        };

        let err = match AppState::new(config) {
            Ok(_) => panic!("zero max body size should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("max_body_size"));
    }

    #[test]
    fn test_app_state_rejects_empty_api_key_set() {
        let mut config = ApiConfig::default();
        config.api_keys.clear();

        let err = match AppState::new(config) {
            Ok(_) => panic!("empty api key set should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("api_keys"));
    }

    #[test]
    fn test_app_state_rejects_empty_api_key_entry() {
        let mut config = ApiConfig::default();
        config.api_keys.clear();
        config
            .api_keys
            .insert(String::new(), crate::api::config::Permission::Admin);

        let err = match AppState::new(config) {
            Ok(_) => panic!("empty api key should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("empty keys"));
    }
}
