// Scan Executor - Background job processor

use crate::api::jobs::{JobQueue, ScanJob};
use crate::api::models::request::ScanOptions;
use crate::api::models::response::{ProgressMessage, ScanStatus};
use crate::api::state::ApiStats;
use crate::application::ScanRequest;
use crate::scanner::{ScanResults, Scanner};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{error, info, warn};

/// Scan executor for processing background jobs
pub struct ScanExecutor {
    job_queue: Arc<dyn JobQueue>,
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    progress_tx: broadcast::Sender<ProgressMessage>,
    stats: Option<Arc<RwLock<ApiStats>>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl ScanExecutor {
    /// Create new scan executor
    pub fn new(job_queue: Arc<dyn JobQueue>, max_concurrent: usize) -> Self {
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let (progress_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        Self {
            job_queue,
            max_concurrent,
            semaphore,
            progress_tx,
            stats: None,
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn with_stats(mut self, stats: Arc<RwLock<ApiStats>>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Get progress broadcaster
    pub fn progress_broadcaster(&self) -> broadcast::Sender<ProgressMessage> {
        self.progress_tx.clone()
    }

    /// Subscribe to progress updates
    pub fn subscribe_progress(&self) -> broadcast::Receiver<ProgressMessage> {
        self.progress_tx.subscribe()
    }

    /// Start the executor
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!(
            "Starting scan executor with {} concurrent slots",
            self.max_concurrent
        );

        let shutdown_rx = self.shutdown_rx.clone();

        loop {
            // Check for shutdown signal
            if *shutdown_rx.borrow() {
                info!("Scan executor shutting down");
                break;
            }

            // Wait for available slot
            let permit = match Arc::clone(&self.semaphore).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    // No slots available, wait a bit
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            // Try to dequeue a job
            match self.job_queue.dequeue().await {
                Ok(Some(job)) => {
                    let executor = Arc::clone(&self);
                    let queue = Arc::clone(&self.job_queue);

                    // Spawn task to process job
                    tokio::spawn(async move {
                        executor.execute_scan(queue, job).await;
                        drop(permit);
                    });
                }
                Ok(None) => {
                    // No jobs in queue
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    error!("Error dequeuing job: {}", e);
                    drop(permit);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        Ok(())
    }

    /// Execute a scan job
    async fn execute_scan(&self, queue: Arc<dyn JobQueue>, mut job: ScanJob) {
        if let Ok(Some(current)) = queue.get_job(&job.id).await
            && matches!(current.status, ScanStatus::Cancelled)
        {
            info!("Skipping cancelled scan job {} before start", job.id);
            return;
        }

        info!("Starting scan job {} for target {}", job.id, job.target);

        // Mark job as started
        job.mark_started();
        if let Err(e) = queue.update_job(&job).await {
            error!("Failed to update job status: {}", e);
        }

        // Send progress update
        self.send_progress(&job, 0, "Starting scan");

        let progress_tx = self.progress_tx.clone();
        let job_for_scan = job.clone();
        let mut scan_task =
            tokio::spawn(async move { Self::run_scan(&job_for_scan, &progress_tx).await });

        let scan_result = loop {
            tokio::select! {
                joined = &mut scan_task => {
                    break match joined {
                        Ok(result) => result,
                        Err(err) if err.is_cancelled() => {
                            info!("Scan job {} task aborted after cancellation", job.id);
                            return;
                        }
                        Err(err) => Err(anyhow::anyhow!("Scan task join error: {}", err)),
                    };
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    if let Ok(Some(current)) = queue.get_job(&job.id).await
                        && matches!(current.status, ScanStatus::Cancelled)
                    {
                        info!("Aborting running scan job {} after cancellation request", job.id);
                        scan_task.abort();
                        let _ = (&mut scan_task).await;
                        let _ = self.progress_tx.send(ProgressMessage::new(&job.id, job.progress, "cancelled"));
                        return;
                    }
                }
            }
        };

        // Execute the scan
        match scan_result {
            Ok(results) => {
                info!("Scan job {} completed successfully", job.id);
                let duration_ms = job
                    .started_at
                    .map(|started| (chrono::Utc::now() - started).num_milliseconds().max(0) as u64)
                    .unwrap_or_default();
                let mut cancelled = false;

                if let Ok(Some(current)) = queue.get_job(&job.id).await {
                    if matches!(current.status, ScanStatus::Cancelled) {
                        cancelled = true;
                        job = current;
                        info!(
                            "Scan job {} finished after cancellation request; preserving cancelled state",
                            job.id
                        );
                    } else {
                        job.mark_completed(results);
                    }
                } else {
                    job.mark_completed(results);
                }

                let msg = if cancelled {
                    ProgressMessage::new(&job.id, job.progress, "cancelled")
                } else {
                    ProgressMessage::completed(&job.id)
                };
                let _ = self.progress_tx.send(msg);
                if !cancelled && let Some(stats) = &self.stats {
                    stats.write().await.record_completed_scan(duration_ms);
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!("Scan job {} failed: {}", job.id, error_msg);
                let mut cancelled = false;
                if let Ok(Some(current)) = queue.get_job(&job.id).await {
                    if matches!(current.status, ScanStatus::Cancelled) {
                        cancelled = true;
                        job = current;
                        info!(
                            "Scan job {} failed after cancellation request; preserving cancelled state",
                            job.id
                        );
                    } else {
                        job.mark_failed(error_msg);
                        if let Some(stats) = &self.stats {
                            stats.write().await.record_failed_scan();
                        }
                    }
                } else {
                    job.mark_failed(error_msg);
                    if let Some(stats) = &self.stats {
                        stats.write().await.record_failed_scan();
                    }
                }
                let msg = if cancelled {
                    ProgressMessage::new(&job.id, job.progress, "cancelled")
                } else {
                    ProgressMessage::failed(&job.id, &job.error.clone().unwrap_or_default())
                };
                let _ = self.progress_tx.send(msg);
            }
        }

        // Update job in queue
        if let Err(e) = queue.update_job(&job).await {
            error!("Failed to update job status: {}", e);
        }

        // Call webhook if configured
        if let Some(webhook_url) = &job.webhook_url
            && !matches!(job.status, ScanStatus::Cancelled)
            && let Err(e) = Self::send_webhook(webhook_url, &job).await
        {
            warn!("Failed to send webhook for job {}: {}", job.id, e);
        }
    }

    /// Run the actual scan
    async fn run_scan(
        job: &ScanJob,
        progress_tx: &broadcast::Sender<ProgressMessage>,
    ) -> Result<ScanResults> {
        let request = Self::options_to_request(&job.target, &job.options);

        let _ = progress_tx.send(ProgressMessage::new(&job.id, 5, "Initializing scanner"));

        // Create scanner
        let scanner = Scanner::new(request)?;

        let _ = progress_tx.send(ProgressMessage::new(&job.id, 10, "Resolving target"));

        // Initialize scanner (DNS resolution)
        scanner.initialize().await?;

        let _ = progress_tx.send(ProgressMessage::new(&job.id, 15, "Starting TLS scan"));

        // Run the scan
        // Note: We'll send progress updates during the scan
        // This is a simplified version - in production you'd want more granular progress
        let results = scanner.run().await?;

        let _ = progress_tx.send(ProgressMessage::new(&job.id, 95, "Finalizing results"));

        Ok(results)
    }

    fn options_to_request(target: &str, options: &ScanOptions) -> ScanRequest {
        ScanRequest {
            target: Some(target.to_string()),
            scan: crate::application::scan_request::ScanRequestScan {
                protocols: options.test_protocols || options.full_scan,
                each_cipher: options.test_ciphers || options.full_scan,
                vulnerabilities: options.test_vulnerabilities || options.full_scan,
                headers: options.test_http_headers || options.full_scan,
                all: options.full_scan,
                full: options.full_scan,
                ..Default::default()
            },
            network: crate::application::scan_request::ScanRequestNetwork {
                ipv4_only: options.ipv4_only,
                ipv6_only: options.ipv6_only,
                ..Default::default()
            },
            connection: crate::application::scan_request::ScanRequestConnection {
                socket_timeout: Some(options.timeout_seconds),
                ..Default::default()
            },
            fingerprint: crate::application::scan_request::ScanRequestFingerprint {
                client_simulation: options.client_simulation || options.full_scan,
                ..Default::default()
            },
            starttls: crate::application::scan_request::ScanRequestStarttls {
                protocol: options.starttls_protocol.clone(),
                ..Default::default()
            },
            ip: options.ip.clone(),
            ..Default::default()
        }
    }

    fn send_progress(&self, job: &ScanJob, progress: u8, stage: &str) {
        let msg = ProgressMessage::new(&job.id, progress, stage);
        let _ = self.progress_tx.send(msg);
    }

    /// Send webhook notification
    async fn send_webhook(webhook_url: &str, job: &ScanJob) -> Result<()> {
        let client = reqwest::Client::new();

        let payload = serde_json::json!({
            "job_id": job.id,
            "target": job.target,
            "status": job.status,
            "completed_at": job.completed_at,
            "error": job.error,
        });

        let response = client
            .post(webhook_url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Webhook returned status: {}", response.status());
        }

        Ok(())
    }

    /// Shutdown the executor gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating executor shutdown");
        self.shutdown_tx.send(true)?;
        Ok(())
    }
}

impl Clone for ScanExecutor {
    fn clone(&self) -> Self {
        Self {
            job_queue: self.job_queue.clone(),
            max_concurrent: self.max_concurrent,
            semaphore: self.semaphore.clone(),
            progress_tx: self.progress_tx.clone(),
            stats: self.stats.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_to_request_basic_flags() {
        let options = ScanOptions {
            test_protocols: true,
            test_ciphers: true,
            test_vulnerabilities: true,
            test_http_headers: true,
            client_simulation: true,
            timeout_seconds: 12,
            starttls_protocol: Some("smtp".to_string()),
            ipv4_only: true,
            ipv6_only: false,
            ip: Some("192.0.2.1".to_string()),
            full_scan: false,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com:443", &options);

        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert_eq!(request.connection.socket_timeout, Some(12));
        assert!(request.scan.protocols);
        assert!(request.scan.each_cipher);
        assert!(request.scan.vulnerabilities);
        assert!(request.scan.headers);
        assert!(request.fingerprint.client_simulation);
        assert_eq!(request.starttls.protocol.as_deref(), Some("smtp"));
        assert!(request.network.ipv4_only);
        assert!(!request.network.ipv6_only);
        assert_eq!(request.ip.as_deref(), Some("192.0.2.1"));
        assert!(!request.scan.all);
    }

    #[test]
    fn test_options_to_request_full_scan() {
        let options = ScanOptions {
            full_scan: true,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com", &options);

        assert!(request.scan.protocols);
        assert!(request.scan.each_cipher);
        assert!(request.scan.vulnerabilities);
        assert!(request.scan.headers);
        assert!(request.fingerprint.client_simulation);
        assert!(request.scan.all);
    }

    #[test]
    fn test_options_to_request_minimal() {
        let options = ScanOptions::default();
        let request = ScanExecutor::options_to_request("example.com:443", &options);

        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert!(!request.scan.protocols);
        assert!(!request.scan.each_cipher);
        assert!(!request.scan.vulnerabilities);
        assert!(!request.scan.headers);
        assert!(!request.scan.all);
    }

    #[test]
    fn test_options_to_request_ipv6_only() {
        let options = ScanOptions {
            ipv6_only: true,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com", &options);

        assert!(request.network.ipv6_only);
        assert!(!request.network.ipv4_only);
        assert!(request.starttls.protocol.is_none());
    }
}
