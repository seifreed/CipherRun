// Scan Executor - Background job processor

use crate::api::jobs::{JobQueue, ScanJob};
use crate::api::models::request::ScanOptions;
use crate::api::models::response::ProgressMessage;
use crate::cli::Args;
use crate::scanner::{ScanResults, Scanner};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, broadcast};
use tracing::{error, info, warn};

/// Scan executor for processing background jobs
pub struct ScanExecutor {
    job_queue: Arc<dyn JobQueue>,
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    progress_tx: broadcast::Sender<ProgressMessage>,
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
            shutdown_tx,
            shutdown_rx,
        }
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
        info!("Starting scan job {} for target {}", job.id, job.target);

        // Mark job as started
        job.mark_started();
        if let Err(e) = queue.update_job(&job).await {
            error!("Failed to update job status: {}", e);
        }

        // Send progress update
        self.send_progress(&job, 0, "Starting scan");

        // Execute the scan
        match Self::run_scan(&job, &self.progress_tx).await {
            Ok(results) => {
                info!("Scan job {} completed successfully", job.id);
                job.mark_completed(results);

                let msg = ProgressMessage::completed(&job.id);
                let _ = self.progress_tx.send(msg);
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!("Scan job {} failed: {}", job.id, error_msg);
                let msg = ProgressMessage::failed(&job.id, &error_msg);
                let _ = self.progress_tx.send(msg);
                job.mark_failed(error_msg);
            }
        }

        // Update job in queue
        if let Err(e) = queue.update_job(&job).await {
            error!("Failed to update job status: {}", e);
        }

        // Call webhook if configured
        if let Some(webhook_url) = &job.webhook_url
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
        // Convert ScanOptions to Args
        let args = Self::options_to_args(&job.target, &job.options)?;

        let _ = progress_tx.send(ProgressMessage::new(&job.id, 5, "Initializing scanner"));

        // Create scanner
        let scanner = Scanner::new(args)?;

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

    /// Convert ScanOptions to Args
    #[allow(clippy::field_reassign_with_default)]
    fn options_to_args(target: &str, options: &ScanOptions) -> Result<Args> {
        let mut args = Args::default();

        args.target = Some(target.to_string());
        args.output.quiet = true; // Suppress output

        // Set timeout
        args.connection.socket_timeout = Some(options.timeout_seconds);

        // Protocol testing
        if options.test_protocols || options.full_scan {
            args.scan.protocols = true;
        }

        // Cipher testing
        if options.test_ciphers || options.full_scan {
            args.scan.each_cipher = true;
        }

        // Vulnerability testing
        if options.test_vulnerabilities || options.full_scan {
            args.scan.vulnerabilities = true;
        }

        // HTTP headers
        if options.test_http_headers || options.full_scan {
            args.scan.headers = true;
        }

        // Client simulation
        if options.client_simulation || options.full_scan {
            args.fingerprint.client_simulation = true;
        }

        args.starttls.protocol = options.starttls_protocol.clone();

        args.network.ipv4_only = options.ipv4_only;
        args.network.ipv6_only = options.ipv6_only;

        args.ip = options.ip.clone();

        // Full scan flag
        if options.full_scan {
            args.scan.all = true;
        }

        Ok(args)
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
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}
