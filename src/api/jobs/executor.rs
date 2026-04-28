// Scan Executor - Background job processor

use crate::api::jobs::{JobQueue, ScanJob};
use crate::api::models::request::ScanOptions;
use crate::api::models::response::{ProgressMessage, ScanStatus};
use crate::api::presenters::target_input::scan_request_from_target_and_options;
use crate::api::state::ApiStats;
use crate::application::ScanRequest;
use crate::scanner::{ScanResults, Scanner};
use crate::utils::network::canonical_target;
use anyhow::Result;
use std::net::SocketAddr;
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

#[derive(Debug)]
pub(crate) struct ValidatedWebhook {
    host: String,
    resolved_addrs: Vec<SocketAddr>,
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

            // Try to dequeue a job FIRST, before acquiring a permit.
            // This avoids holding a permit while no work is available,
            // which would starve real jobs under high load.
            let job = match self.job_queue.dequeue().await {
                Ok(Some(job)) => job,
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Err(e) => {
                    error!("Error dequeuing job: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Now acquire a permit to limit concurrency
            let permit = match Arc::clone(&self.semaphore).acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    // Semaphore closed — re-enqueue the job so it's not lost
                    error!("Semaphore closed, cannot execute job {}", job.id);
                    if let Err(e) = self.job_queue.enqueue(job).await {
                        error!("Failed to re-enqueue job: {}", e);
                    }
                    break;
                }
            };

            let executor = Arc::clone(&self);
            let queue = Arc::clone(&self.job_queue);

            tokio::spawn(async move {
                executor.execute_scan(queue, job).await;
                drop(permit);
            });
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

        // Mark job as started. Use update_job_preserving_cancelled so that a
        // cancellation arriving between the check above and this write is not
        // silently overwritten by the Started status.
        job.mark_started();
        match queue.update_job_preserving_cancelled(&job).await {
            Ok(true) => {}
            Ok(false) => {
                info!(
                    "Job {} was cancelled before it could start, aborting",
                    job.id
                );
                return;
            }
            Err(e) => {
                error!("Failed to update job status: {}", e);
                return;
            }
        }

        // Send progress update
        self.send_progress(queue.clone(), &mut job, 0, "Starting scan")
            .await;

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
                        match (&mut scan_task).await {
                            Ok(Ok(results)) => {
                                // Scan finished successfully right before/after abort
                                job = current;
                                job.mark_completed(results);
                                let _ = self.progress_tx.send(ProgressMessage::completed(&job.id));
                            }
                            Ok(Err(e)) => {
                                job = current;
                                job.mark_failed(e.to_string());
                                let _ = self.progress_tx.send(ProgressMessage::failed(&job.id, job.error.clone().unwrap_or_default()));
                            }
                            _ => {
                                let _ = self.progress_tx.send(ProgressMessage::new(&job.id, job.progress, "cancelled"));
                            }
                        }
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
                    ProgressMessage::failed(&job.id, job.error.clone().unwrap_or_default())
                };
                let _ = self.progress_tx.send(msg);
            }
        }

        // Update job in queue
        // Use update_job_preserving_cancelled to prevent race condition where
        // a cancellation request arrives between scan completion and this update.
        // This ensures we don't overwrite a cancelled status with completed/failed.
        match queue.update_job_preserving_cancelled(&job).await {
            Ok(true) => {
                // Job was successfully updated
            }
            Ok(false) => {
                // Job was cancelled while we were processing - this is expected
                tracing::info!("Job {} was cancelled, preserving cancelled status", job.id);
            }
            Err(e) => {
                error!("Failed to update job status: {}", e);
            }
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
        let request = Self::options_to_request(&job.target, &job.options)?;

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

    fn options_to_request(target: &str, options: &ScanOptions) -> Result<ScanRequest> {
        scan_request_from_target_and_options(target, options)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn send_progress(
        &self,
        queue: Arc<dyn JobQueue>,
        job: &mut ScanJob,
        progress: u8,
        stage: &str,
    ) {
        job.update_progress(progress, stage.to_string());
        let msg = ProgressMessage::new(&job.id, progress, stage);
        let _ = self.progress_tx.send(msg);
        let _ = queue.update_job(job).await;
    }

    /// Send webhook notification.
    /// Validates the URL against SSRF before making the request.
    async fn send_webhook(webhook_url: &str, job: &ScanJob) -> Result<()> {
        let validated = validate_webhook_url(webhook_url).await?;

        // Pin resolved IPs to prevent DNS rebinding TOCTOU attacks
        let mut client_builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        for addr in &validated.resolved_addrs {
            client_builder = client_builder.resolve(&validated.host, *addr);
        }
        let client = client_builder.build()?;

        let payload = serde_json::json!({
            "job_id": job.id,
            "target": job.target,
            "status": job.status,
            "completed_at": job.completed_at,
            "error": job.error,
        });

        let response = client.post(webhook_url).json(&payload).send().await?;

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

pub(crate) async fn validate_webhook_url(webhook_url: &str) -> Result<ValidatedWebhook> {
    // Parse and validate webhook URL to prevent SSRF
    let url: url::Url = webhook_url
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid webhook URL: {}", e))?;

    // Only allow http/https schemes
    match url.scheme() {
        "http" | "https" => {}
        scheme => anyhow::bail!(
            "Webhook URL scheme '{}' not allowed (only http/https)",
            scheme
        ),
    }

    // Resolve hostname and check all IPs against SSRF blocklist
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Webhook URL has no host"))?
        .to_string();

    // Block obvious private hostnames and IP literals
    if host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host == "127.0.0.1"
        || host == "::1"
    {
        anyhow::bail!("Webhook URL points to private/local host: {}", host);
    }

    // Also check if host is an IP literal pointing to a private address
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && crate::security::input_validation::is_private_ip(&ip)
    {
        anyhow::bail!(
            "Webhook URL uses private/internal IP literal {} (SSRF blocked)",
            ip
        );
    }

    // Resolve DNS and check all resulting IPs
    // IMPORTANT: If DNS resolution fails, reject the request to prevent SSRF bypass
    // via DNS rebinding or resolver misconfiguration
    let lookup_target = webhook_lookup_target(&host, url.port_or_known_default().unwrap_or(80));
    let resolved_addrs: Vec<_> = tokio::net::lookup_host(lookup_target)
        .await
        .map_err(|e| anyhow::anyhow!("Webhook DNS resolution failed for {}: {} (SSRF protection requires successful DNS resolution)", host, e))?
        .collect();

    if resolved_addrs.is_empty() {
        anyhow::bail!(
            "Webhook DNS resolution returned no addresses for {} (SSRF blocked)",
            host
        );
    }

    for addr in &resolved_addrs {
        if crate::security::input_validation::is_private_ip(&addr.ip()) {
            anyhow::bail!(
                "Webhook URL resolves to private/internal IP {} (SSRF blocked)",
                addr.ip()
            );
        }
    }

    Ok(ValidatedWebhook {
        host,
        resolved_addrs,
    })
}

fn webhook_lookup_target(host: &str, port: u16) -> String {
    canonical_target(host, port)
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
            ip: Some("8.8.8.8".to_string()),
            full_scan: false,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com:443", &options)
            .expect("request should build");

        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert_eq!(request.connection.connect_timeout, Some(12));
        assert_eq!(request.connection.socket_timeout, Some(12));
        assert!(request.scan.proto.enabled);
        assert!(request.scan.ciphers.each_cipher);
        assert!(request.scan.vulns.vulnerabilities);
        assert!(!request.scan.certs.analyze_certificates);
        assert!(request.scan.prefs.headers);
        assert!(request.fingerprint.client_simulation);
        assert_eq!(request.starttls.protocol.as_deref(), Some("smtp"));
        assert!(request.network.ipv4_only);
        assert!(!request.network.ipv6_only);
        assert_eq!(request.ip.as_deref(), Some("8.8.8.8"));
        assert!(!request.scan.scope.all);
    }

    #[test]
    fn test_options_to_request_full_scan() {
        let options = ScanOptions {
            full_scan: true,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com", &options)
            .expect("request should build");

        assert!(request.scan.proto.enabled);
        assert!(request.scan.ciphers.each_cipher);
        assert!(request.scan.vulns.vulnerabilities);
        assert!(request.scan.certs.analyze_certificates);
        assert!(request.scan.prefs.headers);
        assert!(request.fingerprint.client_simulation);
        assert!(request.scan.scope.all);
    }

    #[test]
    fn test_options_to_request_minimal() {
        let options = ScanOptions::default();
        let err = ScanExecutor::options_to_request("example.com:443", &options)
            .expect_err("empty scan options should fail");

        assert!(
            err.to_string()
                .contains("Scan options must enable at least one scan phase")
        );
    }

    #[test]
    fn test_options_to_request_ipv6_only() {
        let options = ScanOptions {
            ipv6_only: true,
            ..Default::default()
        };

        let err = ScanExecutor::options_to_request("example.com", &options)
            .expect_err("address-family-only options should fail without scan workload");

        assert!(
            err.to_string()
                .contains("Scan options must enable at least one scan phase")
        );
    }

    #[test]
    fn test_options_to_request_maps_analyze_certificates() {
        let options = ScanOptions {
            analyze_certificates: true,
            ..Default::default()
        };

        let request = ScanExecutor::options_to_request("example.com", &options)
            .expect("request should build");

        assert!(request.scan.certs.analyze_certificates);
        assert!(!request.scan.proto.enabled);
        assert!(!request.scan.scope.full);
    }

    #[test]
    fn test_webhook_lookup_target_brackets_ipv6() {
        assert_eq!(
            webhook_lookup_target("2001:db8::1", 443),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn test_webhook_lookup_target_strips_existing_brackets() {
        assert_eq!(
            webhook_lookup_target("[2001:db8::1]", 443),
            "[2001:db8::1]:443"
        );
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_private_hostnames() {
        let err = validate_webhook_url("https://localhost/callback")
            .await
            .expect_err("localhost should fail");

        assert!(err.to_string().contains("private/local host"));
    }

    #[tokio::test]
    async fn test_validate_webhook_url_rejects_invalid_scheme() {
        let err = validate_webhook_url("ftp://example.com/callback")
            .await
            .expect_err("invalid scheme should fail");

        assert!(err.to_string().contains("only http/https"));
    }
}
