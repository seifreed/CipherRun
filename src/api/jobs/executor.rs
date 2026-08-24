// Scan Executor - Background job processor

use crate::Result;
use crate::api::jobs::{JobQueue, RetryDisposition, ScanJob};
use crate::api::models::request::ScanOptions;
use crate::api::models::response::{ProgressMessage, ScanStatus};
use crate::api::presenters::target_input::scan_request_from_target_and_options;
use crate::api::state::ApiStats;
use crate::application::ScanRequest;
use crate::error::TlsError;
use crate::scanner::{ScanResults, Scanner};
use crate::security::webhook::{validate_webhook_url, webhook_http_client};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{error, info, warn};

const WEBHOOK_MAX_ATTEMPTS: u8 = 3;
const WEBHOOK_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_SCAN_ATTEMPTS: u32 = 3;
const JOB_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Scan executor for processing background jobs
pub struct ScanExecutor {
    job_queue: Arc<dyn JobQueue>,
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    progress_tx: broadcast::Sender<ProgressMessage>,
    stats: Option<Arc<RwLock<ApiStats>>>,
    webhook_signing_secret: Option<Arc<Vec<u8>>>,
    worker_allowed_cidrs: Arc<Vec<ipnetwork::IpNetwork>>,
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
            webhook_signing_secret: None,
            worker_allowed_cidrs: Arc::new(Vec::new()),
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn with_stats(mut self, stats: Arc<RwLock<ApiStats>>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_webhook_signing_secret(mut self, secret: Option<Vec<u8>>) -> Self {
        self.webhook_signing_secret = secret.map(Arc::new);
        self
    }

    pub fn with_worker_allowed_cidrs(mut self, cidrs: Vec<ipnetwork::IpNetwork>) -> Self {
        self.worker_allowed_cidrs = Arc::new(cidrs);
        self
    }

    pub fn has_webhook_signing_secret(&self) -> bool {
        self.webhook_signing_secret.is_some()
    }

    pub(crate) fn webhook_signing_secret(&self) -> Option<Vec<u8>> {
        self.webhook_signing_secret
            .as_deref()
            .map(ToOwned::to_owned)
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
            let mut job = match self.job_queue.dequeue().await {
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
                    // Semaphore closed — re-enqueue the job so it's not lost.
                    // dequeue already claimed it as Running, so reset it to
                    // Queued or a later dequeue would skip it as non-pending.
                    error!("Semaphore closed, cannot execute job {}", job.id);
                    job.mark_queued();
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

        // Send the initial progress update. If a cancellation raced in during
        // start-up, the preserving persist reports it and we abort rather than
        // resurrecting the job.
        if !self
            .send_progress(queue.clone(), &mut job, 0, "Starting scan")
            .await
        {
            info!("Job {} was cancelled during start-up, aborting", job.id);
            return;
        }

        let progress_tx = self.progress_tx.clone();
        let queue_for_scan = queue.clone();
        let job_for_scan = job.clone();
        let worker_allowed_cidrs = self.worker_allowed_cidrs.clone();
        let mut scan_task = tokio::spawn(async move {
            Self::run_scan(
                &job_for_scan,
                &queue_for_scan,
                &progress_tx,
                &worker_allowed_cidrs,
            )
            .await
        });
        let mut heartbeat = tokio::time::interval(JOB_HEARTBEAT_INTERVAL);

        let scan_result = loop {
            tokio::select! {
                joined = &mut scan_task => {
                    break match joined {
                        Ok(result) => result,
                        Err(err) if err.is_cancelled() => {
                            info!("Scan job {} task aborted after cancellation", job.id);
                            return;
                        }
                        Err(err) => {
                            Err(TlsError::Other(format!("Scan task join error: {err}")))
                        }
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
                                // Scan finished successfully right before/after abort.
                                // Persist the result with a forcing update so it is not
                                // lost: marking the in-memory job completed and only
                                // broadcasting would leave the queue holding Cancelled
                                // with no results.
                                let duration_ms = job
                                    .started_at
                                    .map(|started| {
                                        u64::try_from(
                                            (chrono::Utc::now() - started)
                                                .num_milliseconds()
                                                .max(0),
                                        )
                                        .unwrap_or_default()
                                    })
                                    .unwrap_or_default();
                                job = current;
                                job.mark_completed(results);
                                if let Err(e) = queue.update_job(&job).await {
                                    error!(
                                        "Failed to persist completed cancelled-race job {}: {}",
                                        job.id, e
                                    );
                                }
                                let _ = self.progress_tx.send(ProgressMessage::completed(&job.id));
                                // The job is now Completed with results available, so it
                                // must count toward completed-scan stats just like the
                                // normal success path.
                                if let Some(stats) = &self.stats {
                                    stats.write().await.record_completed_scan(duration_ms);
                                }
                            }
                            Ok(Err(e)) => {
                                job = current;
                                job.mark_failed(e.to_string());
                                if let Err(e) = queue.update_job(&job).await {
                                    error!(
                                        "Failed to persist failed cancelled-race job {}: {}",
                                        job.id, e
                                    );
                                }
                                let _ = self.progress_tx.send(ProgressMessage::failed(
                                    &job.id,
                                    job.error.clone().unwrap_or_default(),
                                ));
                            }
                            _ => {
                                let _ = self
                                    .progress_tx
                                    .send(ProgressMessage::cancelled(&job.id, job.progress));
                            }
                        }
                        return;
                    }
                }
                _ = heartbeat.tick() => {
                    match queue.renew_lease(&job.id).await {
                        Ok(true) => {}
                        Ok(false) => warn!("Lease renewal skipped for job {}", job.id),
                        Err(error) => warn!("Failed to renew lease for job {}: {}", job.id, error),
                    }
                }
            }
        };

        // Resolve the scan outcome and the in-queue job state, but defer
        // recording completed/failed stats until the authoritative final update
        // below. A cancellation racing in between the check here and that update
        // must not leave the stats counting a completion/failure that the queue
        // records as Cancelled.
        let mut completed_duration: Option<u64> = None;
        let mut failed = false;

        match scan_result {
            Ok(results) => {
                info!("Scan job {} completed successfully", job.id);
                let duration_ms = job
                    .started_at
                    .map(|started| {
                        u64::try_from((chrono::Utc::now() - started).num_milliseconds().max(0))
                            .unwrap_or_default()
                    })
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
                    ProgressMessage::cancelled(&job.id, job.progress)
                } else {
                    ProgressMessage::completed(&job.id)
                };
                let _ = self.progress_tx.send(msg);
                if !cancelled {
                    completed_duration = Some(duration_ms);
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
                        match queue
                            .retry_or_dead_letter(&job, &error_msg, MAX_SCAN_ATTEMPTS)
                            .await
                        {
                            Ok(RetryDisposition::Requeued) => {
                                info!(
                                    "Requeued scan job {} after failed attempt {}/{}",
                                    job.id, job.attempts, MAX_SCAN_ATTEMPTS
                                );
                                let mut message = ProgressMessage::new(&job.id, 0, "retrying");
                                message.details = Some(error_msg);
                                let _ = self.progress_tx.send(message);
                                return;
                            }
                            Ok(RetryDisposition::DeadLettered) => {
                                job.mark_dead_letter(error_msg);
                                failed = true;
                            }
                            Err(retry_error) => {
                                error!("Failed to requeue scan job {}: {}", job.id, retry_error);
                                job.mark_failed(error_msg);
                                failed = true;
                            }
                        }
                    }
                } else {
                    match queue
                        .retry_or_dead_letter(&job, &error_msg, MAX_SCAN_ATTEMPTS)
                        .await
                    {
                        Ok(RetryDisposition::Requeued) => {
                            info!(
                                "Requeued scan job {} after failed attempt {}/{}",
                                job.id, job.attempts, MAX_SCAN_ATTEMPTS
                            );
                            let mut message = ProgressMessage::new(&job.id, 0, "retrying");
                            message.details = Some(error_msg);
                            let _ = self.progress_tx.send(message);
                            return;
                        }
                        Ok(RetryDisposition::DeadLettered) => {
                            job.mark_dead_letter(error_msg);
                            failed = true;
                        }
                        Err(retry_error) => {
                            error!("Failed to requeue scan job {}: {}", job.id, retry_error);
                            job.mark_failed(error_msg);
                            failed = true;
                        }
                    }
                }
                let msg = if cancelled {
                    ProgressMessage::cancelled(&job.id, job.progress)
                } else {
                    ProgressMessage::failed(&job.id, job.error.clone().unwrap_or_default())
                };
                let _ = self.progress_tx.send(msg);
            }
        }

        // Authoritative final update. Use update_job_preserving_cancelled to
        // prevent the race where a cancellation request arrives between scan
        // completion and this update. Only record completed/failed stats when
        // the update actually took (Ok(true)); if a cancellation raced in
        // (Ok(false)) the job is Cancelled and must not be counted.
        match queue.update_job_preserving_cancelled(&job).await {
            Ok(true) => {
                if let Some(duration_ms) = completed_duration {
                    if let Some(stats) = &self.stats {
                        stats.write().await.record_completed_scan(duration_ms);
                    }
                } else if failed && let Some(stats) = &self.stats {
                    stats.write().await.record_failed_scan();
                }
            }
            Ok(false) => {
                // Job was cancelled while we were processing - this is expected.
                tracing::info!("Job {} was cancelled, preserving cancelled status", job.id);
            }
            Err(e) => {
                error!("Failed to update job status: {}", e);
            }
        }

        // Call webhook if configured
        if let (Some(webhook_url), Some(secret)) =
            (&job.webhook_url, self.webhook_signing_secret.as_deref())
            && !matches!(job.status, ScanStatus::Cancelled)
            && let Err(e) = Self::send_webhook(webhook_url, &job, secret).await
        {
            warn!("Failed to send webhook for job {}: {}", job.id, e);
        }
    }

    /// Run the actual scan
    async fn run_scan(
        job: &ScanJob,
        queue: &Arc<dyn JobQueue>,
        progress_tx: &broadcast::Sender<ProgressMessage>,
        worker_allowed_cidrs: &[ipnetwork::IpNetwork],
    ) -> Result<ScanResults> {
        let request = Self::options_to_request_with_worker_scope(
            &job.target,
            &job.options,
            worker_allowed_cidrs,
        )?;

        Self::report_running_progress(job, queue, progress_tx, 5, "Initializing scanner").await;

        // Create scanner
        let scanner = Scanner::new(request)?;

        Self::report_running_progress(job, queue, progress_tx, 10, "Resolving target").await;

        // Initialize scanner (DNS resolution)
        scanner.initialize().await?;

        Self::report_running_progress(job, queue, progress_tx, 15, "Starting TLS scan").await;

        // Run the scan
        let results = scanner.run().await?;

        Self::report_running_progress(job, queue, progress_tx, 95, "Finalizing results").await;

        Ok(results)
    }

    /// Broadcast a running-phase progress milestone and persist it to the job
    /// record.
    ///
    /// Persisting (not just broadcasting) is what lets clients polling
    /// `GET /scan/{id}` observe live progress; without it the stored record
    /// stays frozen at the initial "Starting scan" until the scan reaches a
    /// terminal state, and only WebSocket subscribers see intermediate updates.
    /// The cancellation-preserving persist ensures a concurrent cancellation is
    /// never overwritten back to Running.
    async fn report_running_progress(
        job: &ScanJob,
        queue: &Arc<dyn JobQueue>,
        progress_tx: &broadcast::Sender<ProgressMessage>,
        progress: u8,
        stage: &str,
    ) {
        let _ = progress_tx.send(ProgressMessage::new(&job.id, progress, stage));
        let mut snapshot = job.clone();
        snapshot.update_progress(progress, stage.to_string());
        if let Err(e) = queue.update_job_preserving_cancelled(&snapshot).await {
            error!(
                "Failed to persist running progress for job {}: {}",
                job.id, e
            );
        }
    }

    fn options_to_request(target: &str, options: &ScanOptions) -> Result<ScanRequest> {
        Self::options_to_request_with_worker_scope(target, options, &[])
    }

    fn options_to_request_with_worker_scope(
        target: &str,
        options: &ScanOptions,
        worker_allowed_cidrs: &[ipnetwork::IpNetwork],
    ) -> Result<ScanRequest> {
        let mut request = scan_request_from_target_and_options(target, options)
            .map_err(|error| TlsError::Other(error.to_string()))?;
        request.network.allow_cidrs = worker_allowed_cidrs.to_vec();
        Ok(request)
    }

    /// Broadcast a progress update and persist it.
    ///
    /// Returns `false` if the job has been cancelled (so the caller should stop).
    /// Persistence uses the cancellation-preserving variant: a plain `update_job`
    /// here could clobber a cancellation that raced with the start-up sequence
    /// and resurrect the job back to Running, the exact TOCTOU the surrounding
    /// `mark_started` write guards against.
    async fn send_progress(
        &self,
        queue: Arc<dyn JobQueue>,
        job: &mut ScanJob,
        progress: u8,
        stage: &str,
    ) -> bool {
        job.update_progress(progress, stage.to_string());
        let msg = ProgressMessage::new(&job.id, progress, stage);
        let _ = self.progress_tx.send(msg);
        // A persistence error is not evidence of cancellation; keep going (true),
        // matching the previous fire-and-forget behaviour.
        match queue.update_job_preserving_cancelled(job).await {
            Ok(updated) => updated,
            Err(e) => {
                error!("Failed to persist progress for job {}: {}", job.id, e);
                true
            }
        }
    }

    /// Send webhook notification.
    /// Validates the URL against SSRF before making signed retryable requests.
    async fn send_webhook(webhook_url: &str, job: &ScanJob, secret: &[u8]) -> Result<()> {
        let validated = validate_webhook_url(webhook_url).await?;
        let client = webhook_http_client(&validated)?;

        Self::send_webhook_attempts(
            &client,
            webhook_url,
            job,
            secret,
            WEBHOOK_MAX_ATTEMPTS,
            WEBHOOK_RETRY_DELAY,
        )
        .await
    }

    async fn send_webhook_attempts(
        client: &reqwest::Client,
        webhook_url: &str,
        job: &ScanJob,
        secret: &[u8],
        max_attempts: u8,
        retry_delay: Duration,
    ) -> Result<()> {
        let event = match job.status {
            ScanStatus::Completed => "scan.completed",
            ScanStatus::Failed => "scan.failed",
            _ => "scan.finished",
        };
        let delivery_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let payload = serde_json::json!({
            "event": event,
            "delivery_id": delivery_id,
            "job_id": job.id,
            "target": job.target,
            "status": job.status,
            "completed_at": job.completed_at,
            "error": job.error,
        });
        let payload = serde_json::to_vec(&payload)?;
        let signature = webhook_signature(secret, &timestamp, &payload);
        let max_attempts = max_attempts.max(1);

        for attempt in 1..=max_attempts {
            let response = client
                .post(webhook_url)
                .header("Content-Type", "application/json")
                .header("X-CipherRun-Event", event)
                .header("X-CipherRun-Delivery", &delivery_id)
                .header("X-CipherRun-Timestamp", &timestamp)
                .header("X-CipherRun-Signature", &signature)
                .body(payload.clone())
                .send()
                .await;

            match response {
                Ok(response) if response.status().is_success() => {
                    info!(
                        "Delivered webhook {} for job {} after {} attempt(s)",
                        delivery_id, job.id, attempt
                    );
                    return Ok(());
                }
                Ok(response)
                    if attempt == max_attempts
                        || !is_retryable_webhook_status(response.status()) =>
                {
                    return Err(TlsError::HttpError {
                        status: response.status().as_u16(),
                        details: format!(
                            "Webhook delivery {} failed after {} attempt(s)",
                            delivery_id, attempt
                        ),
                    });
                }
                Ok(response) => warn!(
                    "Webhook {} attempt {} returned {}, retrying",
                    delivery_id,
                    attempt,
                    response.status()
                ),
                Err(error) if attempt == max_attempts => return Err(error.into()),
                Err(error) => warn!(
                    "Webhook {} attempt {} failed: {}, retrying",
                    delivery_id, attempt, error
                ),
            }

            let multiplier = 1u32
                .checked_shl(u32::from(attempt.saturating_sub(1)))
                .unwrap_or(u32::MAX);
            tokio::time::sleep(retry_delay.saturating_mul(multiplier)).await;
        }

        unreachable!("max_attempts is clamped to at least one")
    }

    /// Shutdown the executor gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating executor shutdown");
        self.shutdown_tx
            .send(true)
            .map_err(|e| TlsError::Other(format!("Failed to send shutdown signal: {e}")))?;
        Ok(())
    }
}

fn webhook_signature(secret: &[u8], timestamp: &str, payload: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(timestamp.as_bytes());
    context.update(b".");
    context.update(payload);
    format!("v1={}", hex::encode(context.sign().as_ref()))
}

fn is_retryable_webhook_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_EARLY
                | reqwest::StatusCode::TOO_MANY_REQUESTS
        )
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
            webhook_signing_secret: self.webhook_signing_secret.clone(),
            worker_allowed_cidrs: self.worker_allowed_cidrs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State as AxumState,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct WebhookTestState {
        attempts: AtomicUsize,
        signature_valid: AtomicBool,
        secret: Vec<u8>,
    }

    async fn retrying_webhook(
        AxumState(state): AxumState<Arc<WebhookTestState>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        let timestamp = headers
            .get("X-CipherRun-Timestamp")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let signature = headers
            .get("X-CipherRun-Signature")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("v1="))
            .and_then(|value| hex::decode(value).ok());
        let mut signed = timestamp.as_bytes().to_vec();
        signed.push(b'.');
        signed.extend_from_slice(&body);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &state.secret);
        let valid = signature
            .as_deref()
            .is_some_and(|signature| ring::hmac::verify(&key, &signed, signature).is_ok());
        state.signature_valid.fetch_and(valid, Ordering::SeqCst);

        if state.attempts.fetch_add(1, Ordering::SeqCst) < 2 {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::NO_CONTENT
        }
    }

    #[tokio::test]
    async fn webhook_is_signed_and_retries_transient_failures() {
        let state = Arc::new(WebhookTestState {
            attempts: AtomicUsize::new(0),
            signature_valid: AtomicBool::new(true),
            secret: vec![b's'; 32],
        });
        let app = Router::new()
            .route("/hook", post(retrying_webhook))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::full(), None);
        job.mark_completed(ScanResults::default());

        ScanExecutor::send_webhook_attempts(
            &reqwest::Client::new(),
            &format!("http://{address}/hook"),
            &job,
            &state.secret,
            3,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert_eq!(state.attempts.load(Ordering::SeqCst), 3);
        assert!(state.signature_valid.load(Ordering::SeqCst));
        server.abort();
    }

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
    fn worker_scope_is_injected_after_api_request_validation() {
        let options = ScanOptions {
            test_protocols: true,
            ..Default::default()
        };
        let cidr = vec!["10.20.0.0/16".parse().unwrap()];
        let request =
            ScanExecutor::options_to_request_with_worker_scope("example.com", &options, &cidr)
                .expect("request should build");

        assert_eq!(request.network.allow_cidrs, cidr);
        assert!(!request.network.allow_private);
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
}
