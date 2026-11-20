// Scan Executor - Background job processor

use crate::Result;
use crate::api::jobs::{JobQueue, RetryDisposition, ScanJob};
use crate::api::models::request::ScanOptions;
use crate::api::models::response::{ProgressMessage, ScanStatus};
use crate::api::presenters::target_input::scan_request_from_target_and_options;
use crate::api::state::ApiStats;
use crate::application::{PersistedScan, ScanRequest, ScanResultsStore};
use crate::error::TlsError;
use crate::scanner::{ScanResults, Scanner};
use crate::security::webhook::{validate_webhook_url, webhook_http_client};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{Instrument, error, info, info_span, warn};
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

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
    results_store: Option<Arc<dyn ScanResultsStore>>,
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
            results_store: None,
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

    pub fn with_results_store(mut self, store: Arc<dyn ScanResultsStore>) -> Self {
        self.results_store = Some(store);
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
            event_name = "scan_executor.started",
            concurrency = self.max_concurrent,
            "Scan executor started"
        );

        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut active_tasks = tokio::task::JoinSet::new();
        let mut dequeue_failure_reported = false;

        loop {
            // Check for shutdown signal
            if *shutdown_rx.borrow() {
                info!(
                    event_name = "scan_executor.draining",
                    active_jobs = active_tasks.len(),
                    "Waiting for active scan jobs to finish"
                );
                while let Some(result) = active_tasks.join_next().await {
                    if let Err(error) = result {
                        log_scan_job_task_join_failed(&error);
                    }
                }
                info!(
                    event_name = "scan_executor.shutdown",
                    "Scan executor stopped"
                );
                break;
            }

            // Try to dequeue a job FIRST, before acquiring a permit.
            // This avoids holding a permit while no work is available,
            // which would starve real jobs under high load.
            let result = tokio::select! {
                result = self.job_queue.dequeue() => result,
                _ = shutdown_rx.changed() => continue,
                result = active_tasks.join_next(), if !active_tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        log_scan_job_task_join_failed(&error);
                    }
                    continue;
                }
            };
            let mut job = match result {
                Ok(Some(job)) => {
                    dequeue_failure_reported = false;
                    job
                }
                Ok(None) => {
                    dequeue_failure_reported = false;
                    tokio::select! {
                        _ = shutdown_rx.changed() => {},
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                        result = active_tasks.join_next(), if !active_tasks.is_empty() => {
                            if let Some(Err(error)) = result {
                                log_scan_job_task_join_failed(&error);
                            }
                        }
                    }
                    continue;
                }
                Err(error) => {
                    if !dequeue_failure_reported {
                        error!(
                            event_name = "scan_job.dequeue_failed",
                            error_type = "queue",
                            error_code = error.observability_code(),
                            "Failed to dequeue scan job"
                        );
                        dequeue_failure_reported = true;
                    }
                    tokio::select! {
                        _ = shutdown_rx.changed() => {},
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                    }
                    continue;
                }
            };

            // Now acquire a permit to limit concurrency
            let permit_result = tokio::select! {
                permit = Arc::clone(&self.semaphore).acquire_owned() => permit,
                _ = shutdown_rx.changed() => {
                    job.mark_queued();
                    if let Err(error) = self.job_queue.enqueue(job).await {
                        error!(
                            event_name = "scan_job.requeue_failed",
                            error_type = "queue",
                            error_code = error.observability_code(),
                            "Failed to requeue scan job during shutdown"
                        );
                    }
                    continue;
                }
            };
            let permit = match permit_result {
                Ok(p) => p,
                Err(_) => {
                    // Semaphore closed — re-enqueue the job so it's not lost.
                    // dequeue already claimed it as Running, so reset it to
                    // Queued or a later dequeue would skip it as non-pending.
                    error!(
                        event_name = "scan_job.execution_slot.unavailable",
                        job_id = %job.id,
                        error_type = "semaphore_closed",
                        outcome = "requeue_attempted",
                        "Cannot acquire scan execution slot"
                    );
                    job.mark_queued();
                    if let Err(error) = self.job_queue.enqueue(job).await {
                        error!(
                            event_name = "scan_job.requeue_failed",
                            error_type = "queue",
                            error_code = error.observability_code(),
                            "Failed to requeue scan job after semaphore closure"
                        );
                    }
                    break;
                }
            };

            let executor = Arc::clone(&self);
            let queue = Arc::clone(&self.job_queue);
            let job_span = info_span!(
                "scan.job",
                component = "api.jobs",
                operation = "scan",
                job_id = %job.id,
            );
            #[cfg(feature = "otel")]
            if let Some(parent) = job
                .traceparent
                .as_deref()
                .and_then(crate::telemetry::context_from_traceparent)
                && job_span.set_parent(parent).is_err()
            {
                warn!(
                    event_name = "trace_context.rejected",
                    job_id = %job.id,
                    "Failed to apply scan job trace parent"
                );
            }

            active_tasks.spawn(
                async move {
                    executor.execute_scan(queue, job).await;
                    drop(permit);
                }
                .instrument(job_span),
            );
        }

        Ok(())
    }

    /// Execute a scan job
    async fn execute_scan(&self, queue: Arc<dyn JobQueue>, mut job: ScanJob) {
        match queue.get_job(&job.id).await {
            Ok(Some(current)) if matches!(current.status, ScanStatus::Cancelled) => {
                info!(event_name = "scan_job.cancelled_before_start", job_id = %job.id, outcome = "skipped", "Skipping cancelled scan job");
                return;
            }
            Err(error) => warn!(
                event_name = "scan_job.status_check.failed",
                job_id = %job.id,
                error_type = "queue",
                error_code = error.observability_code(),
                "Failed to read scan job status before starting"
            ),
            _ => {}
        }

        info!(event_name = "scan_job.started", job_id = %job.id, "Starting scan job");

        // Mark job as started. Use update_job_preserving_cancelled so that a
        // cancellation arriving between the check above and this write is not
        // silently overwritten by the Started status.
        job.mark_started();
        match queue.update_job_preserving_cancelled(&job).await {
            Ok(true) => {}
            Ok(false) => {
                info!(event_name = "scan_job.cancelled_before_start", job_id = %job.id, outcome = "skipped", "Scan job cancelled before start");
                return;
            }
            Err(error) => {
                error!(event_name = "scan_job.start_persist_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to persist scan job start");
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
            info!(event_name = "scan_job.cancelled_during_startup", job_id = %job.id, outcome = "cancelled", "Scan job cancelled during startup");
            return;
        }

        let progress_tx = self.progress_tx.clone();
        let queue_for_scan = queue.clone();
        let job_for_scan = job.clone();
        let worker_allowed_cidrs = self.worker_allowed_cidrs.clone();
        let mut scan_task = crate::utils::task::spawn_with_current_span(async move {
            Self::run_scan(
                &job_for_scan,
                &queue_for_scan,
                &progress_tx,
                &worker_allowed_cidrs,
            )
            .await
        });
        let mut heartbeat = tokio::time::interval(JOB_HEARTBEAT_INTERVAL);
        let mut status_check_failure_reported = false;

        let scan_result = loop {
            tokio::select! {
                joined = &mut scan_task => {
                    break match joined {
                        Ok(result) => result,
                        Err(err) if err.is_cancelled() => {
                            info!(event_name = "scan_job.task.cancelled", job_id = %job.id, outcome = "cancelled", "Scan task aborted after cancellation");
                            return;
                        }
                        Err(error) => {
                            log_scan_job_task_join_failed(&error);
                            Err(TlsError::Other("Scan task join error".to_string()))
                        }
                    };
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    let current = match queue.get_job(&job.id).await {
                        Ok(current) => {
                            status_check_failure_reported = false;
                            current
                        }
                        Err(error) => {
                            if !status_check_failure_reported {
                                warn!(
                                    event_name = "scan_job.status_check.failed",
                                    job_id = %job.id,
                                    error_type = "queue",
                                    error_code = error.observability_code(),
                                    "Failed to poll scan job status"
                                );
                                status_check_failure_reported = true;
                            }
                            None
                        }
                    };
                    if let Some(current) = current.filter(|current| matches!(current.status, ScanStatus::Cancelled)) {
                        info!(event_name = "scan_job.cancellation_requested", job_id = %job.id, outcome = "aborting", "Aborting scan after cancellation request");
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
                                if let Err(error) = queue.update_job(&job).await {
                                    error!(event_name = "scan_job.result_persist_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to persist completed scan after cancellation");
                                }
                                let _ = self.progress_tx.send(ProgressMessage::completed(&job.id));
                                // The job is now Completed with results available, so it
                                // must count toward completed-scan stats just like the
                                // normal success path.
                                if let Some(stats) = &self.stats {
                                    let mut stats = stats.write().await;
                                    stats.record_completed_scan(duration_ms);
                                    stats.record_completed_scan_for_owner(
                                        &job.principal_id,
                                        job.tenant_id.as_deref(),
                                        duration_ms,
                                    );
                                }
                            }
                            Ok(Err(e)) => {
                                job = current;
                                job.mark_failed(e.to_string());
                                if let Err(error) = queue.update_job(&job).await {
                                    error!(event_name = "scan_job.failure_persist_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to persist failed scan after cancellation");
                                }
                                let _ = self.progress_tx.send(ProgressMessage::failed(
                                    &job.id,
                                    job.error.clone().unwrap_or_default(),
                                ));
                            }
                            Err(error) => {
                                if error.is_panic() {
                                    log_scan_job_task_join_failed(&error);
                                }
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
                        Ok(false) => warn!(event_name = "scan_job.lease_renewal.skipped", job_id = %job.id, outcome = "lease_lost", "Scan lease renewal skipped"),
                        Err(error) => warn!(event_name = "scan_job.lease_renewal.failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to renew scan lease"),
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
        let mut outcome_error_code = "unknown";
        let mut failed = false;

        match scan_result {
            Ok(results) => {
                if let Err(error) = self.persist_results(&job, &results).await {
                    outcome_error_code = error.observability_code();
                    error!(event_name = "scan_job.result_persist_failed", job_id = %job.id, error_type = "results_store", error_code = error.observability_code(), "Failed to persist scan results");
                    job.mark_failed(error.to_string());
                    failed = true;
                    let _ = self.progress_tx.send(ProgressMessage::failed(
                        &job.id,
                        job.error.clone().unwrap_or_default(),
                    ));
                }
                let duration_ms = job
                    .started_at
                    .map(|started| {
                        u64::try_from((chrono::Utc::now() - started).num_milliseconds().max(0))
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                let mut cancelled = false;

                let current =
                    get_job_for_status_check(queue.as_ref(), &job.id, "success_finalization").await;
                if let Some(current) = current {
                    if matches!(current.status, ScanStatus::Cancelled) {
                        cancelled = true;
                        job = current;
                        info!(event_name = "scan_job.cancelled", job_id = %job.id, outcome = "cancelled", "Scan finished after cancellation; preserving cancelled status");
                    } else {
                        if !failed {
                            job.mark_completed(results);
                        }
                    }
                } else {
                    if !failed {
                        job.mark_completed(results);
                    }
                }

                let msg = if cancelled {
                    ProgressMessage::cancelled(&job.id, job.progress)
                } else if failed {
                    ProgressMessage::failed(&job.id, job.error.clone().unwrap_or_default())
                } else {
                    ProgressMessage::completed(&job.id)
                };
                let _ = self.progress_tx.send(msg);
                if !cancelled && !failed {
                    completed_duration = Some(duration_ms);
                }
            }
            Err(e) => {
                outcome_error_code = e.observability_code();
                let error_msg = e.to_string();
                let mut cancelled = false;
                let current =
                    get_job_for_status_check(queue.as_ref(), &job.id, "failure_finalization").await;
                if let Some(current) = current {
                    if matches!(current.status, ScanStatus::Cancelled) {
                        cancelled = true;
                        job = current;
                        info!(event_name = "scan_job.cancelled", job_id = %job.id, outcome = "cancelled", "Scan failed after cancellation; preserving cancelled status");
                    } else {
                        match queue
                            .retry_or_dead_letter(&job, &error_msg, MAX_SCAN_ATTEMPTS)
                            .await
                        {
                            Ok(RetryDisposition::Requeued) => {
                                info!(event_name = "scan_job.retry.scheduled", job_id = %job.id, attempt = job.attempts, max_attempts = MAX_SCAN_ATTEMPTS, error_code = outcome_error_code, outcome = "requeued", "Scan retry scheduled");
                                let mut message = ProgressMessage::new(&job.id, 0, "retrying");
                                message.details = Some(error_msg);
                                let _ = self.progress_tx.send(message);
                                return;
                            }
                            Ok(RetryDisposition::DeadLettered) => {
                                error!(event_name = "scan_job.dead_lettered", job_id = %job.id, error_code = outcome_error_code, outcome = "failed", "Scan job exhausted retry attempts");
                                job.mark_dead_letter(error_msg);
                                failed = true;
                            }
                            Err(error) => {
                                error!(event_name = "scan_job.retry.schedule_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to schedule scan retry");
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
                            info!(event_name = "scan_job.retry.scheduled", job_id = %job.id, attempt = job.attempts, max_attempts = MAX_SCAN_ATTEMPTS, error_code = outcome_error_code, outcome = "requeued", "Scan retry scheduled");
                            let mut message = ProgressMessage::new(&job.id, 0, "retrying");
                            message.details = Some(error_msg);
                            let _ = self.progress_tx.send(message);
                            return;
                        }
                        Ok(RetryDisposition::DeadLettered) => {
                            error!(event_name = "scan_job.dead_lettered", job_id = %job.id, error_code = outcome_error_code, outcome = "failed", "Scan job exhausted retry attempts");
                            job.mark_dead_letter(error_msg);
                            failed = true;
                        }
                        Err(error) => {
                            error!(event_name = "scan_job.retry.schedule_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to schedule scan retry");
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
                        let mut stats = stats.write().await;
                        stats.record_completed_scan(duration_ms);
                        stats.record_completed_scan_for_owner(
                            &job.principal_id,
                            job.tenant_id.as_deref(),
                            duration_ms,
                        );
                    }
                } else if failed && let Some(stats) = &self.stats {
                    let mut stats = stats.write().await;
                    stats.record_failed_scan();
                    stats.record_failed_scan_for_owner(&job.principal_id, job.tenant_id.as_deref());
                }
            }
            Ok(false) => {
                // Job was cancelled while we were processing - this is expected.
                tracing::info!(
                    event_name = "scan_job.cancelled",
                    job_id = %job.id,
                    "Preserving cancelled job status"
                );
            }
            Err(error) => {
                error!(event_name = "scan_job.final_status_persist_failed", job_id = %job.id, error_type = "queue", error_code = error.observability_code(), "Failed to persist final scan status");
            }
        }

        // Call webhook if configured
        if let (Some(webhook_url), Some(secret)) =
            (&job.webhook_url, self.webhook_signing_secret.as_deref())
            && !matches!(job.status, ScanStatus::Cancelled)
        {
            let started = Instant::now();
            if let Err(error) = Self::send_webhook(webhook_url, &job, secret).await {
                log_scan_job_webhook_failed(&job.id, &error, started.elapsed());
            }
        }

        let duration_ms = job
            .started_at
            .map(|started| {
                u64::try_from((chrono::Utc::now() - started).num_milliseconds().max(0))
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        match &job.status {
            ScanStatus::Failed => info!(
                event_name = "scan_job.finished",
                job_id = %job.id,
                duration_ms,
                error_code = outcome_error_code,
                outcome = "failed",
                "Scan job finished"
            ),
            ScanStatus::Cancelled => info!(
                event_name = "scan_job.finished",
                job_id = %job.id,
                duration_ms,
                outcome = "cancelled",
                "Scan job finished"
            ),
            _ => info!(
                event_name = "scan_job.finished",
                job_id = %job.id,
                duration_ms,
                outcome = "complete",
                "Scan job finished"
            ),
        }
    }

    /// Run the actual scan
    async fn persist_results(&self, job: &ScanJob, results: &ScanResults) -> Result<()> {
        let Some(store) = &self.results_store else {
            return Ok(());
        };
        let persisted = PersistedScan::try_from_scan_results(results)?.with_owner(
            job.principal_id.clone(),
            job.tenant_id.clone(),
            job.created_by_key_id.clone(),
        );
        store.store_scan(&persisted).await.map(|_| ())
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
        if let Err(error) = queue.update_job_preserving_cancelled(&snapshot).await {
            error!(
                event_name = "scan_job.progress.persist_failed",
                job_id = %job.id,
                error_type = "queue",
                error_code = error.observability_code(),
                "Failed to persist running progress"
            );
        }
    }

    #[allow(dead_code)]
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
            Err(error) => {
                error!(
                    event_name = "scan_job.progress.persist_failed",
                    job_id = %job.id,
                    error_type = "queue",
                    error_code = error.observability_code(),
                    "Failed to persist scan progress"
                );
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
        let started = Instant::now();
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
                        event_name = "scan_job.webhook.delivered",
                        job_id = %job.id,
                        attempt,
                        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        outcome = "delivered",
                        "Delivered scan webhook"
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
                    event_name = "scan_job.webhook.retry",
                    job_id = %job.id,
                    attempt,
                    status = response.status().as_u16(),
                    "Scan webhook returned retryable status"
                ),
                Err(error) if attempt == max_attempts => return Err(error.into()),
                Err(_) => warn!(
                    event_name = "scan_job.webhook.retry",
                    job_id = %job.id,
                    attempt,
                    error_type = "transport",
                    "Scan webhook transport failed"
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
        info!(
            event_name = "scan_executor.shutdown_requested",
            "Initiating executor shutdown"
        );
        self.shutdown_tx
            .send(true)
            .map_err(|e| TlsError::Other(format!("Failed to send shutdown signal: {e}")))?;
        Ok(())
    }
}

fn log_scan_job_webhook_failed(job_id: &str, error: &TlsError, duration: Duration) {
    warn!(
        event_name = "scan_job.webhook.failed",
        job_id,
        error_type = "webhook",
        error_code = error.observability_code(),
        duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        outcome = "failed",
        "Failed to deliver scan webhook"
    );
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

fn scan_task_join_error_code(error: &tokio::task::JoinError) -> &'static str {
    if error.is_panic() {
        "task_panicked"
    } else {
        "task_cancelled"
    }
}

fn log_scan_job_task_join_failed(error: &tokio::task::JoinError) {
    error!(
        event_name = "scan_job.task.join_failed",
        error_type = if error.is_panic() {
            "panic"
        } else {
            "cancelled"
        },
        error_code = scan_task_join_error_code(error),
        outcome = "failed",
        "Scan job task failed"
    );
}

async fn get_job_for_status_check(
    queue: &dyn JobQueue,
    job_id: &str,
    operation: &'static str,
) -> Option<ScanJob> {
    match queue.get_job(job_id).await {
        Ok(job) => job,
        Err(error) => {
            warn!(
                event_name = "scan_job.status_check.failed",
                operation,
                job_id,
                error_type = "queue",
                error_code = error.observability_code(),
                outcome = "continue_without_status",
                "Failed to read scan job status during finalization"
            );
            None
        }
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
            webhook_signing_secret: self.webhook_signing_secret.clone(),
            worker_allowed_cidrs: self.worker_allowed_cidrs.clone(),
            results_store: self.results_store.clone(),
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

    #[tokio::test]
    async fn scan_task_join_errors_have_static_diagnostic_codes() {
        let panic = tokio::spawn(async { panic!("test panic") })
            .await
            .expect_err("task should panic");
        assert_eq!(scan_task_join_error_code(&panic), "task_panicked");

        let cancelled_task = tokio::spawn(std::future::pending::<()>());
        cancelled_task.abort();
        let cancelled = cancelled_task
            .await
            .expect_err("aborted task should be cancelled");
        assert_eq!(scan_task_join_error_code(&cancelled), "task_cancelled");
    }

    #[tokio::test]
    async fn scan_task_join_failure_events_are_categorized_and_redacted() {
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let panic = tokio::spawn(async { panic!("private-panic-detail") })
            .await
            .expect_err("task should panic");
        let cancelled_task = tokio::spawn(std::future::pending::<()>());
        cancelled_task.abort();
        let cancelled = cancelled_task
            .await
            .expect_err("aborted task should be cancelled");

        tracing::subscriber::with_default(subscriber, || {
            log_scan_job_task_join_failed(&panic);
            log_scan_job_task_join_failed(&cancelled);
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2, "{output}");
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "scan_job.task.join_failed"
                && event["fields"]["error_type"] == "panic"
                && event["fields"]["error_code"] == "task_panicked"
                && event["fields"]["outcome"] == "failed"
        }));
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "scan_job.task.join_failed"
                && event["fields"]["error_type"] == "cancelled"
                && event["fields"]["error_code"] == "task_cancelled"
                && event["fields"]["outcome"] == "failed"
        }));
        assert!(!output.contains("private-panic-detail"));
    }

    #[test]
    fn final_status_check_failure_is_logged_without_raw_backend_error() {
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let queue = GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: ScanJob::new("example.com".to_string(), ScanOptions::full(), None),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: true,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                runtime
                    .block_on(get_job_for_status_check(
                        &queue,
                        "job-123",
                        "failure_finalization",
                    ))
                    .is_none()
            );
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("scan_job.status_check.failed"), "{output}");
        assert!(output.contains("failure_finalization"), "{output}");
        assert!(output.contains("continue_without_status"), "{output}");
        assert!(!output.contains("password=must-not-appear"), "{output}");
    }

    #[test]
    fn cancelled_job_before_start_emits_safe_outcome_event() {
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let mut job = ScanJob::new(
            "private-target.example".to_string(),
            ScanOptions::full(),
            None,
        );
        job.mark_cancelled();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job.clone(),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: true,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let (progress_tx, _) = broadcast::channel(1);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let executor = ScanExecutor {
            job_queue: queue.clone(),
            max_concurrent: 1,
            semaphore: Arc::new(Semaphore::new(1)),
            progress_tx,
            stats: None,
            webhook_signing_secret: None,
            worker_allowed_cidrs: Arc::new(Vec::new()),
            results_store: None,
            shutdown_tx: tokio::sync::watch::channel(false).0,
            shutdown_rx,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            runtime.block_on(executor.execute_scan(queue, job.clone()));
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("scan_job.cancelled_before_start"),
            "{output}"
        );
        assert!(output.contains(&job.id), "{output}");
        assert!(output.contains("outcome=\"skipped\""), "{output}");
        assert!(!output.contains("private-target.example"), "{output}");
    }

    #[tokio::test]
    async fn run_scan_rejects_invalid_target_before_network_access() {
        let queue: Arc<dyn JobQueue> = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: ScanJob::new("unused.example".to_string(), ScanOptions::full(), None),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let job = ScanJob::new(
            "invalid target with spaces".to_string(),
            ScanOptions::full(),
            None,
        );
        let (progress_tx, _) = broadcast::channel(1);

        let error = ScanExecutor::run_scan(&job, &queue, &progress_tx, &[])
            .await
            .expect_err("invalid targets should fail before a network scan");

        assert!(matches!(error, TlsError::Other(_)));
    }

    #[tokio::test]
    async fn invalid_scan_target_is_dead_lettered_and_broadcast_as_failed() {
        let mut job = ScanJob::new(
            "invalid target with spaces".to_string(),
            ScanOptions::full(),
            None,
        );
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job.clone(),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue.clone(), 1);
        let mut progress = executor.subscribe_progress();

        executor.execute_scan(queue, job).await;

        let messages = std::iter::from_fn(|| progress.try_recv().ok()).collect::<Vec<_>>();
        assert!(messages.iter().any(|message| message.msg_type == "failed"));
    }

    #[tokio::test]
    async fn initial_status_check_failure_is_logged_without_backend_details() {
        use tracing::instrument::WithSubscriber;

        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let mut job = ScanJob::new(
            "invalid target with spaces".to_string(),
            ScanOptions::full(),
            None,
        );
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job.clone(),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: true,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });

        ScanExecutor::new(queue.clone(), 1)
            .execute_scan(queue, job)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "scan_job.status_check.failed"
                && event["fields"]["error_code"] == "other"
        }));
        assert!(!output.contains("password=must-not-appear"));
    }

    #[tokio::test]
    async fn executor_dispatches_a_queued_job_and_drains_it_on_shutdown() {
        let mut job = ScanJob::new(
            "invalid target with spaces".to_string(),
            ScanOptions::full(),
            None,
        );
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(Some(job.clone())),
            cancelled_job: job,
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = Arc::new(ScanExecutor::new(queue.clone(), 1));
        let mut progress = executor.subscribe_progress();
        let handle = tokio::spawn(Arc::clone(&executor).start());

        let failure = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let message = progress.recv().await.expect("progress channel stays open");
                if message.msg_type == "failed" {
                    break message;
                }
            }
        })
        .await
        .expect("the dispatched invalid job should fail promptly");
        assert_eq!(failure.scan_id, queue.cancelled_job.id);
        assert!(queue.dequeue_calls.load(Ordering::SeqCst) >= 1);

        executor.shutdown().await.unwrap();
        handle.await.unwrap().unwrap();
    }

    struct CancelOnStartQueue {
        job: ScanJob,
        persist_error: bool,
        cancel_on_progress: bool,
        persist_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl JobQueue for CancelOnStartQueue {
        async fn enqueue(&self, _job: ScanJob) -> Result<String> {
            unreachable!()
        }

        async fn dequeue(&self) -> Result<Option<ScanJob>> {
            Ok(None)
        }

        async fn get_job(&self, _id: &str) -> Result<Option<ScanJob>> {
            Ok(Some(self.job.clone()))
        }

        async fn update_job(&self, _job: &ScanJob) -> Result<()> {
            Ok(())
        }

        async fn update_job_preserving_cancelled(&self, _job: &ScanJob) -> Result<bool> {
            if self.persist_error {
                Err(TlsError::Other("private queue detail".to_string()))
            } else if self.cancel_on_progress {
                Ok(self.persist_calls.fetch_add(1, Ordering::SeqCst) == 0)
            } else {
                Ok(false)
            }
        }

        async fn cancel_job(&self, _id: &str) -> Result<bool> {
            Ok(false)
        }

        async fn queue_length(&self) -> Result<usize> {
            Ok(0)
        }

        async fn list_jobs(&self) -> Result<Vec<ScanJob>> {
            Ok(Vec::new())
        }

        async fn active_jobs_count(&self) -> Result<usize> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn cancellation_winning_start_persist_skips_scan() {
        use tracing::instrument::WithSubscriber;

        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
            job: job.clone(),
            persist_error: false,
            cancel_on_progress: false,
            persist_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue.clone(), 1);
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        executor
            .execute_scan(queue, job)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "scan_job.cancelled_before_start"
                && event["fields"]["outcome"] == "skipped"
        }));
        assert!(!output.contains("scan_job.progress.persist_failed"));
    }

    #[tokio::test]
    async fn cancellation_during_initial_progress_is_logged_before_scan_starts() {
        use tracing::instrument::WithSubscriber;

        let mut job = ScanJob::new("invalid target".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
            job: job.clone(),
            persist_error: false,
            cancel_on_progress: true,
            persist_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue.clone(), 1);
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        executor
            .execute_scan(queue, job)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event["fields"]["event_name"] == "scan_job.cancelled_during_startup"
                && event["fields"]["outcome"] == "cancelled"
        }));
        assert!(!output.contains("scan_job.finished"));
    }

    #[tokio::test]
    async fn start_persistence_failure_stops_before_scanning_and_redacts_error() {
        use tracing::instrument::WithSubscriber;

        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
            job: job.clone(),
            persist_error: true,
            cancel_on_progress: false,
            persist_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue.clone(), 1);
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(CapturedOutput(output.clone()))
            .finish();

        executor
            .execute_scan(queue, job)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event_name"],
            "scan_job.start_persist_failed"
        );
        assert_eq!(event["fields"]["error_code"], "other");
        assert!(!output.contains("private queue detail"));
    }

    #[tokio::test]
    async fn progress_persistence_errors_continue_but_cancellation_stops() {
        use tracing::instrument::WithSubscriber;

        for (persist_error, expected_continue) in [(false, false), (true, true)] {
            let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
            job.mark_queued();
            let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
                job: job.clone(),
                persist_error,
                cancel_on_progress: false,
                persist_calls: AtomicUsize::new(0),
            });
            let executor = ScanExecutor::new(queue.clone(), 1);
            let output = Arc::new(std::sync::Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::ERROR)
                .with_writer(CapturedOutput(output.clone()))
                .finish();

            let should_continue = executor
                .send_progress(queue, &mut job, 25, "diagnostic test")
                .with_subscriber(tracing::Dispatch::new(subscriber))
                .await;

            assert_eq!(should_continue, expected_continue);
            let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
            if persist_error {
                let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
                assert_eq!(
                    event["fields"]["event_name"],
                    "scan_job.progress.persist_failed"
                );
                assert_eq!(event["fields"]["error_code"], "other");
                assert!(!output.contains("private queue detail"));
            } else {
                assert!(output.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn retryable_scan_failure_is_requeued_with_progress_event() {
        let mut job = ScanJob::new(
            "invalid target with spaces".to_string(),
            ScanOptions::full(),
            None,
        );
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job.clone(),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: Some(RetryDisposition::Requeued),
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue.clone(), 1);
        let mut progress = executor.subscribe_progress();

        executor.execute_scan(queue, job).await;

        assert!(
            std::iter::from_fn(|| progress.try_recv().ok())
                .any(|message| message.stage == "retrying")
        );
    }

    #[tokio::test]
    async fn running_progress_is_broadcast_and_persisted_to_the_queue() {
        let job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        let queue: Arc<dyn JobQueue> = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job.clone(),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let (progress_tx, mut progress_rx) = broadcast::channel(1);

        ScanExecutor::report_running_progress(&job, &queue, &progress_tx, 42, "test stage").await;

        let progress = progress_rx.try_recv().unwrap();
        assert_eq!(progress.scan_id, job.id);
        assert_eq!(progress.progress, 42);
        assert_eq!(progress.stage, "test stage");
    }

    #[tokio::test]
    async fn running_progress_persistence_failure_is_logged_safely() {
        use tracing::instrument::WithSubscriber;

        let job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
            job: job.clone(),
            persist_error: true,
            cancel_on_progress: false,
            persist_calls: AtomicUsize::new(0),
        });
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let (progress_tx, mut progress_rx) = broadcast::channel(1);

        ScanExecutor::report_running_progress(&job, &queue, &progress_tx, 42, "test stage")
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let progress = progress_rx.try_recv().unwrap();
        assert_eq!(progress.progress, 42);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event_name"],
            "scan_job.progress.persist_failed"
        );
        assert_eq!(event["fields"]["error_code"], "other");
        assert!(!output.contains("private queue detail"));
    }

    #[test]
    fn executor_optional_configuration_is_available_to_workers() {
        let job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        let queue: Arc<dyn JobQueue> = Arc::new(CancelOnStartQueue {
            job,
            persist_error: false,
            cancel_on_progress: false,
            persist_calls: AtomicUsize::new(0),
        });
        let executor = ScanExecutor::new(queue, 1);
        assert!(!executor.has_webhook_signing_secret());
        assert_eq!(executor.webhook_signing_secret(), None);

        let stats = Arc::new(RwLock::new(ApiStats::default()));
        let allowed_cidrs = vec!["192.0.2.0/24".parse().unwrap()];
        let configured = executor
            .with_stats(stats.clone())
            .with_webhook_signing_secret(Some(b"test secret".to_vec()))
            .with_worker_allowed_cidrs(allowed_cidrs.clone());

        assert!(Arc::ptr_eq(configured.stats.as_ref().unwrap(), &stats));
        assert!(configured.has_webhook_signing_secret());
        assert_eq!(
            configured.webhook_signing_secret(),
            Some(b"test secret".to_vec())
        );
        assert_eq!(configured.worker_allowed_cidrs.as_ref(), &allowed_cidrs);
        assert!(
            !configured
                .clone()
                .with_webhook_signing_secret(None)
                .has_webhook_signing_secret()
        );
    }

    struct GatedJobQueue {
        job: tokio::sync::Mutex<Option<ScanJob>>,
        cancelled_job: ScanJob,
        entered: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        dequeue_error: bool,
        get_job_error: bool,
        cancel_on_get: bool,
        retry_disposition: Option<RetryDisposition>,
        dequeue_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl JobQueue for GatedJobQueue {
        async fn enqueue(&self, job: ScanJob) -> Result<String> {
            let id = job.id.clone();
            *self.job.lock().await = Some(job);
            Ok(id)
        }

        async fn dequeue(&self) -> Result<Option<ScanJob>> {
            self.dequeue_calls.fetch_add(1, Ordering::SeqCst);
            if self.dequeue_error {
                return Err(TlsError::Other("queue unavailable".into()));
            }
            Ok(self.job.lock().await.take())
        }

        async fn get_job(&self, _id: &str) -> Result<Option<ScanJob>> {
            if self.get_job_error {
                return Err(TlsError::Other("password=must-not-appear".into()));
            }
            if let Some(entered) = self.entered.lock().await.take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            let mut job = self.cancelled_job.clone();
            if self.cancel_on_get {
                job.mark_cancelled();
            }
            Ok(Some(job))
        }

        async fn update_job(&self, _job: &ScanJob) -> Result<()> {
            Ok(())
        }

        async fn update_job_preserving_cancelled(&self, _job: &ScanJob) -> Result<bool> {
            Ok(true)
        }

        async fn retry_or_dead_letter(
            &self,
            _job: &ScanJob,
            _error: &str,
            _max_attempts: u32,
        ) -> Result<RetryDisposition> {
            Ok(self
                .retry_disposition
                .unwrap_or(RetryDisposition::DeadLettered))
        }

        async fn cancel_job(&self, _id: &str) -> Result<bool> {
            unreachable!()
        }

        async fn queue_length(&self) -> Result<usize> {
            Ok(0)
        }

        async fn list_jobs(&self) -> Result<Vec<ScanJob>> {
            Ok(Vec::new())
        }

        async fn active_jobs_count(&self) -> Result<usize> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_active_scan_tasks() {
        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let mut cancelled_job = job.clone();
        cancelled_job.mark_cancelled();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(Some(job)),
            cancelled_job,
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = Arc::new(ScanExecutor::new(queue, 1));
        let handle = tokio::spawn(Arc::clone(&executor).start());

        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("scan task should start")
            .expect("entry signal should be sent");
        executor.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            !handle.is_finished(),
            "shutdown must wait for the active task"
        );

        let _ = release_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("executor should stop after the active task finishes")
            .expect("executor task should join")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_before_start_exits_without_dequeuing_jobs() {
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: ScanJob::new("unused.example".to_string(), ScanOptions::full(), None),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = Arc::new(ScanExecutor::new(queue.clone(), 1));

        executor.shutdown().await.unwrap();
        executor.clone().start().await.unwrap();

        assert_eq!(queue.dequeue_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shutdown_while_waiting_for_a_slot_requeues_the_job() {
        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(Some(job.clone())),
            cancelled_job: job,
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = Arc::new(ScanExecutor::new(queue.clone(), 1));
        let permit = Arc::clone(&executor.semaphore)
            .acquire_owned()
            .await
            .expect("semaphore should be open");
        let handle = tokio::spawn(Arc::clone(&executor).start());

        tokio::time::timeout(Duration::from_secs(1), async {
            while queue.dequeue_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor should dequeue the pending job");
        executor.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if queue.job.lock().await.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("job should be returned to the queue");
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("executor should drain after requeue")
            .expect("executor task should join")
            .unwrap();
        drop(permit);

        assert_eq!(queue.dequeue_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn closed_execution_semaphore_requeues_the_dequeued_job() {
        use tracing::instrument::WithSubscriber;

        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(Some(job.clone())),
            cancelled_job: job,
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let executor = Arc::new(ScanExecutor::new(queue.clone(), 1));
        executor.semaphore.close();

        executor
            .clone()
            .start()
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("closed semaphore should stop the executor cleanly");

        assert_eq!(queue.dequeue_calls.load(Ordering::SeqCst), 1);
        assert!(queue.job.lock().await.is_some(), "job should be requeued");
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("scan_job.execution_slot.unavailable"));
        assert!(output.contains("requeue_attempted"));
    }

    struct RecordingResultsStore(AtomicUsize);

    #[async_trait::async_trait]
    impl ScanResultsStore for RecordingResultsStore {
        async fn store_scan(&self, _scan: &PersistedScan) -> Result<i64> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(42)
        }
    }

    #[tokio::test]
    async fn persist_results_is_optional_and_stores_owner_context_when_configured() {
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: ScanJob::new("unused.example".to_string(), ScanOptions::full(), None),
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: false,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::full(), None);
        job.principal_id = "principal-1".to_string();
        job.tenant_id = Some("tenant-1".to_string());
        job.created_by_key_id = "key-1".to_string();
        let results = ScanResults {
            target: job.target.clone(),
            ..Default::default()
        };
        let without_store = ScanExecutor::new(queue.clone(), 1);
        without_store.persist_results(&job, &results).await.unwrap();

        let store = Arc::new(RecordingResultsStore(AtomicUsize::new(0)));
        let with_store = ScanExecutor::new(queue, 1).with_results_store(store.clone());
        with_store.persist_results(&job, &results).await.unwrap();

        assert_eq!(store.0.load(Ordering::SeqCst), 1);
    }

    struct CapturedOutput(Arc<std::sync::Mutex<Vec<u8>>>);

    struct CapturedWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriter(self.0.clone())
        }
    }

    #[tokio::test]
    async fn repeated_dequeue_failures_emit_one_event_per_failure_streak() {
        use tracing::instrument::WithSubscriber;

        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let mut job = ScanJob::new("example.com".to_string(), ScanOptions::full(), None);
        job.mark_queued();
        let queue = Arc::new(GatedJobQueue {
            job: tokio::sync::Mutex::new(None),
            cancelled_job: job,
            entered: tokio::sync::Mutex::new(None),
            release: tokio::sync::Mutex::new(None),
            dequeue_error: true,
            get_job_error: false,
            cancel_on_get: false,
            retry_disposition: None,
            dequeue_calls: AtomicUsize::new(0),
        });
        let executor = Arc::new(ScanExecutor::new(queue.clone(), 1));
        let dispatch = tracing::Dispatch::new(subscriber);
        let handle = tokio::spawn(Arc::clone(&executor).start().with_subscriber(dispatch));

        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(queue.dequeue_calls.load(Ordering::SeqCst) >= 2);
        executor.shutdown().await.unwrap();
        handle.await.unwrap().unwrap();

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert_eq!(
            output.matches("scan_job.dequeue_failed").count(),
            1,
            "{output}"
        );
    }

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

    async fn rejecting_webhook(AxumState(state): AxumState<Arc<WebhookTestState>>) -> StatusCode {
        state.attempts.fetch_add(1, Ordering::SeqCst);
        StatusCode::BAD_REQUEST
    }

    #[tokio::test]
    async fn webhook_is_signed_and_retries_transient_failures() {
        use tracing::instrument::WithSubscriber;

        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
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
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await
        .unwrap();

        assert_eq!(state.attempts.load(Ordering::SeqCst), 3);
        assert!(state.signature_valid.load(Ordering::SeqCst));
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["fields"]["event_name"] == "scan_job.webhook.delivered")
            .expect("delivery event should be recorded");
        assert_eq!(event["fields"]["attempt"], 3);
        assert_eq!(event["fields"]["outcome"], "delivered");
        assert!(event["fields"]["duration_ms"].is_u64());
        assert!(!output.contains("/hook"));
        server.abort();
    }

    #[tokio::test]
    async fn webhook_does_not_retry_permanent_http_failures() {
        let state = Arc::new(WebhookTestState {
            attempts: AtomicUsize::new(0),
            signature_valid: AtomicBool::new(true),
            secret: vec![b's'; 32],
        });
        let app = Router::new()
            .route("/hook", post(rejecting_webhook))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::full(), None);
        job.mark_completed(ScanResults::default());

        let error = ScanExecutor::send_webhook_attempts(
            &reqwest::Client::new(),
            &format!("http://{address}/hook"),
            &job,
            &state.secret,
            3,
            Duration::from_millis(1),
        )
        .await
        .expect_err("permanent response should fail delivery");

        assert!(matches!(error, TlsError::HttpError { status: 400, .. }));
        assert_eq!(state.attempts.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn webhook_retries_transport_failures_and_reports_the_retry() {
        use tracing::instrument::WithSubscriber;

        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::full(), None);
        job.mark_completed(ScanResults::default());

        let result = ScanExecutor::send_webhook_attempts(
            &reqwest::Client::new(),
            &format!("http://{address}/hook"),
            &job,
            &[b's'; 32],
            2,
            Duration::from_millis(1),
        )
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;

        assert!(result.is_err());
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event_name"], "scan_job.webhook.retry");
        assert_eq!(event["fields"]["error_type"], "transport");
        assert_eq!(event["fields"]["attempt"], 1);
        assert!(!output.contains("/hook"));
    }

    #[test]
    fn webhook_failure_event_has_duration_and_redacts_error_details() {
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(CapturedOutput(output.clone()))
            .finish();
        let error = TlsError::HttpError {
            status: 403,
            details: "https://private.example/hook?api_key=secret-value".to_string(),
        };

        tracing::subscriber::with_default(subscriber, || {
            log_scan_job_webhook_failed("job-123", &error, Duration::from_millis(12));
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event_name"], "scan_job.webhook.failed");
        assert_eq!(event["fields"]["error_code"], "http_error");
        assert_eq!(event["fields"]["duration_ms"], 12);
        assert_eq!(event["fields"]["outcome"], "failed");
        assert!(!output.contains("private.example"));
        assert!(!output.contains("secret-value"));
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
