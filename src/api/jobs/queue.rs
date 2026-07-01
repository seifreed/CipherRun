// Job Queue Implementation

use crate::api::models::{request::ScanOptions, response::ScanStatus};
use crate::scanner::ScanResults;
use crate::{Result, tls_bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Scan job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    /// Unique job ID
    pub id: String,

    /// Target to scan
    pub target: String,

    /// Scan options
    pub options: ScanOptions,

    /// Current status
    pub status: ScanStatus,

    /// Progress percentage (0-100)
    pub progress: u8,

    /// Current stage
    pub current_stage: Option<String>,

    /// When job was queued
    pub queued_at: DateTime<Utc>,

    /// When job started
    pub started_at: Option<DateTime<Utc>>,

    /// When job completed
    pub completed_at: Option<DateTime<Utc>>,

    /// Scan results (if completed)
    pub results: Option<ScanResults>,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Webhook URL to call on completion
    pub webhook_url: Option<String>,

    /// Estimated completion time
    pub estimated_completion: Option<DateTime<Utc>>,

    /// ETA in seconds
    pub eta_seconds: Option<u64>,
}

impl ScanJob {
    /// Create new scan job
    pub fn new(target: String, options: ScanOptions, webhook_url: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target,
            options,
            status: ScanStatus::Queued,
            progress: 0,
            current_stage: None,
            queued_at: Utc::now(),
            started_at: None,
            completed_at: None,
            results: None,
            error: None,
            webhook_url,
            estimated_completion: None,
            eta_seconds: None,
        }
    }

    /// Update progress
    pub fn update_progress(&mut self, progress: u8, stage: String) {
        if progress > 100 {
            tracing::warn!("Ignoring out-of-range job progress: {}", progress);
            return;
        }

        self.progress = progress;
        self.current_stage = Some(stage);
        self.eta_seconds = None;
        self.estimated_completion = None;

        // Estimate completion time based on progress
        if let Some(started) = self.started_at
            && progress > 0
        {
            let elapsed_signed = (Utc::now() - started).num_seconds();

            // Guard against clock skew (started_at in the future)
            if elapsed_signed < 0 {
                tracing::warn!("Job started_at is in the future, skipping ETA calculation");
                return;
            }

            let elapsed = u64::try_from(elapsed_signed).unwrap_or_default();

            // Use checked arithmetic to prevent overflow
            // elapsed * 100 could overflow for very large values (unreachable in practice)
            let total_estimated = match elapsed
                .checked_mul(100)
                .and_then(|e| e.checked_div(progress as u64))
            {
                Some(val) => val,
                None => {
                    // Overflow would only occur with elapsed > 584 years, but handle gracefully
                    tracing::debug!("ETA calculation overflow, skipping");
                    return;
                }
            };

            let remaining = total_estimated.saturating_sub(elapsed);
            let Ok(remaining_seconds) = i64::try_from(remaining) else {
                tracing::debug!("ETA calculation exceeds chrono range, skipping");
                return;
            };
            let Some(remaining_duration) = chrono::Duration::try_seconds(remaining_seconds) else {
                tracing::debug!("ETA calculation exceeds chrono range, skipping");
                return;
            };
            let Some(estimated_completion) = Utc::now().checked_add_signed(remaining_duration)
            else {
                tracing::debug!("ETA completion time exceeds chrono range, skipping");
                return;
            };

            self.eta_seconds = Some(remaining);
            self.estimated_completion = Some(estimated_completion);
        }
    }

    /// Mark as started
    pub fn mark_started(&mut self) {
        self.status = ScanStatus::Running;
        self.started_at = Some(Utc::now());
        self.progress = 0;
    }

    /// Reset to queued, e.g. when a claimed job is returned to the queue
    /// because it could not be dispatched (executor shutting down).
    pub fn mark_queued(&mut self) {
        self.status = ScanStatus::Queued;
        self.started_at = None;
        self.progress = 0;
    }

    /// Mark as completed
    pub fn mark_completed(&mut self, results: ScanResults) {
        self.status = ScanStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.progress = 100;
        self.current_stage = Some("completed".to_string());
        self.results = Some(results);
        self.eta_seconds = None;
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = ScanStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.current_stage = Some("failed".to_string());
        self.error = Some(error.into());
        self.eta_seconds = None;
    }

    /// Mark as cancelled
    pub fn mark_cancelled(&mut self) {
        self.status = ScanStatus::Cancelled;
        self.completed_at = Some(Utc::now());
        self.eta_seconds = None;
    }
}

/// Job queue trait
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Enqueue a new job
    async fn enqueue(&self, job: ScanJob) -> Result<String>;

    /// Dequeue next job
    async fn dequeue(&self) -> Result<Option<ScanJob>>;

    /// Get job by ID
    async fn get_job(&self, id: &str) -> Result<Option<ScanJob>>;

    /// Update job
    async fn update_job(&self, job: &ScanJob) -> Result<()>;

    /// Update job only if it hasn't been cancelled.
    /// This prevents race conditions where a job completes and a cancellation
    /// request arrives simultaneously, and the completion would overwrite the
    /// cancelled status.
    /// Returns Ok(true) if the job was updated, Ok(false) if it was cancelled.
    async fn update_job_preserving_cancelled(&self, job: &ScanJob) -> Result<bool>;

    /// Cancel job
    async fn cancel_job(&self, id: &str) -> Result<bool>;

    /// Get queue length
    async fn queue_length(&self) -> Result<usize>;

    /// Get all jobs (for monitoring)
    async fn list_jobs(&self) -> Result<Vec<ScanJob>>;

    /// Get active jobs count
    async fn active_jobs_count(&self) -> Result<usize>;
}

/// In-memory job queue implementation
pub struct InMemoryJobQueue {
    queue: Arc<RwLock<VecDeque<ScanJob>>>,
    jobs: Arc<RwLock<HashMap<String, ScanJob>>>,
    max_capacity: usize,
}

impl InMemoryJobQueue {
    /// Create new in-memory job queue
    pub fn new(max_capacity: usize) -> Self {
        Self {
            queue: Arc::new(RwLock::new(VecDeque::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            max_capacity,
        }
    }
}

impl InMemoryJobQueue {
    fn is_terminal(status: ScanStatus) -> bool {
        matches!(
            status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        )
    }

    /// Evict the oldest terminal (Completed/Failed/Cancelled) jobs so the job
    /// history map cannot grow without bound over the lifetime of the server.
    ///
    /// Active (Queued/Running) jobs are never evicted. Recent terminal jobs are
    /// retained up to `max_capacity` so a client can still poll a finished job's
    /// result shortly after completion; only the oldest beyond that cap are
    /// dropped. The caller must already hold the `jobs` write lock.
    fn prune_terminal_jobs(&self, jobs: &mut HashMap<String, ScanJob>) {
        let terminal_count = jobs
            .values()
            .filter(|j| Self::is_terminal(j.status))
            .count();
        if terminal_count <= self.max_capacity {
            return;
        }

        let mut terminal: Vec<(String, DateTime<Utc>)> = jobs
            .values()
            .filter(|j| Self::is_terminal(j.status))
            .map(|j| (j.id.clone(), j.completed_at.unwrap_or(j.queued_at)))
            .collect();
        terminal.sort_by_key(|(_, completed_at)| *completed_at); // oldest first

        let to_remove = terminal_count - self.max_capacity;
        for (id, _) in terminal.into_iter().take(to_remove) {
            jobs.remove(&id);
        }
    }
}

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn enqueue(&self, job: ScanJob) -> Result<String> {
        let mut queue = self.queue.write().await;
        let mut jobs = self.jobs.write().await;

        let active_jobs = jobs
            .values()
            .filter(|job| matches!(job.status, ScanStatus::Queued | ScanStatus::Running))
            .count();
        if active_jobs >= self.max_capacity {
            tls_bail!("Job queue is full");
        }

        let job_id = job.id.clone();
        if jobs.contains_key(&job_id) {
            tls_bail!("Job already exists: {}", job_id);
        }
        queue.push_back(job.clone());
        jobs.insert(job_id.clone(), job);

        Ok(job_id)
    }

    async fn dequeue(&self) -> Result<Option<ScanJob>> {
        let mut queue = self.queue.write().await;
        // Acquire jobs lock once to avoid repeated lock/unlock per iteration
        let mut jobs = self.jobs.write().await;

        while let Some(job) = queue.pop_front() {
            match jobs.get(&job.id).map(|j| j.status) {
                Some(ScanStatus::Queued) => {
                    // Claim the job by transitioning it to Running in the same
                    // lock scope that removed it from the queue. Otherwise the
                    // job is gone from the queue yet still recorded as Queued
                    // until the executor marks it started after awaiting a
                    // concurrency permit, leaving it counted by neither
                    // queue_length nor active_jobs_count during that window.
                    if let Some(entry) = jobs.get_mut(&job.id) {
                        entry.mark_started();
                    }
                    let current_job = jobs.get(&job.id).cloned().unwrap_or(job);
                    return Ok(Some(current_job));
                }
                Some(_) => {
                    // Job was cancelled or completed - skip it
                    continue;
                }
                None => {
                    // Job not found in HashMap - skip it (shouldn't happen)
                    continue;
                }
            }
        }

        Ok(None)
    }

    async fn get_job(&self, id: &str) -> Result<Option<ScanJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(id).cloned())
    }

    async fn update_job(&self, job: &ScanJob) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        jobs.insert(job.id.clone(), job.clone());
        self.prune_terminal_jobs(&mut jobs);
        Ok(())
    }

    async fn update_job_preserving_cancelled(&self, job: &ScanJob) -> Result<bool> {
        let mut jobs = self.jobs.write().await;
        if let Some(current) = jobs.get(&job.id) {
            // Only update if not cancelled - prevent race condition where
            // completion overwrites cancellation
            if matches!(current.status, ScanStatus::Cancelled) {
                tracing::info!(
                    "Job {} was cancelled while processing, preserving cancelled status",
                    job.id
                );
                return Ok(false);
            }
        }
        jobs.insert(job.id.clone(), job.clone());
        self.prune_terminal_jobs(&mut jobs);
        Ok(true)
    }

    async fn cancel_job(&self, id: &str) -> Result<bool> {
        let mut queue = self.queue.write().await;
        let mut jobs = self.jobs.write().await;

        if let Some(job) = jobs.get_mut(id) {
            // Only cancel if not already completed/failed
            if matches!(job.status, ScanStatus::Queued | ScanStatus::Running) {
                job.mark_cancelled();
                queue.retain(|queued| queued.id != id);
                self.prune_terminal_jobs(&mut jobs);
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn queue_length(&self) -> Result<usize> {
        let queue = self.queue.read().await;
        Ok(queue.len())
    }

    async fn list_jobs(&self) -> Result<Vec<ScanJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.values().cloned().collect())
    }

    async fn active_jobs_count(&self) -> Result<usize> {
        let jobs = self.jobs.read().await;
        let count = jobs
            .values()
            .filter(|j| matches!(j.status, ScanStatus::Running))
            .count();
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enqueue_dequeue() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

        let job_id = queue
            .enqueue(job.clone())
            .await
            .expect("test assertion should succeed");
        assert_eq!(job_id, job.id);

        let dequeued = queue
            .dequeue()
            .await
            .unwrap()
            .expect("test assertion should succeed");
        assert_eq!(dequeued.id, job.id);
        // dequeue claims the job, so it is reported as Running, not Queued.
        assert_eq!(dequeued.status, ScanStatus::Running);
    }

    #[tokio::test]
    async fn test_terminal_job_history_is_bounded_and_keeps_active_jobs() {
        let cap = 2;
        let queue = InMemoryJobQueue::new(cap);

        // An active (Running) job must survive any amount of terminal-job churn.
        let mut active = ScanJob::new("active:443".to_string(), ScanOptions::default(), None);
        active.mark_started();
        queue
            .update_job(&active)
            .await
            .expect("test assertion should succeed");

        // Flood the history with terminal jobs well beyond capacity.
        for i in 0..(cap + 6) {
            let mut job = ScanJob::new(format!("done{i}:443"), ScanOptions::default(), None);
            job.mark_completed(ScanResults::default());
            queue
                .update_job(&job)
                .await
                .expect("test assertion should succeed");
        }

        let all = queue
            .list_jobs()
            .await
            .expect("test assertion should succeed");
        let terminal = all
            .iter()
            .filter(|j| {
                matches!(
                    j.status,
                    ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
                )
            })
            .count();
        assert!(
            terminal <= cap,
            "terminal job history must be bounded by capacity, found {terminal}"
        );
        assert!(
            queue
                .get_job(&active.id)
                .await
                .expect("test assertion should succeed")
                .is_some(),
            "active jobs must never be evicted"
        );
    }

    #[tokio::test]
    async fn test_dequeue_keeps_job_counted_as_active() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        queue
            .enqueue(job)
            .await
            .expect("test assertion should succeed");

        assert_eq!(queue.queue_length().await.unwrap(), 1);
        assert_eq!(queue.active_jobs_count().await.unwrap(), 0);

        queue
            .dequeue()
            .await
            .unwrap()
            .expect("test assertion should succeed");

        // Once claimed, the job leaves the queue and is counted as active,
        // never falling through both counters.
        assert_eq!(queue.queue_length().await.unwrap(), 0);
        assert_eq!(queue.active_jobs_count().await.unwrap(), 1);
    }

    #[test]
    fn test_update_progress_rejects_out_of_range_progress() {
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.update_progress(50, "halfway".to_string());

        job.update_progress(101, "invalid".to_string());

        assert_eq!(job.progress, 50);
        assert_eq!(job.current_stage.as_deref(), Some("halfway"));
    }

    #[test]
    fn test_update_progress_skips_eta_beyond_datetime_range() {
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.started_at = Some(DateTime::<Utc>::MIN_UTC);

        job.update_progress(1, "ancient".to_string());

        assert_eq!(job.progress, 1);
        assert_eq!(job.current_stage.as_deref(), Some("ancient"));
        assert!(job.eta_seconds.is_none());
        assert!(job.estimated_completion.is_none());
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let queue = InMemoryJobQueue::new(2);

        let job1 = ScanJob::new("example1.com:443".to_string(), ScanOptions::default(), None);
        let job2 = ScanJob::new("example2.com:443".to_string(), ScanOptions::default(), None);
        let job3 = ScanJob::new("example3.com:443".to_string(), ScanOptions::default(), None);

        queue
            .enqueue(job1)
            .await
            .expect("test assertion should succeed");
        queue
            .enqueue(job2)
            .await
            .expect("test assertion should succeed");
        assert!(queue.enqueue(job3).await.is_err());
    }

    #[tokio::test]
    async fn test_enqueue_rejects_duplicate_job_id() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let mut duplicate = ScanJob::new(
            "other.example:443".to_string(),
            ScanOptions::default(),
            None,
        );
        duplicate.id = job.id.clone();

        queue
            .enqueue(job.clone())
            .await
            .expect("initial enqueue should succeed");
        let err = queue
            .enqueue(duplicate)
            .await
            .expect_err("duplicate job id should fail");

        assert!(err.to_string().contains("already exists"));
        assert_eq!(queue.queue_length().await.unwrap(), 1);
        let queued = queue
            .dequeue()
            .await
            .expect("dequeue should succeed")
            .expect("original job should still be queued");
        assert_eq!(queued.target, job.target);
    }

    #[tokio::test]
    async fn test_queue_capacity_counts_running_jobs() {
        let queue = InMemoryJobQueue::new(1);

        let job1 = ScanJob::new("example1.com:443".to_string(), ScanOptions::default(), None);
        let job2 = ScanJob::new("example2.com:443".to_string(), ScanOptions::default(), None);

        queue
            .enqueue(job1)
            .await
            .expect("test assertion should succeed");
        queue
            .dequeue()
            .await
            .expect("dequeue should succeed")
            .expect("job should exist");

        assert!(
            queue.enqueue(job2).await.is_err(),
            "running jobs must count against queue capacity"
        );
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let job_id = queue
            .enqueue(job)
            .await
            .expect("test assertion should succeed");

        let cancelled = queue
            .cancel_job(&job_id)
            .await
            .expect("test assertion should succeed");
        assert!(cancelled);

        let job = queue
            .get_job(&job_id)
            .await
            .unwrap()
            .expect("test assertion should succeed");
        assert_eq!(job.status, ScanStatus::Cancelled);
        assert_eq!(queue.queue_length().await.unwrap(), 0);
    }
}
