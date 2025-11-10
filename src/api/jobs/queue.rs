// Job Queue Implementation

use crate::api::models::{response::ScanStatus, request::ScanOptions};
use crate::scanner::ScanResults;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
        self.progress = progress;
        self.current_stage = Some(stage);

        // Estimate completion time based on progress
        if let Some(started) = self.started_at
            && progress > 0 {
                let elapsed = (Utc::now() - started).num_seconds() as u64;
                let total_estimated = (elapsed * 100) / progress as u64;
                let remaining = total_estimated.saturating_sub(elapsed);
                self.eta_seconds = Some(remaining);
                self.estimated_completion = Some(Utc::now() + chrono::Duration::seconds(remaining as i64));
            }
    }

    /// Mark as started
    pub fn mark_started(&mut self) {
        self.status = ScanStatus::Running;
        self.started_at = Some(Utc::now());
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

    /// Mark as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = ScanStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
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

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn enqueue(&self, job: ScanJob) -> Result<String> {
        let mut queue = self.queue.write().await;
        let mut jobs = self.jobs.write().await;

        if queue.len() >= self.max_capacity {
            anyhow::bail!("Job queue is full");
        }

        let job_id = job.id.clone();
        queue.push_back(job.clone());
        jobs.insert(job_id.clone(), job);

        Ok(job_id)
    }

    async fn dequeue(&self) -> Result<Option<ScanJob>> {
        let mut queue = self.queue.write().await;
        Ok(queue.pop_front())
    }

    async fn get_job(&self, id: &str) -> Result<Option<ScanJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(id).cloned())
    }

    async fn update_job(&self, job: &ScanJob) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn cancel_job(&self, id: &str) -> Result<bool> {
        let mut jobs = self.jobs.write().await;

        if let Some(mut job) = jobs.get(id).cloned() {
            // Only cancel if not already completed/failed
            if matches!(job.status, ScanStatus::Queued | ScanStatus::Running) {
                job.mark_cancelled();
                jobs.insert(id.to_string(), job);
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

        let job_id = queue.enqueue(job.clone()).await.unwrap();
        assert_eq!(job_id, job.id);

        let dequeued = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(dequeued.id, job.id);
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let queue = InMemoryJobQueue::new(2);

        let job1 = ScanJob::new("example1.com:443".to_string(), ScanOptions::default(), None);
        let job2 = ScanJob::new("example2.com:443".to_string(), ScanOptions::default(), None);
        let job3 = ScanJob::new("example3.com:443".to_string(), ScanOptions::default(), None);

        queue.enqueue(job1).await.unwrap();
        queue.enqueue(job2).await.unwrap();
        assert!(queue.enqueue(job3).await.is_err());
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let job_id = queue.enqueue(job).await.unwrap();

        let cancelled = queue.cancel_job(&job_id).await.unwrap();
        assert!(cancelled);

        let job = queue.get_job(&job_id).await.unwrap().unwrap();
        assert_eq!(job.status, ScanStatus::Cancelled);
    }
}
