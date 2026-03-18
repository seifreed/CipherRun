// Background Jobs Module

pub mod executor;
pub mod queue;
pub mod storage;

pub use executor::ScanExecutor;
pub use queue::{InMemoryJobQueue, JobQueue, ScanJob};
pub use storage::JobStorage;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_job_queue_basic_flow() {
        let queue = InMemoryJobQueue::new(10);
        let job = ScanJob::new("example.com:443".to_string(), Default::default(), None);

        let job_id = queue
            .enqueue(job.clone())
            .await
            .expect("enqueue should succeed");
        let fetched = queue
            .get_job(&job_id)
            .await
            .expect("get_job should succeed");

        assert!(fetched.is_some());
        let fetched = fetched.expect("job exists");
        assert_eq!(fetched.id, job_id);

        let dequeued = queue.dequeue().await.expect("dequeue should succeed");
        assert!(dequeued.is_some());
    }
}
