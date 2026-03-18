#[tokio::test]
async fn test_job_queue_operations() {
    use cipherrun::api::jobs::{InMemoryJobQueue, JobQueue, ScanJob};
    use cipherrun::api::models::request::ScanOptions;

    let queue = InMemoryJobQueue::new(10);
    let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

    let job_id = queue.enqueue(job.clone()).await.unwrap();
    assert_eq!(job_id, job.id);

    let retrieved = queue.get_job(&job_id).await.unwrap().unwrap();
    assert_eq!(retrieved.target, "example.com:443");
}
