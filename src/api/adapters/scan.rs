use crate::api::jobs::{JobQueue, ScanJob};
use crate::api::models::error::ApiError;

/// Enqueue a scan job, mapping errors to ApiError.
pub async fn enqueue_scan(queue: &dyn JobQueue, job: ScanJob) -> Result<String, ApiError> {
    queue.enqueue(job).await.map_err(|error| match error {
        crate::TlsError::InvalidInput { message } => ApiError::Conflict(message),
        other => ApiError::service_unavailable_with_diagnostic(
            "enqueue_scan",
            other.observability_code(),
        ),
    })
}

/// Retrieve a scan job by ID, mapping errors to ApiError.
pub async fn get_scan(queue: &dyn JobQueue, id: &str) -> Result<ScanJob, ApiError> {
    queue
        .get_job(id)
        .await
        .map_err(|error| {
            ApiError::internal_with_diagnostic("get_scan_job", error.observability_code())
        })?
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))
}

#[cfg(test)]
mod tests {
    use super::enqueue_scan;
    use crate::api::{
        jobs::{InMemoryJobQueue, JobQueue, ScanJob},
        models::{error::ApiError, request::ScanOptions},
    };

    #[tokio::test]
    async fn enqueue_backend_failure_maps_to_service_unavailable() {
        let queue = InMemoryJobQueue::new(0);
        let job = ScanJob::new("example.com".to_string(), ScanOptions::default(), None);

        let error = enqueue_scan(&queue, job)
            .await
            .expect_err("full queue should fail");

        assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    }

    #[tokio::test]
    async fn enqueue_idempotency_conflict_maps_to_conflict() {
        let queue = InMemoryJobQueue::new(2);
        let mut original = ScanJob::new("example.com".to_string(), ScanOptions::default(), None);
        original.idempotency_key = Some("request-1".to_string());
        original.request_fingerprint = Some("fingerprint-1".to_string());
        queue.enqueue(original).await.expect("first enqueue succeeds");

        let mut conflicting =
            ScanJob::new("example.org".to_string(), ScanOptions::default(), None);
        conflicting.idempotency_key = Some("request-1".to_string());
        conflicting.request_fingerprint = Some("fingerprint-2".to_string());

        let error = enqueue_scan(&queue, conflicting)
            .await
            .expect_err("reusing the key with another request conflicts");

        assert!(matches!(error, ApiError::Conflict(_)));
    }
}
