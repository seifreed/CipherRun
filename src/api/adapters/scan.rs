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
        jobs::{InMemoryJobQueue, ScanJob},
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
}
