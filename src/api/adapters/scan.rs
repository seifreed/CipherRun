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
