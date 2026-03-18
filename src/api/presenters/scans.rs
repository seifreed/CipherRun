use crate::api::{
    jobs::ScanJob,
    models::response::{ScanResponse, ScanStatus, ScanStatusResponse},
};

pub fn present_queued_scan(job: &ScanJob, target: String) -> ScanResponse {
    ScanResponse {
        scan_id: job.id.clone(),
        status: ScanStatus::Queued,
        target,
        websocket_url: Some(format!("/api/v1/scan/{}/stream", job.id)),
        queued_at: job.queued_at,
        estimated_completion: None,
    }
}

pub fn present_scan_status(job: ScanJob) -> ScanStatusResponse {
    let results_url = matches!(job.status, ScanStatus::Completed)
        .then(|| format!("/api/v1/scan/{}/results", job.id));

    ScanStatusResponse {
        scan_id: job.id,
        status: job.status,
        progress: job.progress,
        current_stage: job.current_stage,
        eta_seconds: job.eta_seconds,
        started_at: job.started_at,
        completed_at: job.completed_at,
        error: job.error,
        results_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::jobs::ScanJob;
    use crate::api::models::request::ScanOptions;

    #[test]
    fn present_queued_scan_includes_websocket_url() {
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

        let response = present_queued_scan(&job, "example.com:443".to_string());

        assert_eq!(response.scan_id, job.id);
        assert_eq!(response.target, "example.com:443");
        assert_eq!(
            response.websocket_url.as_deref(),
            Some(format!("/api/v1/scan/{}/stream", job.id).as_str())
        );
    }

    #[test]
    fn present_scan_status_only_includes_results_url_when_completed() {
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Running;
        job.progress = 42;
        let running = present_scan_status(job.clone());
        assert!(running.results_url.is_none());
        assert_eq!(running.progress, 42);

        job.status = ScanStatus::Completed;
        let completed = present_scan_status(job.clone());
        assert_eq!(
            completed.results_url.as_deref(),
            Some(format!("/api/v1/scan/{}/results", job.id).as_str())
        );
        assert_eq!(completed.progress, 42);
    }
}
