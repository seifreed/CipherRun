use crate::api::models::response::HealthResponse;

pub fn present_health_response(
    status: String,
    version: String,
    uptime_seconds: u64,
    active_scans: Option<usize>,
    queued_scans: Option<usize>,
    database: Option<String>,
    queue: Option<String>,
) -> HealthResponse {
    HealthResponse {
        status,
        version,
        uptime_seconds,
        active_scans,
        queued_scans,
        database,
        queue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_healthy_response() {
        let response = present_health_response(
            "healthy".to_string(),
            "1.0.0".to_string(),
            42,
            Some(1),
            Some(2),
            Some("connected".to_string()),
            Some("connected".to_string()),
        );
        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, "1.0.0");
        assert_eq!(response.active_scans, Some(1));
        assert_eq!(response.queued_scans, Some(2));
        assert_eq!(response.database.as_deref(), Some("connected"));
        assert_eq!(response.queue.as_deref(), Some("connected"));
    }
}
