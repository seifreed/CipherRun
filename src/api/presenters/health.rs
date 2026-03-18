use crate::api::models::response::HealthResponse;

pub fn present_health_response(
    version: String,
    uptime_seconds: u64,
    active_scans: usize,
    queued_scans: usize,
    database: Option<String>,
) -> HealthResponse {
    HealthResponse {
        status: "healthy".to_string(),
        version,
        uptime_seconds,
        active_scans,
        queued_scans,
        database,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_healthy_response() {
        let response =
            present_health_response("1.0.0".to_string(), 42, 1, 2, Some("connected".to_string()));
        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, "1.0.0");
        assert_eq!(response.active_scans, 1);
        assert_eq!(response.queued_scans, 2);
        assert_eq!(response.database.as_deref(), Some("connected"));
    }
}
