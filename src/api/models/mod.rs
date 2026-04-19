// API Models Module

pub mod error;
pub mod request;
pub mod response;

pub use error::{ApiError, ApiErrorResponse};
pub use request::{PolicyRequest, ScanOptions, ScanRequest};
pub use response::{HealthResponse, ScanResponse, ScanStatusResponse, StatsResponse};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_models_reexports_basic() {
        let req = ScanRequest {
            target: "example.com:443".to_string(),
            options: Some(ScanOptions::quick()),
            webhook_url: None,
        };

        assert_eq!(req.target, "example.com:443");

        let err = ApiErrorResponse::internal("oops");
        assert_eq!(err.status, 500);
        assert_eq!(err.error, "INTERNAL_ERROR");
    }

    #[test]
    fn test_policy_request_reexport() {
        let req = PolicyRequest {
            name: "policy".to_string(),
            description: None,
            rules: "rules".to_string(),
            enabled: true,
        };
        assert_eq!(req.name, "policy");
        assert!(req.enabled);
    }

    #[test]
    fn test_stats_response_reexport() {
        let resp = StatsResponse {
            total_scans: 1,
            completed_scans: 1,
            failed_scans: 0,
            avg_scan_duration_seconds: 1.0,
            scans_last_24h: 1,
            scans_last_7d: 1,
            top_domains: Vec::new(),
            api_usage: response::ApiUsageStats {
                requests_last_hour: 1,
                requests_last_day: 2,
                avg_response_time_ms: 10.0,
            },
        };

        assert_eq!(resp.total_scans, 1);
        assert_eq!(resp.api_usage.requests_last_hour, 1);
    }
}
