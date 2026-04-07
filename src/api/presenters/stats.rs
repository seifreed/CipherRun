use crate::api::models::response::{ApiUsageStats, DomainStats, StatsResponse};

/// Grouped parameters for building a stats response.
#[derive(Debug, Clone)]
pub struct StatsParams {
    pub total_scans: u64,
    pub completed_scans: u64,
    pub failed_scans: u64,
    pub avg_scan_duration_seconds: f64,
    pub scans_last_24h: u64,
    pub scans_last_7d: u64,
    pub top_domains: Vec<DomainStats>,
    pub api_usage: ApiUsageStats,
}

pub fn present_stats_response(params: StatsParams) -> StatsResponse {
    StatsResponse {
        total_scans: params.total_scans,
        completed_scans: params.completed_scans,
        failed_scans: params.failed_scans,
        avg_scan_duration_seconds: params.avg_scan_duration_seconds,
        scans_last_24h: params.scans_last_24h,
        scans_last_7d: params.scans_last_7d,
        top_domains: params.top_domains,
        api_usage: params.api_usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn preserves_stats_values() {
        let response = present_stats_response(StatsParams {
            total_scans: 10,
            completed_scans: 8,
            failed_scans: 2,
            avg_scan_duration_seconds: 1.5,
            scans_last_24h: 3,
            scans_last_7d: 7,
            top_domains: vec![DomainStats {
                domain: "example.com".to_string(),
                scan_count: 5,
                last_scan: Utc::now(),
            }],
            api_usage: ApiUsageStats {
                requests_last_hour: 11,
                requests_last_day: 22,
                avg_response_time_ms: 33.0,
            },
        });

        assert_eq!(response.total_scans, 10);
        assert_eq!(response.top_domains.len(), 1);
        assert_eq!(response.api_usage.requests_last_hour, 11);
    }
}
