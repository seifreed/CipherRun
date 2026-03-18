use crate::api::models::response::{ApiUsageStats, DomainStats, StatsResponse};

pub fn present_stats_response(
    total_scans: u64,
    completed_scans: u64,
    failed_scans: u64,
    avg_scan_duration_seconds: f64,
    scans_last_24h: u64,
    scans_last_7d: u64,
    top_domains: Vec<DomainStats>,
    api_usage: ApiUsageStats,
) -> StatsResponse {
    StatsResponse {
        total_scans,
        completed_scans,
        failed_scans,
        avg_scan_duration_seconds,
        scans_last_24h,
        scans_last_7d,
        top_domains,
        api_usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn preserves_stats_values() {
        let response = present_stats_response(
            10,
            8,
            2,
            1.5,
            3,
            7,
            vec![DomainStats {
                domain: "example.com".to_string(),
                scan_count: 5,
                last_scan: Utc::now(),
            }],
            ApiUsageStats {
                requests_last_hour: 11,
                requests_last_day: 22,
                avg_response_time_ms: 33.0,
            },
        );

        assert_eq!(response.total_scans, 10);
        assert_eq!(response.top_domains.len(), 1);
        assert_eq!(response.api_usage.requests_last_hour, 11);
    }
}
