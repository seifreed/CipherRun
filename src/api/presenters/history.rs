use crate::api::models::response::{ScanHistoryItem, ScanHistoryResponse};
use crate::application::ScanHistoryPage;

pub fn present_scan_history(
    domain: String,
    port: u16,
    page: ScanHistoryPage,
) -> ScanHistoryResponse {
    let scans = page
        .scans
        .into_iter()
        .map(|scan| ScanHistoryItem {
            scan_id: scan.scan_id,
            timestamp: scan.timestamp,
            grade: scan.grade,
            score: scan.score,
            duration_ms: scan.duration_ms,
        })
        .collect();

    ScanHistoryResponse {
        domain,
        port,
        total_scans: page.total_scans,
        scans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn present_scan_history_sets_total_from_items() {
        let response = present_scan_history(
            "example.com".to_string(),
            443,
            ScanHistoryPage {
                total_scans: 7,
                scans: vec![crate::application::ScanHistoryEntry {
                    scan_id: 1,
                    timestamp: Utc::now(),
                    grade: Some("A".to_string()),
                    score: Some(95),
                    duration_ms: Some(1000),
                }],
            },
        );

        assert_eq!(response.domain, "example.com");
        assert_eq!(response.port, 443);
        assert_eq!(response.total_scans, 7);
        assert_eq!(response.scans.len(), 1);
    }
}
