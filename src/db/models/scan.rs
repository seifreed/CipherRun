// Scan Record Model
// Represents a complete scan in the database

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Scan record in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<i64>,
    pub target_hostname: String,
    pub target_port: i32,
    pub scan_timestamp: DateTime<Utc>,
    pub overall_grade: Option<String>,
    pub overall_score: Option<i32>,
    pub scan_duration_ms: Option<i32>,
    pub scanner_version: Option<String>,
}

impl ScanRecord {
    /// Create new scan record
    pub fn new(hostname: String, port: u16) -> Self {
        Self {
            scan_id: None,
            target_hostname: hostname,
            target_port: port as i32,
            scan_timestamp: Utc::now(),
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: None,
            scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }
    }

    /// Set rating
    pub fn with_rating(mut self, grade: String, score: u8) -> Self {
        self.overall_grade = Some(grade);
        self.overall_score = Some(score as i32);
        self
    }

    /// Set scan duration
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.scan_duration_ms = Some(duration_ms as i32);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_record_creation() {
        let scan = ScanRecord::new("example.com".to_string(), 443);
        assert_eq!(scan.target_hostname, "example.com");
        assert_eq!(scan.target_port, 443);
        assert!(scan.scan_id.is_none());
    }

    #[test]
    fn test_scan_record_with_rating() {
        let scan = ScanRecord::new("example.com".to_string(), 443)
            .with_rating("A".to_string(), 90);

        assert_eq!(scan.overall_grade, Some("A".to_string()));
        assert_eq!(scan.overall_score, Some(90));
    }
}
