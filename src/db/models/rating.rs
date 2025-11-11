// Rating Record Model
// Represents SSL Labs-style rating components for a scan

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Rating record in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RatingRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating_id: Option<i64>,
    pub scan_id: i64,
    pub category: String, // "protocol", "key_exchange", "cipher", "certificate"
    pub score: i32,       // 0-100
    pub grade: Option<String>, // "A+", "A", "B", etc.
    pub rationale: Option<String>,
}

impl RatingRecord {
    /// Create new rating record
    pub fn new(scan_id: i64, category: String, score: u8) -> Self {
        Self {
            rating_id: None,
            scan_id,
            category,
            score: score as i32,
            grade: None,
            rationale: None,
        }
    }

    /// Set grade
    pub fn with_grade(mut self, grade: String) -> Self {
        self.grade = Some(grade);
        self
    }

    /// Set rationale
    pub fn with_rationale(mut self, rationale: String) -> Self {
        self.rationale = Some(rationale);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rating_record_creation() {
        let rating = RatingRecord::new(1, "certificate".to_string(), 90)
            .with_grade("A".to_string())
            .with_rationale("Strong certificate".to_string());

        assert_eq!(rating.scan_id, 1);
        assert_eq!(rating.category, "certificate");
        assert_eq!(rating.score, 90);
        assert_eq!(rating.grade, Some("A".to_string()));
    }
}
