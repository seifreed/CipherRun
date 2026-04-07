// Rating Trend Analysis
// Analyzes security rating scores over time

use super::trend_analyzer::TrendAnalyzer;
use crate::db::ScanRecord;
use chrono::{Duration, Utc};

impl TrendAnalyzer {
    /// Analyze rating trend over time
    pub async fn analyze_rating_trend(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<super::trend_analyzer::RatingTrend> {
        let scans = self.db().get_scan_history(hostname, port, 100).await?;

        let cutoff = Utc::now() - Duration::days(days);
        let filtered_scans: Vec<&ScanRecord> = scans
            .iter()
            .filter(|s| s.scan_timestamp >= cutoff)
            .collect();

        if filtered_scans.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No scans found in the specified time range".to_string(),
            ));
        }

        let mut data_points = Vec::new();
        let mut scores = Vec::new();

        for scan in &filtered_scans {
            if let Some(score) = scan.overall_score {
                let score_u8 = score.clamp(0, 100) as u8;
                data_points.push((scan.scan_timestamp, score_u8));
                scores.push(score_u8);
            }
        }

        if scores.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No rating scores found".to_string(),
            ));
        }

        let mean = Self::calculate_mean(&scores);
        let median = Self::calculate_median(&mut scores.clone());
        let std_dev = Self::calculate_std_dev(&scores, mean);
        let direction = Self::determine_trend_direction(&data_points);
        let forecast = Self::forecast_linear(&data_points);

        Ok(super::trend_analyzer::RatingTrend {
            data_points,
            mean,
            median,
            std_dev,
            direction,
            forecast,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::trend_analyzer::TrendAnalyzer;
    use crate::db::{BindValue, CipherRunDatabase, DatabaseConfig};
    use chrono::{Duration, Utc};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn create_unique_db_path() -> PathBuf {
        let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        let path = PathBuf::from(format!("/tmp/cipherrun-rating-trend-test{}.db", counter));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-rating-trend-test{}.db", counter));
        let _ = std::fs::remove_file(&path);
        path
    }

    async fn setup_db() -> Arc<CipherRunDatabase> {
        let config = DatabaseConfig::sqlite(create_unique_db_path());
        let db = CipherRunDatabase::new(&config)
            .await
            .expect("test assertion should succeed");
        Arc::new(db)
    }

    async fn insert_scan(
        db: &CipherRunDatabase,
        hostname: &str,
        port: u16,
        timestamp: chrono::DateTime<chrono::Utc>,
        grade: Option<&str>,
        score: Option<i32>,
    ) -> i64 {
        let mut qb = db.pool().query_builder();
        let query = qb.insert_returning_query(
            "scans",
            &[
                "target_hostname",
                "target_port",
                "scan_timestamp",
                "overall_grade",
                "overall_score",
                "scan_duration_ms",
                "scanner_version",
            ],
            "scan_id",
        );

        let bindings = vec![
            BindValue::String(hostname.to_string()),
            BindValue::Int32(port as i32),
            BindValue::DateTime(timestamp),
            BindValue::OptString(grade.map(|g| g.to_string())),
            BindValue::OptInt32(score),
            BindValue::OptInt32(Some(1200)),
            BindValue::OptString(Some("test".to_string())),
        ];

        db.pool()
            .execute_insert_returning(&query, bindings)
            .await
            .expect("test assertion should succeed")
    }

    #[tokio::test]
    async fn test_rating_trend_analysis() {
        let db = setup_db().await;
        let hostname = "example.com";
        let port = 443;

        insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(2),
            Some("A"),
            Some(95),
        )
        .await;
        insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(1),
            Some("B"),
            Some(80),
        )
        .await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let rating = analyzer
            .analyze_rating_trend(hostname, port, 30)
            .await
            .expect("rating trend should succeed");
        assert_eq!(rating.data_points.len(), 2);
        assert!(rating.mean > 0.0);
    }
}
