// Cipher Strength Trend Analysis
// Analyzes cipher suite strength distribution over time

use super::trend_analyzer::{CipherStrengthData, TrendAnalyzer};

fn cipher_strength_category(strength: &str) -> &'static str {
    match strength.to_ascii_lowercase().as_str() {
        "weak" | "low" | "export" | "null" => "weak",
        "medium" => "medium",
        "strong" | "high" => "strong",
        _ => "unknown",
    }
}

impl TrendAnalyzer {
    /// Analyze cipher strength trend over time
    pub async fn analyze_cipher_strength_trend(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<super::trend_analyzer::CipherStrengthTrend> {
        let scans = self.get_scans_in_range(hostname, port, days).await?;

        if scans.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No scans found in the specified time range".to_string(),
            ));
        }

        let mut data_points = Vec::new();
        let mut weak_counts = Vec::new();
        let mut strong_counts = Vec::new();

        for scan in &scans {
            if let Some(scan_id) = scan.scan_id {
                let ciphers = self.get_ciphers(scan_id).await?;

                let weak = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "weak")
                    .count();
                let medium = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "medium")
                    .count();
                let strong = ciphers
                    .iter()
                    .filter(|c| cipher_strength_category(&c.strength) == "strong")
                    .count();

                weak_counts.push(weak);
                strong_counts.push(strong);

                data_points.push((
                    scan.scan_timestamp,
                    CipherStrengthData {
                        weak,
                        medium,
                        strong,
                    },
                ));
            }
        }

        let weak_trend = Self::determine_usize_trend_direction(
            &data_points
                .iter()
                .map(|(ts, data)| (*ts, data.weak))
                .collect::<Vec<_>>(),
        );

        let strong_trend = Self::determine_usize_trend_direction(
            &data_points
                .iter()
                .map(|(ts, data)| (*ts, data.strong))
                .collect::<Vec<_>>(),
        );

        Ok(super::trend_analyzer::CipherStrengthTrend {
            data_points,
            weak_count_trend: weak_trend,
            strong_count_trend: strong_trend,
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
        let path = PathBuf::from(format!("/tmp/cipherrun-cipher-trend-test{}.db", counter));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-cipher-trend-test{}.db", counter));
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

    async fn insert_cipher(
        db: &CipherRunDatabase,
        scan_id: i64,
        protocol: &str,
        cipher_name: &str,
        strength: &str,
    ) {
        let mut qb = db.pool().query_builder();
        let query = qb.insert_query(
            "cipher_suites",
            &[
                "scan_id",
                "protocol_name",
                "cipher_name",
                "key_exchange",
                "authentication",
                "encryption",
                "mac",
                "bits",
                "forward_secrecy",
                "strength",
            ],
        );
        let bindings = vec![
            BindValue::Int64(scan_id),
            BindValue::String(protocol.to_string()),
            BindValue::String(cipher_name.to_string()),
            BindValue::OptString(None),
            BindValue::OptString(None),
            BindValue::OptString(None),
            BindValue::OptString(None),
            BindValue::OptInt32(None),
            BindValue::Bool(true),
            BindValue::String(strength.to_string()),
        ];
        db.pool()
            .execute(&query, bindings)
            .await
            .expect("test assertion should succeed");
    }

    #[tokio::test]
    async fn test_cipher_strength_trend_analysis() {
        let db = setup_db().await;
        let hostname = "example.com";
        let port = 443;

        let scan1 = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(2),
            Some("A"),
            Some(95),
        )
        .await;
        let scan2 = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(1),
            Some("B"),
            Some(80),
        )
        .await;

        insert_cipher(&db, scan1, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "strong").await;
        insert_cipher(&db, scan2, "TLS 1.2", "AES128-SHA", "weak").await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let cipher = analyzer
            .analyze_cipher_strength_trend(hostname, port, 30)
            .await
            .expect("cipher trend should succeed");
        assert_eq!(cipher.data_points.len(), 2);
    }

    #[tokio::test]
    async fn test_cipher_strength_trend_counts_low_strength_as_weak() {
        let db = setup_db().await;
        let hostname = "low-cipher.example.com";
        let port = 443;

        let scan = insert_scan(
            &db,
            hostname,
            port,
            Utc::now() - Duration::days(1),
            Some("C"),
            Some(55),
        )
        .await;

        insert_cipher(&db, scan, "TLS 1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "low").await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let cipher = analyzer
            .analyze_cipher_strength_trend(hostname, port, 30)
            .await
            .expect("cipher trend should succeed");
        assert_eq!(cipher.data_points.len(), 1);
        assert_eq!(cipher.data_points[0].1.weak, 1);
        assert_eq!(cipher.data_points[0].1.medium, 0);
        assert_eq!(cipher.data_points[0].1.strong, 0);
    }
}
