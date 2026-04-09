// Protocol Trend Analysis
// Analyzes protocol adoption trends (TLS 1.3, TLS 1.2, legacy) over time

use super::trend_analyzer::TrendAnalyzer;
use chrono::{DateTime, Utc};

impl TrendAnalyzer {
    /// Analyze protocol adoption trend over time
    pub async fn analyze_protocol_trend(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<super::trend_analyzer::ProtocolTrend> {
        let scans = self.get_scans_in_range(hostname, port, days).await?;

        if scans.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No scans found in the specified time range".to_string(),
            ));
        }

        let mut tls13_adoption = Vec::new();
        let mut tls12_usage = Vec::new();
        let mut legacy_protocols = Vec::new();

        for scan in &scans {
            if let Some(scan_id) = scan.scan_id {
                let protocols = self.get_protocols(scan_id).await?;

                let has_tls13 = protocols
                    .iter()
                    .any(|p| p.protocol_name.contains("TLS 1.3") && p.enabled);
                let has_tls12 = protocols
                    .iter()
                    .any(|p| p.protocol_name.contains("TLS 1.2") && p.enabled);

                tls13_adoption.push((scan.scan_timestamp, has_tls13));
                tls12_usage.push((scan.scan_timestamp, has_tls12));

                let legacy: Vec<String> = protocols
                    .iter()
                    .filter(|p| {
                        p.enabled
                            && (p.protocol_name.contains("SSLv")
                                || p.protocol_name.contains("TLS 1.0")
                                || p.protocol_name.contains("TLS 1.1"))
                    })
                    .map(|p| p.protocol_name.clone())
                    .collect();

                legacy_protocols.push((scan.scan_timestamp, legacy));
            }
        }

        let summary =
            Self::generate_protocol_summary(&tls13_adoption, &tls12_usage, &legacy_protocols);

        Ok(super::trend_analyzer::ProtocolTrend {
            tls13_adoption,
            tls12_usage,
            legacy_protocols,
            summary,
        })
    }

    pub(crate) fn generate_protocol_summary(
        tls13: &[(DateTime<Utc>, bool)],
        tls12: &[(DateTime<Utc>, bool)],
        legacy: &[(DateTime<Utc>, Vec<String>)],
    ) -> String {
        let mut summary = String::new();

        let tls13_count = tls13.iter().filter(|(_, enabled)| *enabled).count();
        let tls13_percentage = if !tls13.is_empty() {
            (tls13_count as f64 / tls13.len() as f64) * 100.0
        } else {
            0.0
        };

        summary.push_str(&format!(
            "TLS 1.3 adoption: {:.1}% ({}/{} scans)\n",
            tls13_percentage,
            tls13_count,
            tls13.len()
        ));

        let tls12_count = tls12.iter().filter(|(_, enabled)| *enabled).count();
        let tls12_percentage = if !tls12.is_empty() {
            (tls12_count as f64 / tls12.len() as f64) * 100.0
        } else {
            0.0
        };

        summary.push_str(&format!(
            "TLS 1.2 usage: {:.1}% ({}/{} scans)\n",
            tls12_percentage,
            tls12_count,
            tls12.len()
        ));

        let legacy_count = legacy
            .iter()
            .filter(|(_, protocols)| !protocols.is_empty())
            .count();
        if legacy_count > 0 {
            summary.push_str(&format!(
                "Legacy protocols detected in {} scans\n",
                legacy_count
            ));
        } else {
            summary.push_str("No legacy protocols detected\n");
        }

        summary
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
        let path = PathBuf::from(format!("/tmp/cipherrun-proto-trend-test{}.db", counter));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-proto-trend-test{}.db", counter));
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

    async fn insert_protocol(
        db: &CipherRunDatabase,
        scan_id: i64,
        name: &str,
        enabled: bool,
        preferred: bool,
    ) {
        let mut qb = db.pool().query_builder();
        let query = qb.insert_query(
            "protocols",
            &["scan_id", "protocol_name", "enabled", "preferred"],
        );
        let bindings = vec![
            BindValue::Int64(scan_id),
            BindValue::String(name.to_string()),
            BindValue::Bool(enabled),
            BindValue::Bool(preferred),
        ];
        db.pool()
            .execute(&query, bindings)
            .await
            .expect("test assertion should succeed");
    }

    #[test]
    fn test_generate_protocol_summary() {
        let tls13 = vec![(Utc::now(), true), (Utc::now(), false)];
        let tls12 = vec![(Utc::now(), true), (Utc::now(), true)];
        let legacy = vec![(Utc::now(), vec!["SSLv3".to_string()])];

        let summary = TrendAnalyzer::generate_protocol_summary(&tls13, &tls12, &legacy);
        assert!(summary.contains("TLS 1.3 adoption"));
        assert!(summary.contains("TLS 1.2 usage"));
        assert!(summary.contains("Legacy protocols detected"));
    }

    #[tokio::test]
    async fn test_protocol_trend_analysis() {
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

        insert_protocol(&db, scan1, "TLS 1.3", true, true).await;
        insert_protocol(&db, scan1, "TLS 1.2", true, false).await;
        insert_protocol(&db, scan2, "TLS 1.2", true, true).await;
        insert_protocol(&db, scan2, "SSLv3", true, false).await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let protocol = analyzer
            .analyze_protocol_trend(hostname, port, 30)
            .await
            .expect("protocol trend should succeed");
        assert!(protocol.summary.contains("TLS 1.3 adoption"));
    }
}
