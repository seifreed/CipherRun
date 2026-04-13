// Trend Analyzer
// Statistical analysis of security posture over time

use crate::db::CipherRunDatabase;
use crate::db::connection::DatabasePool;
use crate::utils::network::canonical_target;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrendDirection {
    Improving,
    Degrading,
    Stable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingTrend {
    pub data_points: Vec<(DateTime<Utc>, u8)>,
    pub mean: f64,
    pub median: u8,
    pub std_dev: f64,
    pub direction: TrendDirection,
    pub forecast: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityTrend {
    pub data_points: Vec<(DateTime<Utc>, usize)>,
    pub mean: f64,
    pub median: usize,
    pub severity_distribution: BTreeMap<String, usize>,
    pub direction: TrendDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTrend {
    pub tls13_adoption: Vec<(DateTime<Utc>, bool)>,
    pub tls12_usage: Vec<(DateTime<Utc>, bool)>,
    pub legacy_protocols: Vec<(DateTime<Utc>, Vec<String>)>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherStrengthTrend {
    pub data_points: Vec<(DateTime<Utc>, CipherStrengthData)>,
    pub weak_count_trend: TrendDirection,
    pub strong_count_trend: TrendDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherStrengthData {
    pub weak: usize,
    pub medium: usize,
    pub strong: usize,
}

pub struct TrendAnalyzer {
    db: Arc<CipherRunDatabase>,
}

impl TrendAnalyzer {
    pub fn new(db: Arc<CipherRunDatabase>) -> Self {
        Self { db }
    }

    /// Fetch scans within a time window and return them in chronological order.
    pub(crate) async fn get_scans_in_range(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<Vec<crate::db::ScanRecord>> {
        let cutoff = Utc::now() - Duration::days(days);
        self.db.get_scan_history_since(hostname, port, cutoff).await
    }

    /// Generate comprehensive trend report
    pub async fn generate_trend_report(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<String> {
        let mut report = String::new();

        report.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        report.push_str("║                        TREND ANALYSIS REPORT                       ║\n");
        report
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        report.push_str(&format!("Target: {}\n", canonical_target(hostname, port)));
        report.push_str(&format!("Period: Last {} days\n", days));
        report.push_str(&format!(
            "Generated: {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Rating trend
        match self.analyze_rating_trend(hostname, port, days).await {
            Ok(rating_trend) => {
                report.push_str("RATING TREND\n");
                report.push_str(
                    "───────────────────────────────────────────────────────────────────\n",
                );
                report.push_str(&format!(
                    "Data points:   {}\n",
                    rating_trend.data_points.len()
                ));
                report.push_str(&format!("Mean score:    {:.2}\n", rating_trend.mean));
                report.push_str(&format!("Median score:  {}\n", rating_trend.median));
                report.push_str(&format!("Std deviation: {:.2}\n", rating_trend.std_dev));
                report.push_str(&format!("Trend:         {:?}\n", rating_trend.direction));
                if let Some(forecast) = rating_trend.forecast {
                    report.push_str(&format!("Forecast:      {}\n", forecast));
                }
                report.push('\n');
            }
            Err(e) => {
                report.push_str(&format!("Rating trend analysis failed: {}\n\n", e));
            }
        }

        // Vulnerability trend
        match self.analyze_vulnerability_trend(hostname, port, days).await {
            Ok(vuln_trend) => {
                report.push_str("VULNERABILITY TREND\n");
                report.push_str(
                    "───────────────────────────────────────────────────────────────────\n",
                );
                report.push_str(&format!(
                    "Data points:   {}\n",
                    vuln_trend.data_points.len()
                ));
                report.push_str(&format!("Mean count:    {:.2}\n", vuln_trend.mean));
                report.push_str(&format!("Median count:  {}\n", vuln_trend.median));
                report.push_str(&format!("Trend:         {:?}\n", vuln_trend.direction));
                report.push_str("\nSeverity Distribution:\n");
                let mut severity_distribution: Vec<_> =
                    vuln_trend.severity_distribution.iter().collect();
                severity_distribution.sort_by(|(severity_a, _), (severity_b, _)| {
                    severity_sort_rank(severity_a)
                        .cmp(&severity_sort_rank(severity_b))
                        .then_with(|| severity_a.cmp(severity_b))
                });
                for (severity, count) in severity_distribution {
                    report.push_str(&format!("  {}: {}\n", severity, count));
                }
                report.push('\n');
            }
            Err(e) => {
                report.push_str(&format!("Vulnerability trend analysis failed: {}\n\n", e));
            }
        }

        // Protocol trend
        match self.analyze_protocol_trend(hostname, port, days).await {
            Ok(protocol_trend) => {
                report.push_str("PROTOCOL TREND\n");
                report.push_str(
                    "───────────────────────────────────────────────────────────────────\n",
                );
                report.push_str(&protocol_trend.summary);
                report.push('\n');
            }
            Err(e) => {
                report.push_str(&format!("Protocol trend analysis failed: {}\n\n", e));
            }
        }

        // Cipher strength trend
        match self
            .analyze_cipher_strength_trend(hostname, port, days)
            .await
        {
            Ok(cipher_trend) => {
                report.push_str("CIPHER STRENGTH TREND\n");
                report.push_str(
                    "───────────────────────────────────────────────────────────────────\n",
                );
                report.push_str(&format!(
                    "Data points:      {}\n",
                    cipher_trend.data_points.len()
                ));
                report.push_str(&format!(
                    "Weak ciphers:     {:?}\n",
                    cipher_trend.weak_count_trend
                ));
                report.push_str(&format!(
                    "Strong ciphers:   {:?}\n",
                    cipher_trend.strong_count_trend
                ));

                if let Some((_, latest)) = cipher_trend.data_points.last() {
                    report.push_str("\nLatest distribution:\n");
                    report.push_str(&format!("  Weak:   {}\n", latest.weak));
                    report.push_str(&format!("  Medium: {}\n", latest.medium));
                    report.push_str(&format!("  Strong: {}\n", latest.strong));
                }
                report.push('\n');
            }
            Err(e) => {
                report.push_str(&format!("Cipher strength trend analysis failed: {}\n\n", e));
            }
        }

        Ok(report)
    }

    // Statistical helper methods

    pub(crate) fn calculate_mean(values: &[u8]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
    }

    pub(crate) fn calculate_median(values: &mut [u8]) -> u8 {
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        let mid = values.len() / 2;
        if values.len().is_multiple_of(2) {
            ((values[mid - 1] as u16 + values[mid] as u16) / 2) as u8
        } else {
            values[mid]
        }
    }

    pub(crate) fn calculate_usize_median(values: &mut [usize]) -> usize {
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        let mid = values.len() / 2;
        if values.len().is_multiple_of(2) {
            ((values[mid - 1] as u128 + values[mid] as u128) / 2) as usize
        } else {
            values[mid]
        }
    }

    pub(crate) fn calculate_std_dev(values: &[u8], mean: f64) -> f64 {
        if values.len() <= 1 {
            return 0.0;
        }
        let variance = values
            .iter()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / (values.len() - 1) as f64;
        variance.sqrt()
    }

    pub(crate) fn determine_trend_direction(data_points: &[(DateTime<Utc>, u8)]) -> TrendDirection {
        if data_points.len() < 2 {
            return TrendDirection::Stable;
        }

        let ordered = ordered_data_points(data_points);

        // Simple linear regression to determine slope
        let n = ordered.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in ordered.iter().enumerate() {
            let x = i as f64;
            let y_val = *y as f64;
            sum_x += x;
            sum_y += y_val;
            sum_xy += x * y_val;
            sum_x2 += x * x;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);

        if slope > 0.5 {
            TrendDirection::Improving
        } else if slope < -0.5 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        }
    }

    pub(crate) fn determine_usize_trend_direction(
        data_points: &[(DateTime<Utc>, usize)],
    ) -> TrendDirection {
        if data_points.len() < 2 {
            return TrendDirection::Stable;
        }

        let ordered = ordered_data_points(data_points);

        // Simple linear regression to determine slope
        let n = ordered.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in ordered.iter().enumerate() {
            let x = i as f64;
            let y_val = *y as f64;
            sum_x += x;
            sum_y += y_val;
            sum_xy += x * y_val;
            sum_x2 += x * x;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);

        // For vulnerabilities and weak ciphers, decreasing is improving
        if slope < -0.1 {
            TrendDirection::Improving
        } else if slope > 0.1 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        }
    }

    pub(crate) fn forecast_linear(data_points: &[(DateTime<Utc>, u8)]) -> Option<u8> {
        if data_points.len() < 2 {
            return None;
        }

        let ordered = ordered_data_points(data_points);

        // Linear regression
        let n = ordered.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in ordered.iter().enumerate() {
            let x = i as f64;
            let y_val = *y as f64;
            sum_x += x;
            sum_y += y_val;
            sum_xy += x * y_val;
            sum_x2 += x * x;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        // Forecast next point
        let next_x = data_points.len() as f64;
        let forecast = slope * next_x + intercept;

        Some(forecast.clamp(0.0, 100.0).round() as u8)
    }

    // Database helper methods

    pub(crate) async fn get_vulnerabilities(
        &self,
        scan_id: i64,
    ) -> crate::Result<Vec<crate::db::VulnerabilityRecord>> {
        use crate::db::VulnerabilityRecord;

        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let vulns = sqlx::query_as::<_, VulnerabilityRecord>(
                    "SELECT vuln_id, scan_id, vulnerability_type, severity, description, cve_id, affected_component FROM vulnerabilities WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch vulnerabilities: {}", e)))?;
                Ok(vulns)
            }
            DatabasePool::Sqlite(pool) => {
                let vulns = sqlx::query_as::<_, VulnerabilityRecord>(
                    "SELECT vuln_id, scan_id, vulnerability_type, severity, description, cve_id, affected_component FROM vulnerabilities WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch vulnerabilities: {}", e)))?;
                Ok(vulns)
            }
        }
    }

    pub(crate) async fn get_protocols(
        &self,
        scan_id: i64,
    ) -> crate::Result<Vec<crate::db::ProtocolRecord>> {
        use crate::db::ProtocolRecord;

        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let protocols = sqlx::query_as::<_, ProtocolRecord>(
                    "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch protocols: {}", e)))?;
                Ok(protocols)
            }
            DatabasePool::Sqlite(pool) => {
                let protocols = sqlx::query_as::<_, ProtocolRecord>(
                    "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch protocols: {}", e)))?;
                Ok(protocols)
            }
        }
    }

    pub(crate) async fn get_ciphers(
        &self,
        scan_id: i64,
    ) -> crate::Result<Vec<crate::db::CipherRecord>> {
        use crate::db::CipherRecord;

        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let ciphers = sqlx::query_as::<_, CipherRecord>(
                    "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ciphers: {}", e)))?;
                Ok(ciphers)
            }
            DatabasePool::Sqlite(pool) => {
                let ciphers = sqlx::query_as::<_, CipherRecord>(
                    "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ciphers: {}", e)))?;
                Ok(ciphers)
            }
        }
    }
}

fn ordered_data_points<T: Clone>(data_points: &[(DateTime<Utc>, T)]) -> Vec<(DateTime<Utc>, T)> {
    let mut ordered = data_points.to_vec();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    ordered
}

fn severity_sort_rank(severity: &str) -> usize {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{BindValue, CipherRunDatabase, DatabaseConfig};
    use chrono::{Duration, Utc};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_calculate_mean() {
        let values = vec![80, 85, 90, 95, 100];
        let mean = TrendAnalyzer::calculate_mean(&values);
        assert_eq!(mean, 90.0);
    }

    #[test]
    fn test_calculate_median_odd() {
        let mut values = vec![80, 85, 90, 95, 100];
        let median = TrendAnalyzer::calculate_median(&mut values);
        assert_eq!(median, 90);
    }

    #[test]
    fn test_calculate_median_even() {
        let mut values = vec![80, 85, 90, 95];
        let median = TrendAnalyzer::calculate_median(&mut values);
        assert_eq!(median, 87);
    }

    #[test]
    fn test_calculate_usize_median_even() {
        let mut values = vec![1usize, 4usize];
        let median = TrendAnalyzer::calculate_usize_median(&mut values);
        assert_eq!(median, 2);
    }

    #[test]
    fn test_vulnerability_trend_serializes_severity_distribution_deterministically() {
        let mut first_distribution = BTreeMap::new();
        first_distribution.insert("medium".to_string(), 2);
        first_distribution.insert("high".to_string(), 1);

        let mut second_distribution = BTreeMap::new();
        second_distribution.insert("high".to_string(), 1);
        second_distribution.insert("medium".to_string(), 2);

        let first = VulnerabilityTrend {
            data_points: vec![],
            mean: 0.0,
            median: 0,
            severity_distribution: first_distribution,
            direction: TrendDirection::Stable,
        };
        let second = VulnerabilityTrend {
            data_points: vec![],
            mean: 0.0,
            median: 0,
            severity_distribution: second_distribution,
            direction: TrendDirection::Stable,
        };

        let first_json = serde_json::to_string(&first).expect("serialization should succeed");
        let second_json = serde_json::to_string(&second).expect("serialization should succeed");

        assert_eq!(first_json, second_json);
        assert!(
            first_json.find("\"high\":1").expect("high severity")
                < first_json.find("\"medium\":2").expect("medium severity")
        );
    }

    #[test]
    fn test_calculate_std_dev() {
        let values = vec![80, 85, 90, 95, 100];
        let mean = TrendAnalyzer::calculate_mean(&values);
        let std_dev = TrendAnalyzer::calculate_std_dev(&values, mean);
        assert!(std_dev > 7.0 && std_dev < 8.0);
    }

    #[test]
    fn test_trend_direction() {
        let improving = vec![
            (Utc::now(), 70),
            (Utc::now(), 75),
            (Utc::now(), 80),
            (Utc::now(), 85),
        ];
        assert_eq!(
            TrendAnalyzer::determine_trend_direction(&improving),
            TrendDirection::Improving
        );

        let degrading = vec![
            (Utc::now(), 90),
            (Utc::now(), 85),
            (Utc::now(), 80),
            (Utc::now(), 75),
        ];
        assert_eq!(
            TrendAnalyzer::determine_trend_direction(&degrading),
            TrendDirection::Degrading
        );
    }

    #[test]
    fn test_trend_direction_stable_and_usize() {
        let stable = vec![(Utc::now(), 80), (Utc::now(), 81), (Utc::now(), 79)];
        assert_eq!(
            TrendAnalyzer::determine_trend_direction(&stable),
            TrendDirection::Stable
        );

        let improving = vec![(Utc::now(), 10usize), (Utc::now(), 5usize)];
        assert_eq!(
            TrendAnalyzer::determine_usize_trend_direction(&improving),
            TrendDirection::Improving
        );

        let degrading = vec![(Utc::now(), 1usize), (Utc::now(), 10usize)];
        assert_eq!(
            TrendAnalyzer::determine_usize_trend_direction(&degrading),
            TrendDirection::Degrading
        );
    }

    #[test]
    fn test_forecast_linear() {
        let points = vec![(Utc::now(), 60), (Utc::now(), 70), (Utc::now(), 80)];
        let forecast = TrendAnalyzer::forecast_linear(&points).unwrap();
        assert!(forecast >= 80);
    }

    #[test]
    fn test_trend_functions_are_order_independent() {
        let base = Utc::now();
        let rating_points_desc = vec![
            (base + Duration::minutes(2), 80),
            (base + Duration::minutes(1), 70),
            (base, 60),
        ];
        assert_eq!(
            TrendAnalyzer::determine_trend_direction(&rating_points_desc),
            TrendDirection::Improving
        );
        assert_eq!(
            TrendAnalyzer::forecast_linear(&rating_points_desc),
            Some(90)
        );

        let vuln_points_desc = vec![
            (base + Duration::minutes(2), 15usize),
            (base + Duration::minutes(1), 10usize),
            (base, 5usize),
        ];
        assert_eq!(
            TrendAnalyzer::determine_usize_trend_direction(&vuln_points_desc),
            TrendDirection::Degrading
        );
    }

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn create_unique_db_path() -> PathBuf {
        let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        #[cfg(unix)]
        let path = PathBuf::from(format!("/tmp/cipherrun-trend-test{}.db", counter));
        #[cfg(not(unix))]
        let path = std::env::temp_dir().join(format!("cipherrun-trend-test{}.db", counter));
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

    async fn insert_vulnerability(
        db: &CipherRunDatabase,
        scan_id: i64,
        vuln_type: &str,
        severity: &str,
    ) {
        let mut qb = db.pool().query_builder();
        let query = qb.insert_query(
            "vulnerabilities",
            &[
                "scan_id",
                "vulnerability_type",
                "severity",
                "description",
                "cve_id",
                "affected_component",
            ],
        );
        let bindings = vec![
            BindValue::Int64(scan_id),
            BindValue::String(vuln_type.to_string()),
            BindValue::String(severity.to_string()),
            BindValue::OptString(None),
            BindValue::OptString(None),
            BindValue::OptString(None),
        ];
        db.pool()
            .execute(&query, bindings)
            .await
            .expect("test assertion should succeed");
    }

    #[tokio::test]
    async fn test_trend_analyzer_with_database_data() {
        let db = setup_db().await;
        let hostname = "2001:db8::1";
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

        insert_cipher(&db, scan1, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "strong").await;
        insert_cipher(&db, scan2, "TLS 1.2", "AES128-SHA", "weak").await;

        insert_vulnerability(&db, scan1, "ROBOT", "high").await;
        insert_vulnerability(&db, scan2, "SWEET32", "medium").await;
        insert_vulnerability(&db, scan2, "LOGJAM", "low").await;

        let analyzer = TrendAnalyzer::new(db.clone());

        let rating = analyzer
            .analyze_rating_trend(hostname, port, 30)
            .await
            .expect("rating trend should succeed");
        assert_eq!(rating.data_points.len(), 2);
        assert!(rating.mean > 0.0);

        let vuln = analyzer
            .analyze_vulnerability_trend(hostname, port, 30)
            .await
            .expect("vulnerability trend should succeed");
        assert_eq!(vuln.data_points.len(), 2);
        assert!(vuln.severity_distribution.contains_key("high"));

        let protocol = analyzer
            .analyze_protocol_trend(hostname, port, 30)
            .await
            .expect("protocol trend should succeed");
        assert!(protocol.summary.contains("TLS 1.3 adoption"));

        let cipher = analyzer
            .analyze_cipher_strength_trend(hostname, port, 30)
            .await
            .expect("cipher trend should succeed");
        assert_eq!(cipher.data_points.len(), 2);

        let report = analyzer
            .generate_trend_report(hostname, port, 30)
            .await
            .expect("trend report should succeed");
        assert!(report.contains("TREND ANALYSIS REPORT"));
        assert!(report.contains("RATING TREND"));
        assert!(report.contains("Target: [2001:db8::1]:443"));

        let high_pos = report
            .find("  high: ")
            .expect("high severity line should exist");
        let medium_pos = report
            .find("  medium: ")
            .expect("medium severity line should exist");
        let low_pos = report
            .find("  low: ")
            .expect("low severity line should exist");
        assert!(high_pos < medium_pos);
        assert!(medium_pos < low_pos);
    }
}
