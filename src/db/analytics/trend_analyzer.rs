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
    ordered.sort_by_key(|a| a.0);
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
#[path = "trend_analyzer_tests.rs"]
mod tests;
