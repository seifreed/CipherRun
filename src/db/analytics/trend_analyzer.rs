// Trend Analyzer
// Statistical analysis of security posture over time

use crate::db::{CipherRunDatabase, ScanRecord};
use crate::db::connection::DatabasePool;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;

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
    pub severity_distribution: HashMap<String, usize>,
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

    /// Analyze rating trend over time
    pub async fn analyze_rating_trend(&self, hostname: &str, port: u16, days: i64) -> crate::Result<RatingTrend> {
        let scans = self.db.get_scan_history(hostname, port, 100).await?;

        let cutoff = Utc::now() - Duration::days(days);
        let filtered_scans: Vec<&ScanRecord> = scans.iter()
            .filter(|s| s.scan_timestamp >= cutoff)
            .collect();

        if filtered_scans.is_empty() {
            return Err(crate::TlsError::DatabaseError("No scans found in the specified time range".to_string()));
        }

        let mut data_points = Vec::new();
        let mut scores = Vec::new();

        for scan in &filtered_scans {
            if let Some(score) = scan.overall_score {
                let score_u8 = score.max(0).min(100) as u8;
                data_points.push((scan.scan_timestamp, score_u8));
                scores.push(score_u8);
            }
        }

        if scores.is_empty() {
            return Err(crate::TlsError::DatabaseError("No rating scores found".to_string()));
        }

        let mean = Self::calculate_mean(&scores);
        let median = Self::calculate_median(&mut scores.clone());
        let std_dev = Self::calculate_std_dev(&scores, mean);
        let direction = Self::determine_trend_direction(&data_points);
        let forecast = Self::forecast_linear(&data_points);

        Ok(RatingTrend {
            data_points,
            mean,
            median,
            std_dev,
            direction,
            forecast,
        })
    }

    /// Analyze vulnerability trend over time
    pub async fn analyze_vulnerability_trend(&self, hostname: &str, port: u16, days: i64) -> crate::Result<VulnerabilityTrend> {
        let scans = self.db.get_scan_history(hostname, port, 100).await?;

        let cutoff = Utc::now() - Duration::days(days);
        let filtered_scans: Vec<&ScanRecord> = scans.iter()
            .filter(|s| s.scan_timestamp >= cutoff)
            .collect();

        if filtered_scans.is_empty() {
            return Err(crate::TlsError::DatabaseError("No scans found in the specified time range".to_string()));
        }

        let mut data_points = Vec::new();
        let mut counts = Vec::new();
        let mut severity_distribution: HashMap<String, usize> = HashMap::new();

        for scan in &filtered_scans {
            if let Some(scan_id) = scan.scan_id {
                let vulns = self.get_vulnerabilities(scan_id).await?;
                let count = vulns.len();
                data_points.push((scan.scan_timestamp, count));
                counts.push(count);

                for vuln in vulns {
                    *severity_distribution.entry(vuln.severity.clone()).or_insert(0) += 1;
                }
            }
        }

        let mean = if counts.is_empty() { 0.0 } else {
            counts.iter().sum::<usize>() as f64 / counts.len() as f64
        };

        let median = if counts.is_empty() { 0 } else {
            let mut sorted = counts.clone();
            sorted.sort_unstable();
            sorted[sorted.len() / 2]
        };

        let direction = Self::determine_usize_trend_direction(&data_points);

        Ok(VulnerabilityTrend {
            data_points,
            mean,
            median,
            severity_distribution,
            direction,
        })
    }

    /// Analyze protocol adoption trend over time
    pub async fn analyze_protocol_trend(&self, hostname: &str, port: u16, days: i64) -> crate::Result<ProtocolTrend> {
        let scans = self.db.get_scan_history(hostname, port, 100).await?;

        let cutoff = Utc::now() - Duration::days(days);
        let filtered_scans: Vec<&ScanRecord> = scans.iter()
            .filter(|s| s.scan_timestamp >= cutoff)
            .collect();

        if filtered_scans.is_empty() {
            return Err(crate::TlsError::DatabaseError("No scans found in the specified time range".to_string()));
        }

        let mut tls13_adoption = Vec::new();
        let mut tls12_usage = Vec::new();
        let mut legacy_protocols = Vec::new();

        for scan in &filtered_scans {
            if let Some(scan_id) = scan.scan_id {
                let protocols = self.get_protocols(scan_id).await?;

                let has_tls13 = protocols.iter().any(|p| p.protocol_name.contains("TLS 1.3") && p.enabled);
                let has_tls12 = protocols.iter().any(|p| p.protocol_name.contains("TLS 1.2") && p.enabled);

                tls13_adoption.push((scan.scan_timestamp, has_tls13));
                tls12_usage.push((scan.scan_timestamp, has_tls12));

                let legacy: Vec<String> = protocols.iter()
                    .filter(|p| p.enabled && (p.protocol_name.contains("SSLv") || p.protocol_name.contains("TLS 1.0") || p.protocol_name.contains("TLS 1.1")))
                    .map(|p| p.protocol_name.clone())
                    .collect();

                legacy_protocols.push((scan.scan_timestamp, legacy));
            }
        }

        let summary = Self::generate_protocol_summary(&tls13_adoption, &tls12_usage, &legacy_protocols);

        Ok(ProtocolTrend {
            tls13_adoption,
            tls12_usage,
            legacy_protocols,
            summary,
        })
    }

    /// Analyze cipher strength trend over time
    pub async fn analyze_cipher_strength_trend(&self, hostname: &str, port: u16, days: i64) -> crate::Result<CipherStrengthTrend> {
        let scans = self.db.get_scan_history(hostname, port, 100).await?;

        let cutoff = Utc::now() - Duration::days(days);
        let filtered_scans: Vec<&ScanRecord> = scans.iter()
            .filter(|s| s.scan_timestamp >= cutoff)
            .collect();

        if filtered_scans.is_empty() {
            return Err(crate::TlsError::DatabaseError("No scans found in the specified time range".to_string()));
        }

        let mut data_points = Vec::new();
        let mut weak_counts = Vec::new();
        let mut strong_counts = Vec::new();

        for scan in &filtered_scans {
            if let Some(scan_id) = scan.scan_id {
                let ciphers = self.get_ciphers(scan_id).await?;

                let weak = ciphers.iter().filter(|c| c.strength == "weak" || c.strength == "export" || c.strength == "null").count();
                let medium = ciphers.iter().filter(|c| c.strength == "medium").count();
                let strong = ciphers.iter().filter(|c| c.strength == "strong" || c.strength == "high").count();

                weak_counts.push(weak);
                strong_counts.push(strong);

                data_points.push((scan.scan_timestamp, CipherStrengthData {
                    weak,
                    medium,
                    strong,
                }));
            }
        }

        let weak_trend = Self::determine_usize_trend_direction(
            &data_points.iter().map(|(ts, data)| (*ts, data.weak)).collect::<Vec<_>>()
        );

        let strong_trend = Self::determine_usize_trend_direction(
            &data_points.iter().map(|(ts, data)| (*ts, data.strong)).collect::<Vec<_>>()
        );

        Ok(CipherStrengthTrend {
            data_points,
            weak_count_trend: weak_trend,
            strong_count_trend: strong_trend,
        })
    }

    /// Generate comprehensive trend report
    pub async fn generate_trend_report(&self, hostname: &str, port: u16, days: i64) -> crate::Result<String> {
        let mut report = String::new();

        report.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        report.push_str("║                        TREND ANALYSIS REPORT                       ║\n");
        report.push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        report.push_str(&format!("Target: {}:{}\n", hostname, port));
        report.push_str(&format!("Period: Last {} days\n", days));
        report.push_str(&format!("Generated: {}\n\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        // Rating trend
        match self.analyze_rating_trend(hostname, port, days).await {
            Ok(rating_trend) => {
                report.push_str("RATING TREND\n");
                report.push_str("───────────────────────────────────────────────────────────────────\n");
                report.push_str(&format!("Data points:   {}\n", rating_trend.data_points.len()));
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
                report.push_str("───────────────────────────────────────────────────────────────────\n");
                report.push_str(&format!("Data points:   {}\n", vuln_trend.data_points.len()));
                report.push_str(&format!("Mean count:    {:.2}\n", vuln_trend.mean));
                report.push_str(&format!("Median count:  {}\n", vuln_trend.median));
                report.push_str(&format!("Trend:         {:?}\n", vuln_trend.direction));
                report.push_str("\nSeverity Distribution:\n");
                for (severity, count) in &vuln_trend.severity_distribution {
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
                report.push_str("───────────────────────────────────────────────────────────────────\n");
                report.push_str(&protocol_trend.summary);
                report.push('\n');
            }
            Err(e) => {
                report.push_str(&format!("Protocol trend analysis failed: {}\n\n", e));
            }
        }

        // Cipher strength trend
        match self.analyze_cipher_strength_trend(hostname, port, days).await {
            Ok(cipher_trend) => {
                report.push_str("CIPHER STRENGTH TREND\n");
                report.push_str("───────────────────────────────────────────────────────────────────\n");
                report.push_str(&format!("Data points:      {}\n", cipher_trend.data_points.len()));
                report.push_str(&format!("Weak ciphers:     {:?}\n", cipher_trend.weak_count_trend));
                report.push_str(&format!("Strong ciphers:   {:?}\n", cipher_trend.strong_count_trend));

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

    fn calculate_mean(values: &[u8]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
    }

    fn calculate_median(values: &mut [u8]) -> u8 {
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        let mid = values.len() / 2;
        if values.len() % 2 == 0 {
            ((values[mid - 1] as u16 + values[mid] as u16) / 2) as u8
        } else {
            values[mid]
        }
    }

    fn calculate_std_dev(values: &[u8], mean: f64) -> f64 {
        if values.len() <= 1 {
            return 0.0;
        }
        let variance = values.iter()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt()
    }

    fn determine_trend_direction(data_points: &[(DateTime<Utc>, u8)]) -> TrendDirection {
        if data_points.len() < 2 {
            return TrendDirection::Stable;
        }

        // Simple linear regression to determine slope
        let n = data_points.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in data_points.iter().enumerate() {
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

    fn determine_usize_trend_direction(data_points: &[(DateTime<Utc>, usize)]) -> TrendDirection {
        if data_points.len() < 2 {
            return TrendDirection::Stable;
        }

        // Simple linear regression to determine slope
        let n = data_points.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in data_points.iter().enumerate() {
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

    fn forecast_linear(data_points: &[(DateTime<Utc>, u8)]) -> Option<u8> {
        if data_points.len() < 2 {
            return None;
        }

        // Linear regression
        let n = data_points.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, (_, y)) in data_points.iter().enumerate() {
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

        Some(forecast.max(0.0).min(100.0).round() as u8)
    }

    fn generate_protocol_summary(
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

        summary.push_str(&format!("TLS 1.3 adoption: {:.1}% ({}/{} scans)\n",
            tls13_percentage, tls13_count, tls13.len()));

        let tls12_count = tls12.iter().filter(|(_, enabled)| *enabled).count();
        let tls12_percentage = if !tls12.is_empty() {
            (tls12_count as f64 / tls12.len() as f64) * 100.0
        } else {
            0.0
        };

        summary.push_str(&format!("TLS 1.2 usage: {:.1}% ({}/{} scans)\n",
            tls12_percentage, tls12_count, tls12.len()));

        let legacy_count = legacy.iter().filter(|(_, protocols)| !protocols.is_empty()).count();
        if legacy_count > 0 {
            summary.push_str(&format!("Legacy protocols detected in {} scans\n", legacy_count));
        } else {
            summary.push_str("No legacy protocols detected\n");
        }

        summary
    }

    // Database helper methods

    async fn get_vulnerabilities(&self, scan_id: i64) -> crate::Result<Vec<crate::db::VulnerabilityRecord>> {
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

    async fn get_protocols(&self, scan_id: i64) -> crate::Result<Vec<crate::db::ProtocolRecord>> {
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

    async fn get_ciphers(&self, scan_id: i64) -> crate::Result<Vec<crate::db::CipherRecord>> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(TrendAnalyzer::determine_trend_direction(&improving), TrendDirection::Improving);

        let degrading = vec![
            (Utc::now(), 90),
            (Utc::now(), 85),
            (Utc::now(), 80),
            (Utc::now(), 75),
        ];
        assert_eq!(TrendAnalyzer::determine_trend_direction(&degrading), TrendDirection::Degrading);
    }
}
