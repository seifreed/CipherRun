// Dashboard Generator
// Generate visualization-ready data (JSON for frontend charting)

use crate::db::connection::DatabasePool;
use crate::db::{CipherRunDatabase, ScanRecord};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub rating_timeseries: Vec<TimeSeriesPoint>,
    pub vulnerability_distribution: Vec<DistributionPoint>,
    pub protocol_distribution: Vec<DistributionPoint>,
    pub cipher_strength: Vec<DistributionPoint>,
    pub top_issues: Vec<IssueItem>,
    pub summary: DashboardSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionPoint {
    pub label: String,
    pub value: usize,
    pub percentage: f64,
    pub color: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueItem {
    pub title: String,
    pub severity: String,
    pub count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub hostname: String,
    pub port: u16,
    pub period_days: i64,
    pub total_scans: usize,
    pub latest_grade: Option<String>,
    pub latest_score: Option<i32>,
    pub avg_score: f64,
    pub total_vulnerabilities: usize,
    pub critical_vulnerabilities: usize,
    pub generated_at: DateTime<Utc>,
}

pub struct DashboardGenerator {
    db: Arc<CipherRunDatabase>,
}

impl DashboardGenerator {
    pub fn new(db: Arc<CipherRunDatabase>) -> Self {
        Self { db }
    }

    /// Generate complete dashboard data
    pub async fn generate_dashboard(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<DashboardData> {
        let cutoff = Utc::now() - Duration::days(days);
        let scans = self
            .db
            .get_scan_history_since(hostname, port, cutoff)
            .await?;

        if scans.is_empty() {
            return Err(crate::TlsError::DatabaseError(
                "No scans found in the specified time range".to_string(),
            ));
        }

        let filtered_scans: Vec<&ScanRecord> = scans.iter().collect();

        // Generate rating timeseries
        let rating_timeseries = self.generate_rating_timeseries(&filtered_scans).await?;

        // Generate vulnerability distribution
        let vulnerability_distribution = self
            .generate_vulnerability_distribution(&filtered_scans)
            .await?;

        // Generate protocol distribution
        let protocol_distribution = self.generate_protocol_distribution(&filtered_scans).await?;

        // Generate cipher strength distribution
        let cipher_strength = self
            .generate_cipher_strength_distribution(&filtered_scans)
            .await?;

        // Generate top issues
        let all_issues = self.generate_top_issues(&filtered_scans).await?;

        // Generate summary
        let summary = self
            .generate_summary(hostname, port, days, &filtered_scans, &all_issues)
            .await?;

        let top_issues = all_issues.into_iter().take(10).collect();

        Ok(DashboardData {
            rating_timeseries,
            vulnerability_distribution,
            protocol_distribution,
            cipher_strength,
            top_issues,
            summary,
        })
    }

    /// Convert dashboard data to JSON
    pub fn to_json(&self, dashboard: &DashboardData, pretty: bool) -> crate::Result<String> {
        if pretty {
            serde_json::to_string_pretty(dashboard)
        } else {
            serde_json::to_string(dashboard)
        }
        .map_err(|e| crate::TlsError::DatabaseError(format!("JSON serialization failed: {}", e)))
    }

    // Helper methods

    async fn generate_rating_timeseries(
        &self,
        scans: &[&ScanRecord],
    ) -> crate::Result<Vec<TimeSeriesPoint>> {
        let mut timeseries = Vec::new();

        for scan in scans {
            if let Some(score) = scan.overall_score {
                timeseries.push(TimeSeriesPoint {
                    timestamp: scan.scan_timestamp,
                    value: score as f64,
                    label: scan
                        .overall_grade
                        .clone()
                        .unwrap_or_else(|| "N/A".to_string()),
                });
            }
        }

        // Sort by timestamp
        timeseries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(timeseries)
    }

    async fn generate_vulnerability_distribution(
        &self,
        scans: &[&ScanRecord],
    ) -> crate::Result<Vec<DistributionPoint>> {
        let mut severity_counts: HashMap<String, usize> = HashMap::new();

        for scan in scans {
            if let Some(scan_id) = scan.scan_id {
                let vulns = self.get_vulnerabilities(scan_id).await?;
                for vuln in vulns {
                    let severity = normalized_severity_label(&vuln.severity);
                    *severity_counts.entry(severity.to_string()).or_insert(0) += 1;
                }
            }
        }

        let total: usize = severity_counts.values().sum();
        let mut distribution = Vec::new();

        let severity_order = ["critical", "high", "medium", "low", "info", "unknown"];
        let severity_colors = [
            "#dc3545", "#fd7e14", "#ffc107", "#28a745", "#17a2b8", "#6c757d",
        ];

        for (severity, color) in severity_order.iter().zip(severity_colors.iter()) {
            if let Some(&count) = severity_counts.get(*severity) {
                let percentage = if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                distribution.push(DistributionPoint {
                    label: severity.to_string(),
                    value: count,
                    percentage,
                    color: Some(color.to_string()),
                });
            }
        }

        Ok(distribution)
    }

    async fn generate_protocol_distribution(
        &self,
        scans: &[&ScanRecord],
    ) -> crate::Result<Vec<DistributionPoint>> {
        let mut protocol_counts: HashMap<String, usize> = HashMap::new();

        for scan in scans {
            if let Some(scan_id) = scan.scan_id {
                let protocols = self.get_protocols(scan_id).await?;
                for protocol in protocols {
                    if protocol.enabled {
                        *protocol_counts
                            .entry(protocol.protocol_name.clone())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        let total: usize = protocol_counts.values().sum();
        let mut distribution: Vec<DistributionPoint> = protocol_counts
            .into_iter()
            .map(|(label, value)| {
                let percentage = if total > 0 {
                    (value as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                let color = if label.contains("TLS 1.3") {
                    Some("#28a745".to_string())
                } else if label.contains("TLS 1.2") {
                    Some("#17a2b8".to_string())
                } else if label.contains("SSLv") {
                    Some("#dc3545".to_string())
                } else {
                    Some("#ffc107".to_string())
                };

                DistributionPoint {
                    label,
                    value,
                    percentage,
                    color,
                }
            })
            .collect();

        // Sort by value descending with a stable label tie-breaker
        distribution.sort_by(|a, b| b.value.cmp(&a.value).then_with(|| a.label.cmp(&b.label)));

        Ok(distribution)
    }

    async fn generate_cipher_strength_distribution(
        &self,
        scans: &[&ScanRecord],
    ) -> crate::Result<Vec<DistributionPoint>> {
        let mut strength_counts: HashMap<String, usize> = HashMap::new();

        for scan in scans {
            if let Some(scan_id) = scan.scan_id {
                let ciphers = self.get_ciphers(scan_id).await?;
                for cipher in ciphers {
                    let strength_category = normalized_cipher_strength_category(&cipher.strength);
                    *strength_counts
                        .entry(strength_category.to_string())
                        .or_insert(0) += 1;
                }
            }
        }

        let total: usize = strength_counts.values().sum();
        let mut distribution = Vec::new();

        let strength_order = ["strong", "medium", "weak", "unknown"];
        let strength_colors = ["#28a745", "#ffc107", "#dc3545", "#6c757d"];

        for (strength, color) in strength_order.iter().zip(strength_colors.iter()) {
            if let Some(&count) = strength_counts.get(*strength) {
                let percentage = if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                distribution.push(DistributionPoint {
                    label: strength.to_string(),
                    value: count,
                    percentage,
                    color: Some(color.to_string()),
                });
            }
        }

        Ok(distribution)
    }

    async fn generate_top_issues(&self, scans: &[&ScanRecord]) -> crate::Result<Vec<IssueItem>> {
        let mut issue_tracker: HashMap<String, (String, Vec<DateTime<Utc>>)> = HashMap::new();

        for scan in scans {
            if let Some(scan_id) = scan.scan_id {
                let vulns = self.get_vulnerabilities(scan_id).await?;
                for vuln in vulns {
                    let normalized_severity = normalized_severity_label(&vuln.severity);
                    let entry = issue_tracker
                        .entry(vuln.vulnerability_type.clone())
                        .or_insert_with(|| (normalized_severity.to_string(), Vec::new()));
                    if severity_priority(normalized_severity) < severity_priority(&entry.0) {
                        entry.0 = normalized_severity.to_string();
                    }
                    entry.1.push(scan.scan_timestamp);
                }
            }
        }

        let mut issues: Vec<IssueItem> = issue_tracker
            .into_iter()
            .map(|(title, (severity, timestamps))| {
                let first_seen = timestamps.iter().min().copied().unwrap_or_else(Utc::now);
                let last_seen = timestamps.iter().max().copied().unwrap_or_else(Utc::now);
                IssueItem {
                    title,
                    severity,
                    count: timestamps.len(),
                    first_seen,
                    last_seen,
                }
            })
            .collect();

        // Sort by severity, count, and label to keep output deterministic
        issues.sort_by(|a, b| {
            severity_priority(&a.severity)
                .cmp(&severity_priority(&b.severity))
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.title.cmp(&b.title))
                .then_with(|| a.first_seen.cmp(&b.first_seen))
                .then_with(|| a.last_seen.cmp(&b.last_seen))
        });

        Ok(issues)
    }

    async fn generate_summary(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
        scans: &[&ScanRecord],
        top_issues: &[IssueItem],
    ) -> crate::Result<DashboardSummary> {
        let latest = scans.last();

        let latest_grade = latest.and_then(|s| s.overall_grade.clone());
        let latest_score = latest.and_then(|s| s.overall_score);

        let scores: Vec<i32> = scans.iter().filter_map(|s| s.overall_score).collect();

        let avg_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<i32>() as f64 / scores.len() as f64
        };

        let total_vulnerabilities = top_issues.iter().map(|i| i.count).sum();
        let critical_vulnerabilities = top_issues
            .iter()
            .filter(|i| i.severity == "critical")
            .map(|i| i.count)
            .sum();

        Ok(DashboardSummary {
            hostname: hostname.to_string(),
            port,
            period_days: days,
            total_scans: scans.len(),
            latest_grade,
            latest_score,
            avg_score,
            total_vulnerabilities,
            critical_vulnerabilities,
            generated_at: Utc::now(),
        })
    }

    // Database helper methods

    async fn get_vulnerabilities(
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

fn normalized_severity_label(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "unknown",
    }
}

fn severity_priority(severity: &str) -> usize {
    match normalized_severity_label(severity) {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

fn normalized_cipher_strength_category(strength: &str) -> &'static str {
    match strength.to_ascii_lowercase().as_str() {
        "weak" | "low" | "export" | "null" => "weak",
        "medium" => "medium",
        "strong" | "high" => "strong",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_point_creation() {
        let point = DistributionPoint {
            label: "critical".to_string(),
            value: 5,
            percentage: 25.0,
            color: Some("#dc3545".to_string()),
        };

        assert_eq!(point.label, "critical");
        assert_eq!(point.value, 5);
        assert_eq!(point.percentage, 25.0);
    }

    #[test]
    fn test_issue_item_creation() {
        let now = Utc::now();
        let issue = IssueItem {
            title: "Heartbleed".to_string(),
            severity: "critical".to_string(),
            count: 3,
            first_seen: now,
            last_seen: now,
        };

        assert_eq!(issue.title, "Heartbleed");
        assert_eq!(issue.severity, "critical");
        assert_eq!(issue.count, 3);
    }
}
