// Change Tracker
// Detects and reports changes between consecutive scans

use crate::db::connection::DatabasePool;
use crate::db::{CipherRecord, CipherRunDatabase, ProtocolRecord, ScanRecord, VulnerabilityRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Protocol,
    Cipher,
    Certificate,
    Vulnerability,
    Rating,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub description: String,
    pub previous_value: Option<String>,
    pub current_value: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct ChangeTracker {
    db: Arc<CipherRunDatabase>,
}

impl ChangeTracker {
    pub fn new(db: Arc<CipherRunDatabase>) -> Self {
        Self { db }
    }

    /// Detect changes for a hostname in the last N days
    pub async fn detect_changes(
        &self,
        hostname: &str,
        port: u16,
        days: i64,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let scans = self.db.get_scan_history(hostname, port, days).await?;

        if scans.len() < 2 {
            return Ok(Vec::new());
        }

        // Compare consecutive scans
        let mut all_changes = Vec::new();
        for i in 0..scans.len() - 1 {
            let newer_scan = &scans[i];
            let older_scan = &scans[i + 1];

            if let (Some(newer_id), Some(older_id)) = (newer_scan.scan_id, older_scan.scan_id) {
                let mut changes = self.detect_changes_between(older_id, newer_id).await?;
                all_changes.append(&mut changes);
            }
        }

        Ok(all_changes)
    }

    /// Detect changes between two specific scans
    pub async fn detect_changes_between(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let mut changes = Vec::new();

        // Get scan records
        let scan1_opt = self.get_scan_by_id(scan_id_1).await?;
        let scan2_opt = self.get_scan_by_id(scan_id_2).await?;

        let (scan1, scan2) = match (scan1_opt, scan2_opt) {
            (Some(s1), Some(s2)) => (s1, s2),
            _ => {
                return Err(crate::TlsError::DatabaseError(
                    "One or both scans not found".to_string(),
                ));
            }
        };

        let timestamp = scan2.scan_timestamp;

        // Detect protocol changes
        changes.append(
            &mut self
                .detect_protocol_changes(scan_id_1, scan_id_2, timestamp)
                .await?,
        );

        // Detect cipher changes
        changes.append(
            &mut self
                .detect_cipher_changes(scan_id_1, scan_id_2, timestamp)
                .await?,
        );

        // Detect certificate changes
        changes.append(
            &mut self
                .detect_certificate_changes(scan_id_1, scan_id_2, timestamp)
                .await?,
        );

        // Detect vulnerability changes
        changes.append(
            &mut self
                .detect_vulnerability_changes(scan_id_1, scan_id_2, timestamp)
                .await?,
        );

        // Detect rating changes
        changes.append(
            &mut self
                .detect_rating_changes(&scan1, &scan2, timestamp)
                .await?,
        );

        Ok(changes)
    }

    /// Generate a human-readable change report
    pub fn generate_change_report(&self, changes: &[ChangeEvent]) -> String {
        if changes.is_empty() {
            return "No changes detected.".to_string();
        }

        let mut report = String::new();
        report.push_str(&format!(
            "Change Report - {} changes detected\n",
            changes.len()
        ));
        report.push_str("═══════════════════════════════════════════════════════\n\n");

        // Group by change type
        let mut by_type: HashMap<String, Vec<&ChangeEvent>> = HashMap::new();
        for change in changes {
            let type_key = format!("{:?}", change.change_type);
            by_type.entry(type_key).or_default().push(change);
        }

        for (change_type, events) in by_type.iter() {
            report.push_str(&format!("{} Changes ({})\n", change_type, events.len()));
            report.push_str("───────────────────────────────────────────────────────\n");

            for event in events {
                let severity_marker = match event.severity {
                    ChangeSeverity::Critical => "[CRITICAL]",
                    ChangeSeverity::High => "[HIGH]    ",
                    ChangeSeverity::Medium => "[MEDIUM]  ",
                    ChangeSeverity::Low => "[LOW]     ",
                    ChangeSeverity::Info => "[INFO]    ",
                };

                report.push_str(&format!("{} {}\n", severity_marker, event.description));

                if let Some(prev) = &event.previous_value {
                    report.push_str(&format!("  Previous: {}\n", prev));
                }
                if let Some(curr) = &event.current_value {
                    report.push_str(&format!("  Current:  {}\n", curr));
                }
                report.push_str(&format!(
                    "  Time:     {}\n",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                ));
                report.push('\n');
            }
        }

        report
    }

    // Helper methods

    async fn get_scan_by_id(&self, scan_id: i64) -> crate::Result<Option<ScanRecord>> {
        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query_as::<_, ScanRecord>(
                    "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version FROM scans WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scan: {}", e)))?;
                Ok(result)
            }
            DatabasePool::Sqlite(pool) => {
                let result = sqlx::query_as::<_, ScanRecord>(
                    "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version FROM scans WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scan: {}", e)))?;
                Ok(result)
            }
        }
    }

    async fn detect_protocol_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        let mut changes = Vec::new();

        let set1: HashSet<&str> = protocols1
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.as_str())
            .collect();

        let set2: HashSet<&str> = protocols2
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.as_str())
            .collect();

        // Removed protocols
        for proto in set1.difference(&set2) {
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Medium,
                description: format!("Protocol removed: {}", proto),
                previous_value: Some("enabled".to_string()),
                current_value: Some("disabled".to_string()),
                timestamp,
            });
        }

        // Added protocols
        for proto in set2.difference(&set1) {
            let severity = if proto.contains("SSLv") {
                ChangeSeverity::High
            } else if proto.contains("TLS 1.3") {
                ChangeSeverity::Info
            } else {
                ChangeSeverity::Low
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity,
                description: format!("Protocol added: {}", proto),
                previous_value: Some("disabled".to_string()),
                current_value: Some("enabled".to_string()),
                timestamp,
            });
        }

        // Preferred protocol changes
        let pref1 = protocols1
            .iter()
            .find(|p| p.preferred)
            .map(|p| &p.protocol_name);
        let pref2 = protocols2
            .iter()
            .find(|p| p.preferred)
            .map(|p| &p.protocol_name);

        if pref1 != pref2 {
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Low,
                description: "Preferred protocol changed".to_string(),
                previous_value: pref1.cloned(),
                current_value: pref2.cloned(),
                timestamp,
            });
        }

        Ok(changes)
    }

    async fn detect_cipher_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let ciphers1 = self.get_ciphers(scan_id_1).await?;
        let ciphers2 = self.get_ciphers(scan_id_2).await?;

        let mut changes = Vec::new();

        let set1: HashSet<&str> = ciphers1.iter().map(|c| c.cipher_name.as_str()).collect();
        let set2: HashSet<&str> = ciphers2.iter().map(|c| c.cipher_name.as_str()).collect();

        // Removed ciphers
        for cipher_name in set1.difference(&set2) {
            let cipher = ciphers1
                .iter()
                .find(|c| &c.cipher_name == cipher_name)
                .ok_or_else(|| anyhow::anyhow!("Cipher {} not found in set1", cipher_name))?;
            let severity = match cipher.strength.as_str() {
                "weak" | "export" | "null" => ChangeSeverity::Low,
                _ => ChangeSeverity::Info,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Cipher,
                severity,
                description: format!("Cipher removed: {}", cipher_name),
                previous_value: Some(cipher.strength.clone()), // Necessary: String for ChangeEvent
                current_value: None,
                timestamp,
            });
        }

        // Added ciphers
        for cipher_name in set2.difference(&set1) {
            let cipher = ciphers2
                .iter()
                .find(|c| &c.cipher_name == cipher_name)
                .ok_or_else(|| anyhow::anyhow!("Cipher {} not found in set2", cipher_name))?;
            let severity = match cipher.strength.as_str() {
                "weak" | "export" | "null" => ChangeSeverity::High,
                "medium" => ChangeSeverity::Medium,
                _ => ChangeSeverity::Info,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Cipher,
                severity,
                description: format!("Cipher added: {}", cipher_name),
                previous_value: None,
                current_value: Some(cipher.strength.clone()), // Necessary: String for ChangeEvent
                timestamp,
            });
        }

        Ok(changes)
    }

    async fn detect_certificate_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let cert1 = self.get_leaf_certificate(scan_id_1).await?;
        let cert2 = self.get_leaf_certificate(scan_id_2).await?;

        let mut changes = Vec::new();

        match (cert1, cert2) {
            (Some(c1), Some(c2)) => {
                // Different certificate (renewal or replacement)
                if c1.fingerprint_sha256 != c2.fingerprint_sha256 {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Certificate,
                        severity: ChangeSeverity::Medium,
                        description: "Certificate renewed or replaced".to_string(),
                        previous_value: Some(c1.subject.clone()),
                        current_value: Some(c2.subject.clone()),
                        timestamp,
                    });

                    // Check issuer change
                    if c1.issuer != c2.issuer {
                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity: ChangeSeverity::High,
                            description: "Certificate issuer changed".to_string(),
                            previous_value: Some(c1.issuer.clone()),
                            current_value: Some(c2.issuer.clone()),
                            timestamp,
                        });
                    }

                    // Check key size change
                    if c1.public_key_size != c2.public_key_size {
                        let severity = match (c1.public_key_size, c2.public_key_size) {
                            (Some(old), Some(new)) if new < old => ChangeSeverity::High,
                            (Some(old), Some(new)) if new > old => ChangeSeverity::Low,
                            _ => ChangeSeverity::Medium,
                        };

                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity,
                            description: "Certificate key size changed".to_string(),
                            previous_value: c1.public_key_size.map(|s| format!("{} bits", s)),
                            current_value: c2.public_key_size.map(|s| format!("{} bits", s)),
                            timestamp,
                        });
                    }

                    // Check expiration extension
                    if c2.not_after > c1.not_after {
                        changes.push(ChangeEvent {
                            change_type: ChangeType::Certificate,
                            severity: ChangeSeverity::Info,
                            description: "Certificate validity extended".to_string(),
                            previous_value: Some(c1.not_after.format("%Y-%m-%d").to_string()),
                            current_value: Some(c2.not_after.format("%Y-%m-%d").to_string()),
                            timestamp,
                        });
                    }
                }
            }
            (None, Some(_)) => {
                changes.push(ChangeEvent {
                    change_type: ChangeType::Certificate,
                    severity: ChangeSeverity::Low,
                    description: "Certificate added".to_string(),
                    previous_value: None,
                    current_value: Some("present".to_string()),
                    timestamp,
                });
            }
            (Some(_), None) => {
                changes.push(ChangeEvent {
                    change_type: ChangeType::Certificate,
                    severity: ChangeSeverity::Critical,
                    description: "Certificate removed".to_string(),
                    previous_value: Some("present".to_string()),
                    current_value: None,
                    timestamp,
                });
            }
            (None, None) => {}
        }

        Ok(changes)
    }

    async fn detect_vulnerability_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let vulns1 = self.get_vulnerabilities(scan_id_1).await?;
        let vulns2 = self.get_vulnerabilities(scan_id_2).await?;

        let mut changes = Vec::new();

        let set1: HashSet<&str> = vulns1
            .iter()
            .map(|v| v.vulnerability_type.as_str())
            .collect();
        let set2: HashSet<&str> = vulns2
            .iter()
            .map(|v| v.vulnerability_type.as_str())
            .collect();

        // Resolved vulnerabilities
        for vuln_type in set1.difference(&set2) {
            let vuln = vulns1
                .iter()
                .find(|v| &v.vulnerability_type == vuln_type)
                .ok_or_else(|| anyhow::anyhow!("Vulnerability {} not found in set1", vuln_type))?;
            let severity = match vuln.severity.as_str() {
                "critical" => ChangeSeverity::Info,
                "high" => ChangeSeverity::Info,
                "medium" => ChangeSeverity::Info,
                "low" => ChangeSeverity::Info,
                _ => ChangeSeverity::Info,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Vulnerability,
                severity,
                description: format!("Vulnerability resolved: {}", vuln_type),
                previous_value: Some(vuln.severity.clone()), // Necessary: String for ChangeEvent
                current_value: Some("resolved".to_string()),
                timestamp,
            });
        }

        // New vulnerabilities
        for vuln_type in set2.difference(&set1) {
            let vuln = vulns2
                .iter()
                .find(|v| &v.vulnerability_type == vuln_type)
                .ok_or_else(|| anyhow::anyhow!("Vulnerability {} not found in set2", vuln_type))?;
            let severity = match vuln.severity.as_str() {
                "critical" => ChangeSeverity::Critical,
                "high" => ChangeSeverity::High,
                "medium" => ChangeSeverity::Medium,
                "low" => ChangeSeverity::Low,
                _ => ChangeSeverity::Info,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Vulnerability,
                severity,
                description: format!("New vulnerability detected: {}", vuln_type),
                previous_value: None,
                current_value: Some(vuln.severity.clone()), // Necessary: String for ChangeEvent
                timestamp,
            });
        }

        Ok(changes)
    }

    async fn detect_rating_changes(
        &self,
        scan1: &ScanRecord,
        scan2: &ScanRecord,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let mut changes = Vec::new();

        if scan1.overall_grade != scan2.overall_grade || scan1.overall_score != scan2.overall_score
        {
            let severity = match (scan1.overall_score, scan2.overall_score) {
                (Some(old), Some(new)) if new < old => ChangeSeverity::High,
                (Some(old), Some(new)) if new > old => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };

            changes.push(ChangeEvent {
                change_type: ChangeType::Rating,
                severity,
                description: "Overall rating changed".to_string(),
                previous_value: scan1
                    .overall_grade
                    .clone()
                    .map(|g| format!("{} ({})", g, scan1.overall_score.unwrap_or(0))),
                current_value: scan2
                    .overall_grade
                    .clone()
                    .map(|g| format!("{} ({})", g, scan2.overall_score.unwrap_or(0))),
                timestamp,
            });
        }

        Ok(changes)
    }

    async fn get_protocols(&self, scan_id: i64) -> crate::Result<Vec<ProtocolRecord>> {
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

    async fn get_ciphers(&self, scan_id: i64) -> crate::Result<Vec<CipherRecord>> {
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

    async fn get_vulnerabilities(&self, scan_id: i64) -> crate::Result<Vec<VulnerabilityRecord>> {
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

    async fn get_leaf_certificate(
        &self,
        scan_id: i64,
    ) -> crate::Result<Option<crate::db::CertificateRecord>> {
        use crate::db::CertificateRecord;
        use sqlx::Row;

        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let cert = sqlx::query_as::<_, CertificateRecord>(
                    r#"
                    SELECT c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.serial_number,
                           c.not_before, c.not_after, c.signature_algorithm, c.public_key_algorithm,
                           c.public_key_size, c.san_domains, c.is_ca, c.key_usage, c.extended_key_usage,
                           c.der_bytes, c.created_at
                    FROM certificates c
                    JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                    WHERE sc.scan_id = $1 AND sc.chain_position = 0
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;
                Ok(cert)
            }
            DatabasePool::Sqlite(pool) => {
                let row = sqlx::query(
                    r#"
                    SELECT c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.serial_number,
                           c.not_before, c.not_after, c.signature_algorithm, c.public_key_algorithm,
                           c.public_key_size, c.san_domains, c.is_ca, c.key_usage, c.extended_key_usage,
                           c.der_bytes, c.created_at
                    FROM certificates c
                    JOIN scan_certificates sc ON c.cert_id = sc.cert_id
                    WHERE sc.scan_id = ? AND sc.chain_position = 0
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;

                if let Some(row) = row {
                    let san_json: String = row.try_get("san_domains").unwrap_or_default();
                    let san_domains: Vec<String> =
                        serde_json::from_str(&san_json).unwrap_or_default();

                    let key_usage_json: String = row.try_get("key_usage").unwrap_or_default();
                    let key_usage: Vec<String> =
                        serde_json::from_str(&key_usage_json).unwrap_or_default();

                    let extended_key_usage_json: String =
                        row.try_get("extended_key_usage").unwrap_or_default();
                    let extended_key_usage: Vec<String> =
                        serde_json::from_str(&extended_key_usage_json).unwrap_or_default();

                    Ok(Some(CertificateRecord {
                        cert_id: row.try_get("cert_id").ok(),
                        fingerprint_sha256: row.try_get("fingerprint_sha256").unwrap_or_default(),
                        subject: row.try_get("subject").unwrap_or_default(),
                        issuer: row.try_get("issuer").unwrap_or_default(),
                        serial_number: row.try_get("serial_number").ok(),
                        not_before: row
                            .try_get("not_before")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                        not_after: row
                            .try_get("not_after")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                        signature_algorithm: row.try_get("signature_algorithm").ok(),
                        public_key_algorithm: row.try_get("public_key_algorithm").ok(),
                        public_key_size: row.try_get("public_key_size").ok(),
                        san_domains,
                        is_ca: row.try_get("is_ca").unwrap_or(false),
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").ok(),
                        created_at: row
                            .try_get("created_at")
                            .unwrap_or_else(|_| chrono::Utc::now()),
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_severity_ordering() {
        assert!(ChangeSeverity::Critical > ChangeSeverity::High);
        assert!(ChangeSeverity::High > ChangeSeverity::Medium);
        assert!(ChangeSeverity::Medium > ChangeSeverity::Low);
        assert!(ChangeSeverity::Low > ChangeSeverity::Info);
    }

    #[tokio::test]
    async fn test_generate_change_report_empty() {
        let db = Arc::new(
            CipherRunDatabase::new(&crate::db::DatabaseConfig::sqlite(
                std::path::PathBuf::from(":memory:"),
            ))
            .await
            .unwrap(),
        );
        let tracker = ChangeTracker::new(db);
        let report = tracker.generate_change_report(&[]);
        assert!(report.contains("No changes detected"));
    }
}
