// Scan Comparator
// Generates detailed side-by-side comparison of two scans

use crate::db::{CipherRunDatabase, ScanRecord, ProtocolRecord, CipherRecord, VulnerabilityRecord, CertificateRecord, RatingRecord};
use crate::db::connection::DatabasePool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::{HashSet, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    pub scan_1: ScanRecord,
    pub scan_2: ScanRecord,
    pub protocol_diff: ProtocolDiff,
    pub cipher_diff: CipherDiff,
    pub certificate_diff: CertificateDiff,
    pub vulnerability_diff: VulnerabilityDiff,
    pub rating_diff: RatingDiff,
    pub summary: ComparisonSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
    pub preferred_change: Option<(Option<String>, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDiff {
    pub added: Vec<CipherInfo>,
    pub removed: Vec<CipherInfo>,
    pub unchanged: Vec<CipherInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    pub name: String,
    pub protocol: String,
    pub strength: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDiff {
    pub fingerprint_changed: bool,
    pub subject_changed: bool,
    pub issuer_changed: bool,
    pub key_size_changed: bool,
    pub expiry_changed: bool,
    pub scan_1_cert: Option<CertSummary>,
    pub scan_2_cert: Option<CertSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_size: Option<i32>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDiff {
    pub resolved: Vec<VulnInfo>,
    pub new: Vec<VulnInfo>,
    pub unchanged: Vec<VulnInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    pub vuln_type: String,
    pub severity: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingDiff {
    pub overall_changed: bool,
    pub scan_1_grade: Option<String>,
    pub scan_1_score: Option<i32>,
    pub scan_2_grade: Option<String>,
    pub scan_2_score: Option<i32>,
    pub component_diffs: Vec<ComponentRatingDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRatingDiff {
    pub category: String,
    pub scan_1_score: Option<i32>,
    pub scan_2_score: Option<i32>,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub total_changes: usize,
    pub protocol_changes: usize,
    pub cipher_changes: usize,
    pub certificate_changes: usize,
    pub vulnerability_changes: usize,
    pub rating_changes: usize,
    pub time_between_scans: i64,  // seconds
}

pub struct ScanComparator {
    db: Arc<CipherRunDatabase>,
}

impl ScanComparator {
    pub fn new(db: Arc<CipherRunDatabase>) -> Self {
        Self { db }
    }

    /// Compare two specific scans
    pub async fn compare_scans(&self, scan_id_1: i64, scan_id_2: i64) -> crate::Result<ScanComparison> {
        // Get scan records
        let scan_1 = self.get_scan_by_id(scan_id_1).await?
            .ok_or_else(|| crate::TlsError::DatabaseError(format!("Scan {} not found", scan_id_1)))?;
        let scan_2 = self.get_scan_by_id(scan_id_2).await?
            .ok_or_else(|| crate::TlsError::DatabaseError(format!("Scan {} not found", scan_id_2)))?;

        // Compare protocols
        let protocol_diff = self.compare_protocols(scan_id_1, scan_id_2).await?;

        // Compare ciphers
        let cipher_diff = self.compare_ciphers(scan_id_1, scan_id_2).await?;

        // Compare certificates
        let certificate_diff = self.compare_certificates(scan_id_1, scan_id_2).await?;

        // Compare vulnerabilities
        let vulnerability_diff = self.compare_vulnerabilities(scan_id_1, scan_id_2).await?;

        // Compare ratings
        let rating_diff = self.compare_ratings(&scan_1, &scan_2, scan_id_1, scan_id_2).await?;

        // Generate summary
        let summary = self.generate_summary(
            &scan_1,
            &scan_2,
            &protocol_diff,
            &cipher_diff,
            &certificate_diff,
            &vulnerability_diff,
            &rating_diff,
        );

        Ok(ScanComparison {
            scan_1,
            scan_2,
            protocol_diff,
            cipher_diff,
            certificate_diff,
            vulnerability_diff,
            rating_diff,
            summary,
        })
    }

    /// Compare the two latest scans for a hostname
    pub async fn compare_latest(&self, hostname: &str, port: u16) -> crate::Result<ScanComparison> {
        let scans = self.db.get_scan_history(hostname, port, 2).await?;

        if scans.len() < 2 {
            return Err(crate::TlsError::DatabaseError(
                "Not enough scans found for comparison".to_string()
            ));
        }

        let scan_id_1 = scans[1].scan_id.ok_or_else(||
            crate::TlsError::DatabaseError("Scan ID missing".to_string())
        )?;
        let scan_id_2 = scans[0].scan_id.ok_or_else(||
            crate::TlsError::DatabaseError("Scan ID missing".to_string())
        )?;

        self.compare_scans(scan_id_1, scan_id_2).await
    }

    /// Format comparison as string
    pub fn format_comparison(&self, comparison: &ScanComparison, format: &str) -> crate::Result<String> {
        match format.to_lowercase().as_str() {
            "json" => {
                serde_json::to_string_pretty(comparison)
                    .map_err(|e| crate::TlsError::DatabaseError(format!("JSON serialization failed: {}", e)))
            }
            "terminal" | "text" => Ok(self.format_terminal(comparison)),
            _ => Err(crate::TlsError::DatabaseError(format!("Unknown format: {}", format))),
        }
    }

    // Helper methods

    fn format_terminal(&self, comp: &ScanComparison) -> String {
        let mut output = String::new();

        output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                        SCAN COMPARISON                             ║\n");
        output.push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        // Scan info
        output.push_str(&format!("Scan 1: {} (ID: {})\n",
            comp.scan_1.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            comp.scan_1.scan_id.unwrap_or(0)
        ));
        output.push_str(&format!("Scan 2: {} (ID: {})\n",
            comp.scan_2.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            comp.scan_2.scan_id.unwrap_or(0)
        ));
        output.push_str(&format!("Target: {}:{}\n\n", comp.scan_1.target_hostname, comp.scan_1.target_port));

        // Summary
        output.push_str("SUMMARY\n");
        output.push_str("───────────────────────────────────────────────────────────────────\n");
        output.push_str(&format!("Total changes:        {}\n", comp.summary.total_changes));
        output.push_str(&format!("Protocol changes:     {}\n", comp.summary.protocol_changes));
        output.push_str(&format!("Cipher changes:       {}\n", comp.summary.cipher_changes));
        output.push_str(&format!("Certificate changes:  {}\n", comp.summary.certificate_changes));
        output.push_str(&format!("Vulnerability changes:{}\n", comp.summary.vulnerability_changes));
        output.push_str(&format!("Rating changes:       {}\n", comp.summary.rating_changes));
        output.push_str(&format!("Time between scans:   {} seconds\n\n", comp.summary.time_between_scans));

        // Rating comparison
        if comp.rating_diff.overall_changed {
            output.push_str("RATING CHANGES\n");
            output.push_str("───────────────────────────────────────────────────────────────────\n");
            output.push_str(&format!("Overall: {} ({}) → {} ({})\n\n",
                comp.rating_diff.scan_1_grade.as_ref().unwrap_or(&"N/A".to_string()),
                comp.rating_diff.scan_1_score.unwrap_or(0),
                comp.rating_diff.scan_2_grade.as_ref().unwrap_or(&"N/A".to_string()),
                comp.rating_diff.scan_2_score.unwrap_or(0)
            ));

            for component in &comp.rating_diff.component_diffs {
                if component.changed {
                    output.push_str(&format!("  {}: {} → {}\n",
                        component.category,
                        component.scan_1_score.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string()),
                        component.scan_2_score.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string())
                    ));
                }
            }
            output.push('\n');
        }

        // Protocol changes
        if !comp.protocol_diff.added.is_empty() || !comp.protocol_diff.removed.is_empty() {
            output.push_str("PROTOCOL CHANGES\n");
            output.push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.protocol_diff.added.is_empty() {
                output.push_str("Added:\n");
                for proto in &comp.protocol_diff.added {
                    output.push_str(&format!("  + {}\n", proto));
                }
            }
            if !comp.protocol_diff.removed.is_empty() {
                output.push_str("Removed:\n");
                for proto in &comp.protocol_diff.removed {
                    output.push_str(&format!("  - {}\n", proto));
                }
            }
            if let Some((old_pref, new_pref)) = &comp.protocol_diff.preferred_change {
                output.push_str(&format!("Preferred: {:?} → {:?}\n", old_pref, new_pref));
            }
            output.push('\n');
        }

        // Cipher changes
        if !comp.cipher_diff.added.is_empty() || !comp.cipher_diff.removed.is_empty() {
            output.push_str("CIPHER SUITE CHANGES\n");
            output.push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.cipher_diff.added.is_empty() {
                output.push_str(&format!("Added ({}):\n", comp.cipher_diff.added.len()));
                for cipher in comp.cipher_diff.added.iter().take(5) {
                    output.push_str(&format!("  + {} [{}] ({})\n", cipher.name, cipher.protocol, cipher.strength));
                }
                if comp.cipher_diff.added.len() > 5 {
                    output.push_str(&format!("  ... and {} more\n", comp.cipher_diff.added.len() - 5));
                }
            }
            if !comp.cipher_diff.removed.is_empty() {
                output.push_str(&format!("Removed ({}):\n", comp.cipher_diff.removed.len()));
                for cipher in comp.cipher_diff.removed.iter().take(5) {
                    output.push_str(&format!("  - {} [{}] ({})\n", cipher.name, cipher.protocol, cipher.strength));
                }
                if comp.cipher_diff.removed.len() > 5 {
                    output.push_str(&format!("  ... and {} more\n", comp.cipher_diff.removed.len() - 5));
                }
            }
            output.push('\n');
        }

        // Certificate changes
        if comp.certificate_diff.fingerprint_changed {
            output.push_str("CERTIFICATE CHANGES\n");
            output.push_str("───────────────────────────────────────────────────────────────────\n");
            if let Some(cert1) = &comp.certificate_diff.scan_1_cert {
                output.push_str(&format!("Old Certificate:\n"));
                output.push_str(&format!("  Subject:  {}\n", cert1.subject));
                output.push_str(&format!("  Issuer:   {}\n", cert1.issuer));
                output.push_str(&format!("  Expires:  {}\n", cert1.not_after.format("%Y-%m-%d")));
                output.push_str(&format!("  Key Size: {} bits\n", cert1.key_size.unwrap_or(0)));
            }
            if let Some(cert2) = &comp.certificate_diff.scan_2_cert {
                output.push_str(&format!("New Certificate:\n"));
                output.push_str(&format!("  Subject:  {}\n", cert2.subject));
                output.push_str(&format!("  Issuer:   {}\n", cert2.issuer));
                output.push_str(&format!("  Expires:  {}\n", cert2.not_after.format("%Y-%m-%d")));
                output.push_str(&format!("  Key Size: {} bits\n", cert2.key_size.unwrap_or(0)));
            }
            output.push('\n');
        }

        // Vulnerability changes
        if !comp.vulnerability_diff.new.is_empty() || !comp.vulnerability_diff.resolved.is_empty() {
            output.push_str("VULNERABILITY CHANGES\n");
            output.push_str("───────────────────────────────────────────────────────────────────\n");
            if !comp.vulnerability_diff.new.is_empty() {
                output.push_str("New Vulnerabilities:\n");
                for vuln in &comp.vulnerability_diff.new {
                    output.push_str(&format!("  + {} [{}]\n", vuln.vuln_type, vuln.severity));
                }
            }
            if !comp.vulnerability_diff.resolved.is_empty() {
                output.push_str("Resolved Vulnerabilities:\n");
                for vuln in &comp.vulnerability_diff.resolved {
                    output.push_str(&format!("  - {} [{}]\n", vuln.vuln_type, vuln.severity));
                }
            }
            output.push('\n');
        }

        output
    }

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

    async fn compare_protocols(&self, scan_id_1: i64, scan_id_2: i64) -> crate::Result<ProtocolDiff> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        let set1: HashSet<String> = protocols1.iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.clone())
            .collect();
        let set2: HashSet<String> = protocols2.iter()
            .filter(|p| p.enabled)
            .map(|p| p.protocol_name.clone())
            .collect();

        let added: Vec<String> = set2.difference(&set1).cloned().collect();
        let removed: Vec<String> = set1.difference(&set2).cloned().collect();
        let unchanged: Vec<String> = set1.intersection(&set2).cloned().collect();

        let pref1 = protocols1.iter().find(|p| p.preferred).map(|p| p.protocol_name.clone());
        let pref2 = protocols2.iter().find(|p| p.preferred).map(|p| p.protocol_name.clone());

        let preferred_change = if pref1 != pref2 {
            Some((pref1, pref2))
        } else {
            None
        };

        Ok(ProtocolDiff {
            added,
            removed,
            unchanged,
            preferred_change,
        })
    }

    async fn compare_ciphers(&self, scan_id_1: i64, scan_id_2: i64) -> crate::Result<CipherDiff> {
        let ciphers1 = self.get_ciphers(scan_id_1).await?;
        let ciphers2 = self.get_ciphers(scan_id_2).await?;

        let set1: HashMap<String, &CipherRecord> = ciphers1.iter()
            .map(|c| (c.cipher_name.clone(), c))
            .collect();
        let set2: HashMap<String, &CipherRecord> = ciphers2.iter()
            .map(|c| (c.cipher_name.clone(), c))
            .collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut unchanged = Vec::new();

        for (name, cipher) in &set2 {
            if !set1.contains_key(name) {
                added.push(CipherInfo {
                    name: cipher.cipher_name.clone(),
                    protocol: cipher.protocol_name.clone(),
                    strength: cipher.strength.clone(),
                    forward_secrecy: cipher.forward_secrecy,
                });
            } else {
                unchanged.push(CipherInfo {
                    name: cipher.cipher_name.clone(),
                    protocol: cipher.protocol_name.clone(),
                    strength: cipher.strength.clone(),
                    forward_secrecy: cipher.forward_secrecy,
                });
            }
        }

        for (name, cipher) in &set1 {
            if !set2.contains_key(name) {
                removed.push(CipherInfo {
                    name: cipher.cipher_name.clone(),
                    protocol: cipher.protocol_name.clone(),
                    strength: cipher.strength.clone(),
                    forward_secrecy: cipher.forward_secrecy,
                });
            }
        }

        Ok(CipherDiff {
            added,
            removed,
            unchanged,
        })
    }

    async fn compare_certificates(&self, scan_id_1: i64, scan_id_2: i64) -> crate::Result<CertificateDiff> {
        let cert1 = self.get_leaf_certificate(scan_id_1).await?;
        let cert2 = self.get_leaf_certificate(scan_id_2).await?;

        let fingerprint_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.fingerprint_sha256 != c2.fingerprint_sha256,
            (None, Some(_)) | (Some(_), None) => true,
            (None, None) => false,
        };

        let subject_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.subject != c2.subject,
            _ => false,
        };

        let issuer_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.issuer != c2.issuer,
            _ => false,
        };

        let key_size_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.public_key_size != c2.public_key_size,
            _ => false,
        };

        let expiry_changed = match (&cert1, &cert2) {
            (Some(c1), Some(c2)) => c1.not_after != c2.not_after,
            _ => false,
        };

        let scan_1_cert = cert1.map(|c| CertSummary {
            subject: c.subject,
            issuer: c.issuer,
            not_before: c.not_before,
            not_after: c.not_after,
            key_size: c.public_key_size,
            fingerprint: c.fingerprint_sha256,
        });

        let scan_2_cert = cert2.map(|c| CertSummary {
            subject: c.subject,
            issuer: c.issuer,
            not_before: c.not_before,
            not_after: c.not_after,
            key_size: c.public_key_size,
            fingerprint: c.fingerprint_sha256,
        });

        Ok(CertificateDiff {
            fingerprint_changed,
            subject_changed,
            issuer_changed,
            key_size_changed,
            expiry_changed,
            scan_1_cert,
            scan_2_cert,
        })
    }

    async fn compare_vulnerabilities(&self, scan_id_1: i64, scan_id_2: i64) -> crate::Result<VulnerabilityDiff> {
        let vulns1 = self.get_vulnerabilities(scan_id_1).await?;
        let vulns2 = self.get_vulnerabilities(scan_id_2).await?;

        let set1: HashMap<String, &VulnerabilityRecord> = vulns1.iter()
            .map(|v| (v.vulnerability_type.clone(), v))
            .collect();
        let set2: HashMap<String, &VulnerabilityRecord> = vulns2.iter()
            .map(|v| (v.vulnerability_type.clone(), v))
            .collect();

        let mut new = Vec::new();
        let mut resolved = Vec::new();
        let mut unchanged = Vec::new();

        for (vuln_type, vuln) in &set2 {
            if !set1.contains_key(vuln_type) {
                new.push(VulnInfo {
                    vuln_type: vuln.vulnerability_type.clone(),
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            } else {
                unchanged.push(VulnInfo {
                    vuln_type: vuln.vulnerability_type.clone(),
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            }
        }

        for (vuln_type, vuln) in &set1 {
            if !set2.contains_key(vuln_type) {
                resolved.push(VulnInfo {
                    vuln_type: vuln.vulnerability_type.clone(),
                    severity: vuln.severity.clone(),
                    description: vuln.description.clone(),
                });
            }
        }

        Ok(VulnerabilityDiff {
            resolved,
            new,
            unchanged,
        })
    }

    async fn compare_ratings(&self, scan_1: &ScanRecord, scan_2: &ScanRecord, scan_id_1: i64, scan_id_2: i64) -> crate::Result<RatingDiff> {
        let overall_changed = scan_1.overall_grade != scan_2.overall_grade ||
                             scan_1.overall_score != scan_2.overall_score;

        let ratings1 = self.get_ratings(scan_id_1).await?;
        let ratings2 = self.get_ratings(scan_id_2).await?;

        let mut component_diffs = Vec::new();

        let categories = vec!["certificate", "protocol", "key_exchange", "cipher"];
        for category in categories {
            let score1 = ratings1.iter()
                .find(|r| r.category == category)
                .map(|r| r.score);
            let score2 = ratings2.iter()
                .find(|r| r.category == category)
                .map(|r| r.score);

            component_diffs.push(ComponentRatingDiff {
                category: category.to_string(),
                scan_1_score: score1,
                scan_2_score: score2,
                changed: score1 != score2,
            });
        }

        Ok(RatingDiff {
            overall_changed,
            scan_1_grade: scan_1.overall_grade.clone(),
            scan_1_score: scan_1.overall_score,
            scan_2_grade: scan_2.overall_grade.clone(),
            scan_2_score: scan_2.overall_score,
            component_diffs,
        })
    }

    fn generate_summary(
        &self,
        scan_1: &ScanRecord,
        scan_2: &ScanRecord,
        protocol_diff: &ProtocolDiff,
        cipher_diff: &CipherDiff,
        certificate_diff: &CertificateDiff,
        vulnerability_diff: &VulnerabilityDiff,
        rating_diff: &RatingDiff,
    ) -> ComparisonSummary {
        let protocol_changes = protocol_diff.added.len() + protocol_diff.removed.len() +
            if protocol_diff.preferred_change.is_some() { 1 } else { 0 };
        let cipher_changes = cipher_diff.added.len() + cipher_diff.removed.len();
        let certificate_changes = if certificate_diff.fingerprint_changed { 1 } else { 0 };
        let vulnerability_changes = vulnerability_diff.new.len() + vulnerability_diff.resolved.len();
        let rating_changes = if rating_diff.overall_changed { 1 } else { 0 } +
            rating_diff.component_diffs.iter().filter(|d| d.changed).count();

        let total_changes = protocol_changes + cipher_changes + certificate_changes +
                           vulnerability_changes + rating_changes;

        let time_between_scans = (scan_2.scan_timestamp - scan_1.scan_timestamp).num_seconds();

        ComparisonSummary {
            total_changes,
            protocol_changes,
            cipher_changes,
            certificate_changes,
            vulnerability_changes,
            rating_changes,
            time_between_scans,
        }
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

    async fn get_ratings(&self, scan_id: i64) -> crate::Result<Vec<RatingRecord>> {
        match self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let ratings = sqlx::query_as::<_, RatingRecord>(
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = $1"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ratings: {}", e)))?;
                Ok(ratings)
            }
            DatabasePool::Sqlite(pool) => {
                let ratings = sqlx::query_as::<_, RatingRecord>(
                    "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = ?"
                )
                .bind(scan_id)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch ratings: {}", e)))?;
                Ok(ratings)
            }
        }
    }

    async fn get_leaf_certificate(&self, scan_id: i64) -> crate::Result<Option<CertificateRecord>> {
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
                    let san_domains: Vec<String> = serde_json::from_str(&san_json).unwrap_or_default();

                    let key_usage_json: String = row.try_get("key_usage").unwrap_or_default();
                    let key_usage: Vec<String> = serde_json::from_str(&key_usage_json).unwrap_or_default();

                    let extended_key_usage_json: String = row.try_get("extended_key_usage").unwrap_or_default();
                    let extended_key_usage: Vec<String> = serde_json::from_str(&extended_key_usage_json).unwrap_or_default();

                    Ok(Some(CertificateRecord {
                        cert_id: row.try_get("cert_id").ok(),
                        fingerprint_sha256: row.try_get("fingerprint_sha256").unwrap_or_default(),
                        subject: row.try_get("subject").unwrap_or_default(),
                        issuer: row.try_get("issuer").unwrap_or_default(),
                        serial_number: row.try_get("serial_number").ok(),
                        not_before: row.try_get("not_before").unwrap_or_else(|_| chrono::Utc::now()),
                        not_after: row.try_get("not_after").unwrap_or_else(|_| chrono::Utc::now()),
                        signature_algorithm: row.try_get("signature_algorithm").ok(),
                        public_key_algorithm: row.try_get("public_key_algorithm").ok(),
                        public_key_size: row.try_get("public_key_size").ok(),
                        san_domains,
                        is_ca: row.try_get("is_ca").unwrap_or(false),
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").ok(),
                        created_at: row.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now()),
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
    fn test_cipher_info_creation() {
        let cipher = CipherInfo {
            name: "TLS_AES_256_GCM_SHA384".to_string(),
            protocol: "TLS 1.3".to_string(),
            strength: "strong".to_string(),
            forward_secrecy: true,
        };

        assert_eq!(cipher.name, "TLS_AES_256_GCM_SHA384");
        assert!(cipher.forward_secrecy);
    }
}
