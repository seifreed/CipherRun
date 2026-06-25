// Change Tracker
// Detects and reports changes between consecutive scans

use crate::db::connection::DatabasePool;
use crate::db::{
    CipherRecord, CipherRunDatabase, ProtocolRecord, RatingRecord, ScanRecord, VulnerabilityRecord,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;
use std::sync::Arc;

macro_rules! dual_query_fetch_all {
    ($self:expr, $pg_query:expr, $sqlite_query:expr, $err_msg:expr, $( $bind:expr ),* ) => {{
        match $self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let q = sqlx::query_as($pg_query);
                $( let q = q.bind($bind); )*
                q.fetch_all(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("{}: {}", $err_msg, e)))
            }
            DatabasePool::Sqlite(pool) => {
                let q = sqlx::query_as($sqlite_query);
                $( let q = q.bind($bind); )*
                q.fetch_all(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("{}: {}", $err_msg, e)))
            }
        }
    }};
}

macro_rules! dual_query_fetch_optional {
    ($self:expr, $pg_query:expr, $sqlite_query:expr, $err_msg:expr, $( $bind:expr ),* ) => {{
        match $self.db.pool() {
            DatabasePool::Postgres(pool) => {
                let q = sqlx::query_as($pg_query);
                $( let q = q.bind($bind); )*
                q.fetch_optional(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("{}: {}", $err_msg, e)))
            }
            DatabasePool::Sqlite(pool) => {
                let q = sqlx::query_as($sqlite_query);
                $( let q = q.bind($bind); )*
                q.fetch_optional(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("{}: {}", $err_msg, e)))
            }
        }
    }};
}

mod certificates;
mod ciphers;
mod protocols;
mod ratings;
mod vulnerabilities;

struct SetDifferences<T> {
    removed: Vec<T>,
    added: Vec<T>,
}

#[derive(Debug)]
struct VulnerabilityPairCandidate<'a> {
    score: usize,
    old_index: usize,
    new_index: usize,
    old_key: (String, String, String, String),
    new_key: (String, String, String, String),
    old: &'a VulnerabilityRecord,
    new: &'a VulnerabilityRecord,
}

fn detect_set_differences<T: Eq + Hash + Clone>(
    old: &HashSet<T>,
    new: &HashSet<T>,
) -> SetDifferences<T> {
    SetDifferences {
        removed: old.difference(new).cloned().collect(),
        added: new.difference(old).cloned().collect(),
    }
}

fn normalized_protocol_name(protocol: &str) -> String {
    protocol
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn protocol_identity(protocol: &str) -> String {
    let normalized = normalized_protocol_name(protocol);
    if let Some(version) = normalized.strip_prefix("TLSV") {
        format!("TLS{}", version)
    } else if let Some(version) = normalized.strip_prefix("SSLV") {
        format!("SSL{}", version)
    } else {
        normalized
    }
}

fn is_tls_version(protocol: &str, version: &str) -> bool {
    let normalized = protocol_identity(protocol);
    normalized.contains(&format!("TLS{}", version))
}

fn is_ssl_protocol(protocol: &str) -> bool {
    let normalized = protocol_identity(protocol);
    normalized.starts_with("SSL")
}

fn vulnerability_sort_key(vuln: &&VulnerabilityRecord) -> (String, String, String, String) {
    (
        vuln.description.clone().unwrap_or_default(),
        vuln.cve_id.clone().unwrap_or_default(),
        vuln.affected_component.clone().unwrap_or_default(),
        vuln.severity.clone(),
    )
}

fn vulnerability_match_score(old: &VulnerabilityRecord, new: &VulnerabilityRecord) -> usize {
    let mut score = 0;

    if matches!((&old.description, &new.description), (Some(old_desc), Some(new_desc)) if old_desc == new_desc)
    {
        score += 8;
    }
    if matches!((&old.cve_id, &new.cve_id), (Some(old_cve), Some(new_cve)) if old_cve == new_cve) {
        score += 4;
    }
    if matches!(
        (&old.affected_component, &new.affected_component),
        (Some(old_component), Some(new_component)) if old_component == new_component
    ) {
        score += 2;
    }

    score
}

fn allows_ambiguous_zero_score_pairing(old_count: usize, new_count: usize) -> bool {
    old_count == 1 && new_count == 1
}

fn vulnerability_record_changed(old: &VulnerabilityRecord, new: &VulnerabilityRecord) -> bool {
    old.severity != new.severity
        || old.description != new.description
        || old.cve_id != new.cve_id
        || old.affected_component != new.affected_component
}

fn change_type_rank(change_type: &ChangeType) -> usize {
    match change_type {
        ChangeType::Protocol => 0,
        ChangeType::Cipher => 1,
        ChangeType::Certificate => 2,
        ChangeType::Vulnerability => 3,
        ChangeType::Rating => 4,
    }
}

fn change_type_label(change_type: &ChangeType) -> &'static str {
    match change_type {
        ChangeType::Protocol => "Protocol",
        ChangeType::Cipher => "Cipher",
        ChangeType::Certificate => "Certificate",
        ChangeType::Vulnerability => "Vulnerability",
        ChangeType::Rating => "Rating",
    }
}

fn change_severity_rank(severity: &ChangeSeverity) -> usize {
    match severity {
        ChangeSeverity::Critical => 0,
        ChangeSeverity::High => 1,
        ChangeSeverity::Medium => 2,
        ChangeSeverity::Low => 3,
        ChangeSeverity::Info => 4,
    }
}

fn compare_change_events(a: &ChangeEvent, b: &ChangeEvent) -> Ordering {
    change_type_rank(&a.change_type)
        .cmp(&change_type_rank(&b.change_type))
        .then_with(|| change_severity_rank(&a.severity).cmp(&change_severity_rank(&b.severity)))
        .then_with(|| a.timestamp.cmp(&b.timestamp))
        .then_with(|| a.description.cmp(&b.description))
        .then_with(|| a.previous_value.cmp(&b.previous_value))
        .then_with(|| a.current_value.cmp(&b.current_value))
}

fn sort_change_events(events: &mut [ChangeEvent]) {
    events.sort_by(compare_change_events);
}

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

    /// Detect changes for a hostname across the last N scans
    pub async fn detect_changes(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let scans = self.db.get_scan_history(hostname, port, limit).await?;

        // Need at least 2 scans to compare
        if scans.len() < 2 {
            return Ok(Vec::new());
        }

        // Compare consecutive scans (use saturating_sub to prevent underflow)
        let mut all_changes = Vec::new();
        for i in 0..scans.len().saturating_sub(1) {
            let newer_scan = &scans[i];
            let older_scan = &scans[i + 1];

            if let (Some(newer_id), Some(older_id)) = (newer_scan.scan_id, older_scan.scan_id) {
                let mut changes = self.detect_changes_between(older_id, newer_id).await?;
                all_changes.append(&mut changes);
            }
        }

        sort_change_events(&mut all_changes);
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

        sort_change_events(&mut changes);
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
        let mut by_type: BTreeMap<usize, (&'static str, Vec<&ChangeEvent>)> = BTreeMap::new();
        for change in changes {
            let type_rank = change_type_rank(&change.change_type);
            let type_label = change_type_label(&change.change_type);
            by_type
                .entry(type_rank)
                .or_insert_with(|| (type_label, Vec::new()))
                .1
                .push(change);
        }

        for (_, (change_type, mut events)) in by_type {
            events.sort_by(|a, b| compare_change_events(a, b));
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
        Ok(dual_query_fetch_optional!(
            self,
            "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version FROM scans WHERE scan_id = $1",
            "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version FROM scans WHERE scan_id = ?",
            "Failed to fetch scan",
            scan_id
        )?)
    }

    async fn get_protocols(&self, scan_id: i64) -> crate::Result<Vec<ProtocolRecord>> {
        Ok(dual_query_fetch_all!(
            self,
            "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = $1",
            "SELECT protocol_id, scan_id, protocol_name, enabled, preferred FROM protocols WHERE scan_id = ?",
            "Failed to fetch protocols",
            scan_id
        )?)
    }

    async fn get_ciphers(&self, scan_id: i64) -> crate::Result<Vec<CipherRecord>> {
        Ok(dual_query_fetch_all!(
            self,
            "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = $1",
            "SELECT cipher_id, scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength FROM cipher_suites WHERE scan_id = ?",
            "Failed to fetch ciphers",
            scan_id
        )?)
    }

    async fn get_ratings(&self, scan_id: i64) -> crate::Result<Vec<RatingRecord>> {
        Ok(dual_query_fetch_all!(
            self,
            "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = $1 ORDER BY category ASC, rating_id ASC",
            "SELECT rating_id, scan_id, category, score, grade, rationale FROM ratings WHERE scan_id = ? ORDER BY category ASC, rating_id ASC",
            "Failed to fetch ratings",
            scan_id
        )?)
    }

    async fn get_vulnerabilities(&self, scan_id: i64) -> crate::Result<Vec<VulnerabilityRecord>> {
        Ok(dual_query_fetch_all!(
            self,
            "SELECT vuln_id, scan_id, vulnerability_type, severity, description, cve_id, affected_component FROM vulnerabilities WHERE scan_id = $1",
            "SELECT vuln_id, scan_id, vulnerability_type, severity, description, cve_id, affected_component FROM vulnerabilities WHERE scan_id = ?",
            "Failed to fetch vulnerabilities",
            scan_id
        )?)
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
                    let fingerprint_sha256 = row.try_get("fingerprint_sha256").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field fingerprint_sha256: {}",
                            e
                        ))
                    })?;
                    let subject = row.try_get("subject").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field subject: {}",
                            e
                        ))
                    })?;
                    let issuer = row.try_get("issuer").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field issuer: {}",
                            e
                        ))
                    })?;
                    let not_before = row.try_get("not_before").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field not_before: {}",
                            e
                        ))
                    })?;
                    let not_after = row.try_get("not_after").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field not_after: {}",
                            e
                        ))
                    })?;
                    let is_ca = row.try_get("is_ca").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field is_ca: {}",
                            e
                        ))
                    })?;
                    let created_at = row.try_get("created_at").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field created_at: {}",
                            e
                        ))
                    })?;

                    let san_json: Option<String> = row.try_get("san_domains").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field san_domains: {}",
                            e
                        ))
                    })?;
                    let san_domains = CertificateRecord::parse_json_text_array(
                        san_json.as_deref(),
                        "san_domains",
                    )?;

                    let key_usage_json: Option<String> = row.try_get("key_usage").map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "Invalid certificate field key_usage: {}",
                            e
                        ))
                    })?;
                    let key_usage = CertificateRecord::parse_json_text_array(
                        key_usage_json.as_deref(),
                        "key_usage",
                    )?;

                    let extended_key_usage_json: Option<String> =
                        row.try_get("extended_key_usage").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field extended_key_usage: {}",
                                e
                            ))
                        })?;
                    let extended_key_usage = CertificateRecord::parse_json_text_array(
                        extended_key_usage_json.as_deref(),
                        "extended_key_usage",
                    )?;

                    Ok(Some(CertificateRecord {
                        cert_id: row.try_get("cert_id").ok(),
                        fingerprint_sha256,
                        subject,
                        issuer,
                        serial_number: row.try_get("serial_number").ok(),
                        not_before,
                        not_after,
                        signature_algorithm: row.try_get("signature_algorithm").ok(),
                        public_key_algorithm: row.try_get("public_key_algorithm").ok(),
                        public_key_size: row.try_get("public_key_size").ok(),
                        san_domains,
                        is_ca,
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").ok(),
                        created_at,
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
