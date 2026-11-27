// Change Tracker
// Detects and reports changes between consecutive scans

use crate::db::analytics::protocol_identity::{is_ssl_protocol, is_tls_version, protocol_identity};
use crate::db::analytics::vulnerability_matching::{
    allows_ambiguous_zero_score_pairing, vulnerability_match_score, vulnerability_record_changed,
    vulnerability_sort_key,
};
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
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "change_tracker.detect")
    )]
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

        // Compare consecutive scans
        let mut all_changes = Vec::new();
        for scan_pair in scans.windows(2) {
            let [newer_scan, older_scan] = scan_pair else {
                continue;
            };

            if let (Some(newer_id), Some(older_id)) = (newer_scan.scan_id, older_scan.scan_id) {
                let mut changes = self.detect_changes_between(older_id, newer_id).await?;
                all_changes.append(&mut changes);
            }
        }

        sort_change_events(&mut all_changes);
        Ok(all_changes)
    }

    /// Detect changes between two specific scans
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "change_tracker.compare"
        )
    )]
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
            "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id FROM scans WHERE scan_id = $1",
            "SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id FROM scans WHERE scan_id = ?",
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
                        cert_id: row.try_get("cert_id").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field cert_id: {}",
                                e
                            ))
                        })?,
                        fingerprint_sha256,
                        subject,
                        issuer,
                        serial_number: row.try_get("serial_number").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field serial_number: {}",
                                e
                            ))
                        })?,
                        not_before,
                        not_after,
                        signature_algorithm: row.try_get("signature_algorithm").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field signature_algorithm: {}",
                                e
                            ))
                        })?,
                        public_key_algorithm: row.try_get("public_key_algorithm").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field public_key_algorithm: {}",
                                e
                            ))
                        })?,
                        public_key_size: row.try_get("public_key_size").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field public_key_size: {}",
                                e
                            ))
                        })?,
                        san_domains,
                        is_ca,
                        key_usage,
                        extended_key_usage,
                        der_bytes: row.try_get("der_bytes").map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Invalid certificate field der_bytes: {}",
                                e
                            ))
                        })?,
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

    #[test]
    fn test_tls_version_matching_is_exact_after_normalization() {
        assert!(is_tls_version("TLS 1.3", "1.3"));
        assert!(is_tls_version("TLSv1.3", "1.3"));
        assert!(!is_tls_version("TLS 1.30", "1.3"));
        assert!(!is_tls_version("TLS 1.20", "1.2"));
    }

    #[test]
    fn test_ssl_protocol_matching_is_exact_after_normalization() {
        assert!(is_ssl_protocol("SSLv3"));
        assert!(is_ssl_protocol("SSL 3.0"));
        assert!(!is_ssl_protocol("SSLv300"));
        assert!(!is_ssl_protocol("not-SSLv3"));
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

    #[tokio::test]
    async fn test_generate_change_report_groups_and_sorts_all_event_kinds() {
        let db = Arc::new(
            CipherRunDatabase::new(&crate::db::DatabaseConfig::sqlite(
                std::path::PathBuf::from(":memory:"),
            ))
            .await
            .unwrap(),
        );
        let tracker = ChangeTracker::new(db);
        let timestamp = Utc::now();
        let event = |change_type: ChangeType,
                     severity: ChangeSeverity,
                     description: &str,
                     previous_value: Option<&str>,
                     current_value: Option<&str>| ChangeEvent {
            change_type,
            severity,
            description: description.to_string(),
            previous_value: previous_value.map(str::to_string),
            current_value: current_value.map(str::to_string),
            timestamp,
        };
        let changes = vec![
            event(
                ChangeType::Rating,
                ChangeSeverity::Info,
                "z-last",
                Some("old-z"),
                Some("new-z"),
            ),
            event(
                ChangeType::Vulnerability,
                ChangeSeverity::Low,
                "vulnerability",
                None,
                None,
            ),
            event(
                ChangeType::Certificate,
                ChangeSeverity::Medium,
                "certificate",
                Some("old-cert"),
                None,
            ),
            event(
                ChangeType::Cipher,
                ChangeSeverity::High,
                "cipher",
                None,
                Some("new-cipher"),
            ),
            event(
                ChangeType::Protocol,
                ChangeSeverity::Critical,
                "protocol",
                Some("disabled"),
                Some("enabled"),
            ),
            event(
                ChangeType::Rating,
                ChangeSeverity::Info,
                "a-first",
                Some("old-a"),
                Some("new-a"),
            ),
        ];

        let report = tracker.generate_change_report(&changes);
        let headings: Vec<_> = report
            .lines()
            .filter(|line| line.ends_with("Changes (1)") || line.ends_with("Changes (2)"))
            .collect();
        assert_eq!(
            headings,
            [
                "Protocol Changes (1)",
                "Cipher Changes (1)",
                "Certificate Changes (1)",
                "Vulnerability Changes (1)",
                "Rating Changes (2)",
            ]
        );
        assert!(report.contains("[CRITICAL] protocol"));
        assert!(report.contains("[HIGH]     cipher"));
        assert!(report.contains("Previous: disabled"));
        assert!(report.contains("Current:  new-cipher"));
        assert!(report.find("a-first").unwrap() < report.find("z-last").unwrap());
    }

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn detect_changes_between_reads_all_postgres_change_sources() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Ok(url) = std::env::var("CIPHERRUN_TEST_POSTGRES_URL") else {
            return;
        };
        let admin = PgPoolOptions::new()
            .connect_with(PgConnectOptions::from_str(&url).expect("test URL should be valid"))
            .await
            .expect("test PostgreSQL should accept connections");
        let schema = format!("cipherrun_change_tracker_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("test schema should be created");

        let options = PgConnectOptions::from_str(&url)
            .expect("test URL should be valid")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test PostgreSQL schema should accept connections");
        for ddl in [
            "CREATE TABLE scans (scan_id BIGINT PRIMARY KEY, target_hostname TEXT NOT NULL, target_port INTEGER NOT NULL, scan_timestamp TIMESTAMPTZ NOT NULL, overall_grade TEXT, overall_score INTEGER, scan_duration_ms BIGINT, revocation_json TEXT, scanner_version TEXT, principal_id TEXT, tenant_id TEXT, created_by_key_id TEXT)",
            "CREATE TABLE protocols (protocol_id BIGINT PRIMARY KEY, scan_id BIGINT NOT NULL, protocol_name TEXT NOT NULL, enabled BOOLEAN NOT NULL, preferred BOOLEAN NOT NULL)",
            "CREATE TABLE cipher_suites (cipher_id BIGINT PRIMARY KEY, scan_id BIGINT NOT NULL, protocol_name TEXT NOT NULL, cipher_name TEXT NOT NULL, key_exchange TEXT, authentication TEXT, encryption TEXT, mac TEXT, bits INTEGER, forward_secrecy BOOLEAN NOT NULL, strength TEXT NOT NULL)",
            "CREATE TABLE certificates (cert_id BIGINT PRIMARY KEY, fingerprint_sha256 TEXT NOT NULL, subject TEXT NOT NULL, issuer TEXT NOT NULL, serial_number TEXT, not_before TIMESTAMPTZ NOT NULL, not_after TIMESTAMPTZ NOT NULL, signature_algorithm TEXT, public_key_algorithm TEXT, public_key_size INTEGER, san_domains TEXT[], is_ca BOOLEAN NOT NULL, key_usage TEXT[], extended_key_usage TEXT[], der_bytes BYTEA, created_at TIMESTAMPTZ NOT NULL)",
            "CREATE TABLE scan_certificates (id BIGINT PRIMARY KEY, scan_id BIGINT NOT NULL, cert_id BIGINT NOT NULL, chain_position INTEGER NOT NULL)",
            "CREATE TABLE vulnerabilities (vuln_id BIGINT PRIMARY KEY, scan_id BIGINT NOT NULL, vulnerability_type TEXT NOT NULL, severity TEXT NOT NULL, description TEXT, cve_id TEXT, affected_component TEXT)",
            "CREATE TABLE ratings (rating_id BIGINT PRIMARY KEY, scan_id BIGINT NOT NULL, category TEXT NOT NULL, score INTEGER NOT NULL, grade TEXT, rationale TEXT)",
        ] {
            sqlx::query(ddl)
                .execute(&pool)
                .await
                .expect("change-tracker table should be created");
        }
        for scan_id in [1_i64, 2] {
            sqlx::query(
                "INSERT INTO scans (scan_id, target_hostname, target_port, scan_timestamp) \
                 VALUES ($1, 'example.test', 443, $2)",
            )
            .bind(scan_id)
            .bind(Utc::now())
            .execute(&pool)
            .await
            .expect("scan should be inserted");
        }

        let database = Arc::new(CipherRunDatabase::from_pool(DatabasePool::Postgres(
            pool.clone(),
        )));
        let tracker = ChangeTracker::new(database);
        assert!(
            tracker
                .get_leaf_certificate(1)
                .await
                .expect("missing leaf certificate should be a successful empty lookup")
                .is_none()
        );

        let now = Utc::now();
        sqlx::query(
            "INSERT INTO certificates \
             (cert_id, fingerprint_sha256, subject, issuer, not_before, not_after, san_domains, \
              is_ca, key_usage, extended_key_usage, der_bytes, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(101_i64)
        .bind("leaf-fingerprint")
        .bind("CN=example.test")
        .bind("CN=Example CA")
        .bind(now)
        .bind(now + chrono::Duration::days(1))
        .bind(vec!["example.test".to_string()])
        .bind(false)
        .bind(vec!["digitalSignature".to_string()])
        .bind(vec!["serverAuth".to_string()])
        .bind(vec![0x30_u8, 0x00])
        .bind(now)
        .execute(&pool)
        .await
        .expect("leaf certificate should be inserted");
        sqlx::query(
            "INSERT INTO scan_certificates (id, scan_id, cert_id, chain_position) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(1_i64)
        .bind(1_i64)
        .bind(101_i64)
        .bind(0_i32)
        .execute(&pool)
        .await
        .expect("leaf certificate should be linked to its scan");
        sqlx::query(
            "INSERT INTO scan_certificates (id, scan_id, cert_id, chain_position) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(2_i64)
        .bind(2_i64)
        .bind(101_i64)
        .bind(0_i32)
        .execute(&pool)
        .await
        .expect("same certificate should be linked to the comparison scan");

        let certificate = tracker
            .get_leaf_certificate(1)
            .await
            .expect("leaf certificate should be readable")
            .expect("linked leaf certificate should be found");
        assert_eq!(certificate.cert_id, Some(101));
        assert_eq!(certificate.fingerprint_sha256, "leaf-fingerprint");
        assert_eq!(certificate.san_domains, ["example.test"]);
        assert_eq!(certificate.key_usage, ["digitalSignature"]);
        assert_eq!(certificate.extended_key_usage, ["serverAuth"]);

        let changes = tracker
            .detect_changes_between(1, 2)
            .await
            .expect("all PostgreSQL change sources should be readable");
        assert!(changes.is_empty());

        drop(pool);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
    }
}
