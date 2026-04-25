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

    async fn detect_protocol_changes(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let protocols1 = self.get_protocols(scan_id_1).await?;
        let protocols2 = self.get_protocols(scan_id_2).await?;

        let mut changes = Vec::new();

        let protocol_names1: BTreeMap<String, String> = protocols1
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (protocol_identity(&p.protocol_name), p.protocol_name.clone()))
            .collect();

        let protocol_names2: BTreeMap<String, String> = protocols2
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (protocol_identity(&p.protocol_name), p.protocol_name.clone()))
            .collect();

        let set1: HashSet<String> = protocol_names1.keys().cloned().collect();
        let set2: HashSet<String> = protocol_names2.keys().cloned().collect();
        let diffs = detect_set_differences(&set1, &set2);

        for proto_key in &diffs.removed {
            let proto = protocol_names1
                .get(proto_key)
                .map(String::as_str)
                .unwrap_or(proto_key.as_str());
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Medium,
                description: format!("Protocol removed: {}", proto),
                previous_value: Some("enabled".to_string()),
                current_value: Some("disabled".to_string()),
                timestamp,
            });
        }

        for proto_key in &diffs.added {
            let proto = protocol_names2
                .get(proto_key)
                .map(String::as_str)
                .unwrap_or(proto_key.as_str());
            let severity = if is_ssl_protocol(proto) {
                ChangeSeverity::High
            } else if is_tls_version(proto, "1.3") {
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
            .map(|p| p.protocol_name.as_str());
        let pref2 = protocols2
            .iter()
            .find(|p| p.preferred)
            .map(|p| p.protocol_name.as_str());

        let pref1_normalized = pref1.map(protocol_identity);
        let pref2_normalized = pref2.map(protocol_identity);

        if pref1_normalized != pref2_normalized {
            changes.push(ChangeEvent {
                change_type: ChangeType::Protocol,
                severity: ChangeSeverity::Low,
                description: "Preferred protocol changed".to_string(),
                previous_value: pref1.map(str::to_string),
                current_value: pref2.map(str::to_string),
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

        let set1: BTreeMap<(String, String), &CipherRecord> = ciphers1
            .iter()
            .map(|cipher| (Self::cipher_identity(cipher), cipher))
            .collect();
        let set2: BTreeMap<(String, String), &CipherRecord> = ciphers2
            .iter()
            .map(|cipher| (Self::cipher_identity(cipher), cipher))
            .collect();

        let keys: BTreeSet<(String, String)> =
            set1.keys().cloned().chain(set2.keys().cloned()).collect();

        for key in keys {
            match (set1.get(&key), set2.get(&key)) {
                (Some(old), Some(new)) => {
                    if old.same_attributes(new) {
                        continue;
                    }

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity: Self::cipher_change_severity(old, new),
                        description: format!(
                            "Cipher changed: {} [{}]",
                            old.cipher_name.as_str(),
                            old.protocol_name.as_str()
                        ),
                        previous_value: Some(Self::cipher_detail(old)),
                        current_value: Some(Self::cipher_detail(new)),
                        timestamp,
                    });
                }
                (Some(old), None) => {
                    let severity = if Self::is_weak_cipher_strength(&old.strength) {
                        ChangeSeverity::Low
                    } else {
                        ChangeSeverity::Info
                    };

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity,
                        description: format!(
                            "Cipher removed: {} [{}]",
                            old.cipher_name.as_str(),
                            old.protocol_name.as_str()
                        ),
                        previous_value: Some(Self::cipher_detail(old)),
                        current_value: None,
                        timestamp,
                    });
                }
                (None, Some(new)) => {
                    let severity = match Self::cipher_strength_rank(&new.strength) {
                        0 => ChangeSeverity::High,
                        1 => ChangeSeverity::Medium,
                        _ => ChangeSeverity::Info,
                    };

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Cipher,
                        severity,
                        description: format!(
                            "Cipher added: {} [{}]",
                            new.cipher_name.as_str(),
                            new.protocol_name.as_str()
                        ),
                        previous_value: None,
                        current_value: Some(Self::cipher_detail(new)),
                        timestamp,
                    });
                }
                (None, None) => unreachable!("cipher identity set should cover both sides"),
            }
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

        let mut grouped1: BTreeMap<String, Vec<&VulnerabilityRecord>> = BTreeMap::new();
        let mut grouped2: BTreeMap<String, Vec<&VulnerabilityRecord>> = BTreeMap::new();

        for vuln in &vulns1 {
            grouped1
                .entry(vuln.vulnerability_type.clone())
                .or_default()
                .push(vuln);
        }
        for vuln in &vulns2 {
            grouped2
                .entry(vuln.vulnerability_type.clone())
                .or_default()
                .push(vuln);
        }

        let vuln_types: BTreeSet<String> = grouped1
            .keys()
            .cloned()
            .chain(grouped2.keys().cloned())
            .collect();

        for vuln_type in vuln_types {
            let mut old_vulns = grouped1.remove(&vuln_type).unwrap_or_default();
            let mut new_vulns = grouped2.remove(&vuln_type).unwrap_or_default();
            let allow_zero_score_pairing =
                allows_ambiguous_zero_score_pairing(old_vulns.len(), new_vulns.len());

            old_vulns.sort_by_key(vulnerability_sort_key);
            new_vulns.sort_by_key(vulnerability_sort_key);

            let mut candidates = Vec::new();
            for (old_index, old_vuln) in old_vulns.iter().enumerate() {
                for (new_index, new_vuln) in new_vulns.iter().enumerate() {
                    candidates.push(VulnerabilityPairCandidate {
                        score: vulnerability_match_score(old_vuln, new_vuln),
                        old_index,
                        new_index,
                        old_key: vulnerability_sort_key(old_vuln),
                        new_key: vulnerability_sort_key(new_vuln),
                        old: old_vuln,
                        new: new_vuln,
                    });
                }
            }

            candidates.sort_by(|a, b| {
                b.score
                    .cmp(&a.score)
                    .then_with(|| a.old_key.cmp(&b.old_key))
                    .then_with(|| a.new_key.cmp(&b.new_key))
                    .then_with(|| a.old_index.cmp(&b.old_index))
                    .then_with(|| a.new_index.cmp(&b.new_index))
            });

            let mut old_used = vec![false; old_vulns.len()];
            let mut new_used = vec![false; new_vulns.len()];

            for candidate in candidates {
                if old_used[candidate.old_index] || new_used[candidate.new_index] {
                    continue;
                }
                if candidate.score == 0 && !allow_zero_score_pairing {
                    continue;
                }

                old_used[candidate.old_index] = true;
                new_used[candidate.new_index] = true;

                if vulnerability_record_changed(candidate.old, candidate.new) {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity: Self::vulnerability_change_severity(candidate.old, candidate.new),
                        description: format!("Vulnerability changed: {}", vuln_type),
                        previous_value: Some(Self::vulnerability_detail(candidate.old)),
                        current_value: Some(Self::vulnerability_detail(candidate.new)),
                        timestamp,
                    });
                }
            }

            for (index, vuln) in old_vulns.iter().enumerate() {
                if !old_used[index] {
                    let severity = Self::vuln_severity_to_change_severity(&vuln.severity);

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity,
                        description: format!("Vulnerability resolved: {}", vuln_type),
                        previous_value: Some(Self::vulnerability_detail(vuln)),
                        current_value: Some("resolved".to_string()),
                        timestamp,
                    });
                }
            }

            for (index, vuln) in new_vulns.iter().enumerate() {
                if !new_used[index] {
                    let severity = Self::vuln_severity_to_change_severity(&vuln.severity);

                    changes.push(ChangeEvent {
                        change_type: ChangeType::Vulnerability,
                        severity,
                        description: format!("New vulnerability detected: {}", vuln_type),
                        previous_value: None,
                        current_value: Some(Self::vulnerability_detail(vuln)),
                        timestamp,
                    });
                }
            }
        }

        Ok(changes)
    }

    fn vuln_severity_to_change_severity(severity: &str) -> ChangeSeverity {
        match severity.to_ascii_lowercase().as_str() {
            "critical" => ChangeSeverity::Critical,
            "high" => ChangeSeverity::High,
            "medium" => ChangeSeverity::Medium,
            "low" => ChangeSeverity::Low,
            _ => ChangeSeverity::Info,
        }
    }

    fn vulnerability_change_severity(
        old: &VulnerabilityRecord,
        new: &VulnerabilityRecord,
    ) -> ChangeSeverity {
        std::cmp::max(
            Self::vuln_severity_to_change_severity(&old.severity),
            Self::vuln_severity_to_change_severity(&new.severity),
        )
    }

    fn vulnerability_detail(vuln: &VulnerabilityRecord) -> String {
        let mut details = vec![format!("severity={}", vuln.severity)];

        if let Some(description) = &vuln.description {
            details.push(format!("description={}", description));
        }
        if let Some(cve) = &vuln.cve_id {
            details.push(format!("cve={}", cve));
        }
        if let Some(component) = &vuln.affected_component {
            details.push(format!("component={}", component));
        }

        details.join(", ")
    }

    fn cipher_identity(cipher: &CipherRecord) -> (String, String) {
        (
            protocol_identity(&cipher.protocol_name),
            cipher.cipher_name.clone(),
        )
    }

    fn is_weak_cipher_strength(strength: &str) -> bool {
        matches!(
            strength.to_ascii_lowercase().as_str(),
            "weak" | "low" | "export" | "null"
        )
    }

    fn cipher_strength_rank(strength: &str) -> i32 {
        match strength.to_ascii_lowercase().as_str() {
            "weak" | "low" | "export" | "null" => 0,
            "medium" => 1,
            "strong" | "high" => 2,
            _ => 1,
        }
    }

    fn cipher_change_severity(old: &CipherRecord, new: &CipherRecord) -> ChangeSeverity {
        let mut severity = ChangeSeverity::Info;

        if old.strength != new.strength {
            let strength_severity = match (
                Self::cipher_strength_rank(&old.strength),
                Self::cipher_strength_rank(&new.strength),
            ) {
                (old_rank, new_rank) if new_rank < old_rank => ChangeSeverity::High,
                (old_rank, new_rank) if new_rank > old_rank => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };
            severity = severity.max(strength_severity);
        }

        if old.bits != new.bits {
            let bit_severity = match (old.bits, new.bits) {
                (Some(old_bits), Some(new_bits)) if new_bits < old_bits => ChangeSeverity::High,
                (Some(old_bits), Some(new_bits)) if new_bits > old_bits => ChangeSeverity::Low,
                _ => ChangeSeverity::Medium,
            };
            severity = severity.max(bit_severity);
        }

        if old.forward_secrecy != new.forward_secrecy {
            let fs_severity = if old.forward_secrecy && !new.forward_secrecy {
                ChangeSeverity::High
            } else {
                ChangeSeverity::Low
            };
            severity = severity.max(fs_severity);
        }

        if old.key_exchange != new.key_exchange
            || old.authentication != new.authentication
            || old.encryption != new.encryption
            || old.mac != new.mac
        {
            severity = severity.max(ChangeSeverity::Medium);
        }

        severity
    }

    fn cipher_detail(cipher: &CipherRecord) -> String {
        format!(
            "protocol={}, cipher={}, key_exchange={}, authentication={}, encryption={}, mac={}, bits={}, forward_secrecy={}, strength={}",
            cipher.protocol_name.as_str(),
            cipher.cipher_name.as_str(),
            cipher.key_exchange.as_deref().unwrap_or("N/A"),
            cipher.authentication.as_deref().unwrap_or("N/A"),
            cipher.encryption.as_deref().unwrap_or("N/A"),
            cipher.mac.as_deref().unwrap_or("N/A"),
            cipher
                .bits
                .map(|bits| bits.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            cipher.forward_secrecy,
            cipher.strength
        )
    }

    fn rating_category_rank(category: &str) -> usize {
        match category {
            "certificate" => 0,
            "protocol" => 1,
            "key_exchange" => 2,
            "cipher" => 3,
            _ => 4,
        }
    }

    fn rating_detail(rating: &RatingRecord) -> String {
        let mut details = vec![
            format!("score={}", rating.score),
            format!("grade={}", rating.grade.as_deref().unwrap_or("N/A")),
        ];

        if let Some(rationale) = &rating.rationale {
            details.push(format!("rationale={}", rationale));
        }

        details.join(", ")
    }

    fn rating_change_severity(old: &RatingRecord, new: &RatingRecord) -> ChangeSeverity {
        match new.score.cmp(&old.score) {
            std::cmp::Ordering::Less => ChangeSeverity::High,
            std::cmp::Ordering::Greater => ChangeSeverity::Low,
            std::cmp::Ordering::Equal => {
                if old.grade != new.grade || old.rationale != new.rationale {
                    ChangeSeverity::Medium
                } else {
                    ChangeSeverity::Info
                }
            }
        }
    }

    async fn detect_rating_changes(
        &self,
        scan1: &ScanRecord,
        scan2: &ScanRecord,
        timestamp: DateTime<Utc>,
    ) -> crate::Result<Vec<ChangeEvent>> {
        let mut changes = Vec::new();

        let scan1_id = scan1
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 1 missing scan_id".to_string()))?;
        let scan2_id = scan2
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan 2 missing scan_id".to_string()))?;

        let ratings1 = self.get_ratings(scan1_id).await?;
        let ratings2 = self.get_ratings(scan2_id).await?;

        let ratings1_by_category: std::collections::BTreeMap<String, RatingRecord> = ratings1
            .into_iter()
            .map(|rating| (rating.category.clone(), rating))
            .collect();
        let ratings2_by_category: std::collections::BTreeMap<String, RatingRecord> = ratings2
            .into_iter()
            .map(|rating| (rating.category.clone(), rating))
            .collect();

        let mut categories: Vec<String> = ratings1_by_category
            .keys()
            .cloned()
            .chain(ratings2_by_category.keys().cloned())
            .collect();
        categories.sort_by(|a, b| {
            Self::rating_category_rank(a)
                .cmp(&Self::rating_category_rank(b))
                .then_with(|| a.cmp(b))
        });
        categories.dedup();

        for category in categories {
            match (
                ratings1_by_category.get(&category),
                ratings2_by_category.get(&category),
            ) {
                (Some(old), Some(new))
                    if old.score != new.score
                        || old.grade != new.grade
                        || old.rationale != new.rationale =>
                {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: Self::rating_change_severity(old, new),
                        description: format!("Rating changed: {}", category),
                        previous_value: Some(Self::rating_detail(old)),
                        current_value: Some(Self::rating_detail(new)),
                        timestamp,
                    });
                }
                (Some(old), None) => {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: ChangeSeverity::Medium,
                        description: format!("Rating removed: {}", category),
                        previous_value: Some(Self::rating_detail(old)),
                        current_value: None,
                        timestamp,
                    });
                }
                (None, Some(new)) => {
                    changes.push(ChangeEvent {
                        change_type: ChangeType::Rating,
                        severity: ChangeSeverity::Medium,
                        description: format!("Rating added: {}", category),
                        previous_value: None,
                        current_value: Some(Self::rating_detail(new)),
                        timestamp,
                    });
                }
                (Some(_), Some(_)) | (None, None) => {}
            }
        }

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
                    let san_json: Option<String> = row.try_get("san_domains").ok();
                    let san_domains = CertificateRecord::parse_json_text_array(
                        san_json.as_deref(),
                        "san_domains",
                    )?;

                    let key_usage_json: Option<String> = row.try_get("key_usage").ok();
                    let key_usage = CertificateRecord::parse_json_text_array(
                        key_usage_json.as_deref(),
                        "key_usage",
                    )?;

                    let extended_key_usage_json: Option<String> =
                        row.try_get("extended_key_usage").ok();
                    let extended_key_usage = CertificateRecord::parse_json_text_array(
                        extended_key_usage_json.as_deref(),
                        "extended_key_usage",
                    )?;

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
