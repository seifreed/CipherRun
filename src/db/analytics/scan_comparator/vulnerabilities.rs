// Vulnerability comparison methods for ScanComparator

use super::{ScanComparator, VulnInfo, VulnerabilityDiff};
use crate::db::VulnerabilityRecord;
use crate::db::connection::DatabasePool;
use std::collections::{BTreeMap, BTreeSet};

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

fn vulnerability_sort_key(vuln: &VulnerabilityRecord) -> (String, String, String, String) {
    (
        vuln.description.clone().unwrap_or_default(),
        vuln.cve_id.clone().unwrap_or_default(),
        vuln.affected_component.clone().unwrap_or_default(),
        vuln.severity.clone(),
    )
}

fn vulnerability_match_score(old: &VulnerabilityRecord, new: &VulnerabilityRecord) -> usize {
    let mut score = 0;

    if old.description == new.description {
        score += 8;
    }
    if old.cve_id == new.cve_id {
        score += 4;
    }
    if old.affected_component == new.affected_component {
        score += 2;
    }
    if old.severity == new.severity {
        score += 1;
    }

    score
}

fn vulnerability_record_changed(old: &VulnerabilityRecord, new: &VulnerabilityRecord) -> bool {
    old.severity != new.severity
        || old.description != new.description
        || old.cve_id != new.cve_id
        || old.affected_component != new.affected_component
}

impl ScanComparator {
    pub(crate) async fn compare_vulnerabilities(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<VulnerabilityDiff> {
        let vulns1 = self.get_vulnerabilities(scan_id_1).await?;
        let vulns2 = self.get_vulnerabilities(scan_id_2).await?;

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

        let mut new_entries = Vec::new();
        let mut resolved = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();

        // Helper function to convert VulnerabilityRecord to VulnInfo
        let to_vuln_info = |vuln: &VulnerabilityRecord| VulnInfo {
            vuln_type: vuln.vulnerability_type.clone(), // Necessary: building owned result
            severity: vuln.severity.clone(),
            description: vuln.description.clone(),
        };

        let vuln_types: BTreeSet<String> = grouped1
            .keys()
            .cloned()
            .chain(grouped2.keys().cloned())
            .collect();

        for vuln_type in vuln_types {
            let mut old_vulns = grouped1.remove(&vuln_type).unwrap_or_default();
            let mut new_vulns = grouped2.remove(&vuln_type).unwrap_or_default();

            old_vulns.sort_by(|a, b| vulnerability_sort_key(a).cmp(&vulnerability_sort_key(b)));
            new_vulns.sort_by(|a, b| vulnerability_sort_key(a).cmp(&vulnerability_sort_key(b)));

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

                old_used[candidate.old_index] = true;
                new_used[candidate.new_index] = true;

                if vulnerability_record_changed(candidate.old, candidate.new) {
                    changed.push(to_vuln_info(candidate.new));
                } else {
                    unchanged.push(to_vuln_info(candidate.new));
                }
            }

            for (index, vuln) in old_vulns.iter().enumerate() {
                if !old_used[index] {
                    resolved.push(to_vuln_info(vuln));
                }
            }

            for (index, vuln) in new_vulns.iter().enumerate() {
                if !new_used[index] {
                    new_entries.push(to_vuln_info(vuln));
                }
            }
        }

        Ok(VulnerabilityDiff {
            resolved,
            new: new_entries,
            changed,
            unchanged,
        })
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
}
