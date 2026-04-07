// Vulnerability comparison methods for ScanComparator

use super::{ScanComparator, VulnInfo, VulnerabilityDiff};
use crate::db::connection::DatabasePool;
use crate::db::VulnerabilityRecord;
use std::collections::HashMap;

impl ScanComparator {
    pub(crate) async fn compare_vulnerabilities(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<VulnerabilityDiff> {
        let vulns1 = self.get_vulnerabilities(scan_id_1).await?;
        let vulns2 = self.get_vulnerabilities(scan_id_2).await?;

        // Use compound key (type, severity) to avoid losing duplicates with different severities
        let set1: HashMap<(&str, &str), &VulnerabilityRecord> = vulns1
            .iter()
            .map(|v| ((v.vulnerability_type.as_str(), v.severity.as_str()), v))
            .collect();
        let set2: HashMap<(&str, &str), &VulnerabilityRecord> = vulns2
            .iter()
            .map(|v| ((v.vulnerability_type.as_str(), v.severity.as_str()), v))
            .collect();

        let mut new = Vec::new();
        let mut resolved = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();

        // Helper function to convert VulnerabilityRecord to VulnInfo
        let to_vuln_info = |vuln: &VulnerabilityRecord| VulnInfo {
            vuln_type: vuln.vulnerability_type.clone(), // Necessary: building owned result
            severity: vuln.severity.clone(),
            description: vuln.description.clone(),
        };

        for (key, vuln) in &set2 {
            if let Some(old_vuln) = set1.get(key) {
                // Present in both scans — check if description changed
                if vuln.description != old_vuln.description {
                    changed.push(to_vuln_info(vuln));
                } else {
                    unchanged.push(to_vuln_info(vuln));
                }
            } else {
                new.push(to_vuln_info(vuln));
            }
        }

        for (key, vuln) in &set1 {
            if !set2.contains_key(key) {
                resolved.push(to_vuln_info(vuln));
            }
        }

        Ok(VulnerabilityDiff {
            resolved,
            new,
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
