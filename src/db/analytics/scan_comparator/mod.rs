// Scan Comparator
// Generates detailed side-by-side comparison of two scans

mod certificates;
mod ciphers;
mod formatter;
mod protocols;
mod ratings;
mod vulnerabilities;

use crate::db::connection::DatabasePool;
use crate::db::{CipherRunDatabase, ScanRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    pub changed: Vec<CipherChangeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    pub name: String,
    pub protocol: String,
    pub strength: String,
    pub forward_secrecy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherDetailInfo {
    pub name: String,
    pub protocol: String,
    pub key_exchange: Option<String>,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub mac: Option<String>,
    pub bits: Option<i32>,
    pub forward_secrecy: bool,
    pub strength: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherChangeInfo {
    pub previous: CipherDetailInfo,
    pub current: CipherDetailInfo,
    pub changed_fields: Vec<String>,
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
    pub changed: Vec<VulnInfo>,
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
    pub scan_1_grade: Option<String>,
    pub scan_1_rationale: Option<String>,
    pub scan_2_score: Option<i32>,
    pub scan_2_grade: Option<String>,
    pub scan_2_rationale: Option<String>,
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
    pub time_between_scans: i64, // seconds
}

pub struct ScanComparator {
    db: Arc<CipherRunDatabase>,
}

impl ScanComparator {
    pub fn new(db: Arc<CipherRunDatabase>) -> Self {
        Self { db }
    }

    /// Compare two specific scans
    pub async fn compare_scans(
        &self,
        scan_id_1: i64,
        scan_id_2: i64,
    ) -> crate::Result<ScanComparison> {
        // Get scan records
        let scan_1 = self.get_scan_by_id(scan_id_1).await?.ok_or_else(|| {
            crate::TlsError::DatabaseError(format!("Scan {} not found", scan_id_1))
        })?;
        let scan_2 = self.get_scan_by_id(scan_id_2).await?.ok_or_else(|| {
            crate::TlsError::DatabaseError(format!("Scan {} not found", scan_id_2))
        })?;

        // Compare protocols
        let protocol_diff = self.compare_protocols(scan_id_1, scan_id_2).await?;

        // Compare ciphers
        let cipher_diff = self.compare_ciphers(scan_id_1, scan_id_2).await?;

        // Compare certificates
        let certificate_diff = self.compare_certificates(scan_id_1, scan_id_2).await?;

        // Compare vulnerabilities
        let vulnerability_diff = self.compare_vulnerabilities(scan_id_1, scan_id_2).await?;

        // Compare ratings
        let rating_diff = self
            .compare_ratings(&scan_1, &scan_2, scan_id_1, scan_id_2)
            .await?;

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
        // Fetch up to 365 recent scans to find the 2 most recent regardless
        // of when they occurred, then take only the latest 2
        let scans = self.db.get_scan_history(hostname, port, 365).await?;

        if scans.len() < 2 {
            return Err(crate::TlsError::DatabaseError(
                "Not enough scans found for comparison".to_string(),
            ));
        }

        let scan_id_1 = scans[1]
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan ID missing".to_string()))?;
        let scan_id_2 = scans[0]
            .scan_id
            .ok_or_else(|| crate::TlsError::DatabaseError("Scan ID missing".to_string()))?;

        self.compare_scans(scan_id_1, scan_id_2).await
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
