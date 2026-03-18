// Database Traits
// Defines repository interfaces for database operations

use crate::db::models::*;
use async_trait::async_trait;

/// Scan repository trait
#[async_trait]
pub trait ScanRepository: Send + Sync {
    /// Create a new scan record and return its ID
    async fn create_scan(&self, scan: &ScanRecord) -> crate::Result<i64>;

    /// Get scan by ID
    async fn get_scan_by_id(&self, scan_id: i64) -> crate::Result<Option<ScanRecord>>;

    /// Get scans for a specific hostname and port, ordered by timestamp descending
    async fn get_scans_by_hostname(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ScanRecord>>;

    /// Get the latest scan for a hostname and port
    async fn get_latest_scan(&self, hostname: &str, port: u16)
    -> crate::Result<Option<ScanRecord>>;

    /// Delete scans older than the specified number of days
    async fn delete_old_scans(&self, days: i64) -> crate::Result<u64>;

    /// Update scan with rating information
    async fn update_scan_rating(&self, scan_id: i64, grade: &str, score: u8) -> crate::Result<()>;
}

/// Protocol repository trait
#[async_trait]
pub trait ProtocolRepository: Send + Sync {
    /// Create a new protocol record
    async fn create_protocol(&self, protocol: &ProtocolRecord) -> crate::Result<i64>;

    /// Get all protocols for a scan
    async fn get_protocols_by_scan(&self, scan_id: i64) -> crate::Result<Vec<ProtocolRecord>>;

    /// Bulk insert protocols
    async fn create_protocols_bulk(&self, protocols: &[ProtocolRecord]) -> crate::Result<()>;
}

/// Cipher repository trait
#[async_trait]
pub trait CipherRepository: Send + Sync {
    /// Create a new cipher record
    async fn create_cipher(&self, cipher: &CipherRecord) -> crate::Result<i64>;

    /// Get all ciphers for a scan
    async fn get_ciphers_by_scan(&self, scan_id: i64) -> crate::Result<Vec<CipherRecord>>;

    /// Get ciphers by scan and protocol
    async fn get_ciphers_by_scan_and_protocol(
        &self,
        scan_id: i64,
        protocol: &str,
    ) -> crate::Result<Vec<CipherRecord>>;

    /// Bulk insert ciphers
    async fn create_ciphers_bulk(&self, ciphers: &[CipherRecord]) -> crate::Result<()>;
}

/// Certificate repository trait
#[async_trait]
pub trait CertificateRepository: Send + Sync {
    /// Create or get existing certificate by fingerprint (deduplication)
    async fn create_or_get_certificate(&self, cert: &CertificateRecord) -> crate::Result<i64>;

    /// Get certificate by ID
    async fn get_certificate_by_id(&self, cert_id: i64)
    -> crate::Result<Option<CertificateRecord>>;

    /// Get certificate by fingerprint
    async fn get_certificate_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Option<CertificateRecord>>;

    /// Link certificate to scan (junction table)
    async fn link_certificate_to_scan(
        &self,
        scan_id: i64,
        cert_id: i64,
        chain_position: i32,
    ) -> crate::Result<()>;

    /// Get certificate chain for a scan
    async fn get_certificate_chain_by_scan(
        &self,
        scan_id: i64,
    ) -> crate::Result<Vec<CertificateRecord>>;
}

/// Vulnerability repository trait
#[async_trait]
pub trait VulnerabilityRepository: Send + Sync {
    /// Create a new vulnerability record
    async fn create_vulnerability(&self, vuln: &VulnerabilityRecord) -> crate::Result<i64>;

    /// Get all vulnerabilities for a scan
    async fn get_vulnerabilities_by_scan(
        &self,
        scan_id: i64,
    ) -> crate::Result<Vec<VulnerabilityRecord>>;

    /// Get vulnerabilities by severity
    async fn get_vulnerabilities_by_severity(
        &self,
        scan_id: i64,
        severity: &str,
    ) -> crate::Result<Vec<VulnerabilityRecord>>;

    /// Bulk insert vulnerabilities
    async fn create_vulnerabilities_bulk(&self, vulns: &[VulnerabilityRecord])
    -> crate::Result<()>;
}

/// Rating repository trait
#[async_trait]
pub trait RatingRepository: Send + Sync {
    /// Create a new rating record
    async fn create_rating(&self, rating: &RatingRecord) -> crate::Result<i64>;

    /// Get all ratings for a scan
    async fn get_ratings_by_scan(&self, scan_id: i64) -> crate::Result<Vec<RatingRecord>>;

    /// Get rating by scan and category
    async fn get_rating_by_category(
        &self,
        scan_id: i64,
        category: &str,
    ) -> crate::Result<Option<RatingRecord>>;

    /// Bulk insert ratings
    async fn create_ratings_bulk(&self, ratings: &[RatingRecord]) -> crate::Result<()>;
}

/// Database trait combining all repositories
#[async_trait]
pub trait Database: Send + Sync {
    fn scans(&self) -> &dyn ScanRepository;
    fn protocols(&self) -> &dyn ProtocolRepository;
    fn ciphers(&self) -> &dyn CipherRepository;
    fn certificates(&self) -> &dyn CertificateRepository;
    fn vulnerabilities(&self) -> &dyn VulnerabilityRepository;
    fn ratings(&self) -> &dyn RatingRepository;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::ScanRecord;
    use async_trait::async_trait;

    struct DummyScanRepo;

    #[async_trait]
    impl ScanRepository for DummyScanRepo {
        async fn create_scan(&self, _scan: &ScanRecord) -> crate::Result<i64> {
            Ok(1)
        }

        async fn get_scan_by_id(&self, _scan_id: i64) -> crate::Result<Option<ScanRecord>> {
            Ok(None)
        }

        async fn get_scans_by_hostname(
            &self,
            _hostname: &str,
            _port: u16,
            _limit: i64,
        ) -> crate::Result<Vec<ScanRecord>> {
            Ok(Vec::new())
        }

        async fn get_latest_scan(
            &self,
            _hostname: &str,
            _port: u16,
        ) -> crate::Result<Option<ScanRecord>> {
            Ok(None)
        }

        async fn delete_old_scans(&self, _days: i64) -> crate::Result<u64> {
            Ok(0)
        }

        async fn update_scan_rating(
            &self,
            _scan_id: i64,
            _grade: &str,
            _score: u8,
        ) -> crate::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_dummy_scan_repository_methods() {
        let repo = DummyScanRepo;
        let scan = ScanRecord::new("example.com".to_string(), 443);

        let id = repo.create_scan(&scan).await.expect("create ok");
        assert_eq!(id, 1);

        let scans = repo
            .get_scans_by_hostname("example.com", 443, 10)
            .await
            .expect("get scans ok");
        assert!(scans.is_empty());
    }
}
