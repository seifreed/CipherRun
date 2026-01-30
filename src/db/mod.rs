// Database Module
// Complete database abstraction layer for CipherRun

pub mod analytics;
pub mod config;
pub mod connection;
pub mod migrations;
pub mod models;
pub mod repositories;
pub mod traits;

// Re-exports
pub use config::{Config, DatabaseConfig, DatabaseType, RetentionConfig};
pub use connection::{BindValue, DatabasePool, QueryBuilder};
pub use migrations::{revert_migration, run_migrations};
pub use models::*;
pub use traits::*;

use crate::scanner::ScanResults;
use repositories::ScanRepositoryImpl;

/// Main database struct
pub struct CipherRunDatabase {
    pool: DatabasePool,
    scan_repo: ScanRepositoryImpl,
}

impl CipherRunDatabase {
    /// Create new database instance
    pub async fn new(config: &DatabaseConfig) -> crate::Result<Self> {
        let pool = DatabasePool::new(config).await?;

        // Run migrations
        run_migrations(&pool).await?;

        let scan_repo = ScanRepositoryImpl::new(pool.clone());

        Ok(Self { pool, scan_repo })
    }

    /// Create database from config file
    pub async fn from_config_file(path: &str) -> crate::Result<Self> {
        let config = DatabaseConfig::from_file(path)?;
        Self::new(&config.database).await
    }

    /// Get database pool
    pub fn pool(&self) -> &DatabasePool {
        &self.pool
    }

    /// Close database connection
    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Store complete scan results
    pub async fn store_scan(&self, results: &ScanResults) -> crate::Result<i64> {
        use crate::db::models::*;

        // Parse target
        let parts: Vec<&str> = results.target.split(':').collect();
        let hostname = parts.first().unwrap_or(&"unknown").to_string();
        let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

        // Create scan record
        let mut scan = ScanRecord::new(hostname, port);

        if let Some(rating) = results.ssl_rating() {
            scan = scan.with_rating(rating.grade.to_string(), rating.score);
        }

        scan = scan.with_duration(results.scan_time_ms);

        // Insert scan
        let scan_id = self.scan_repo.create_scan(&scan).await?;

        // Store protocols
        self.store_protocols(scan_id, results).await?;

        // Store ciphers
        self.store_ciphers(scan_id, results).await?;

        // Store vulnerabilities
        self.store_vulnerabilities(scan_id, results).await?;

        // Store ratings
        if let Some(rating) = results.ssl_rating() {
            self.store_ratings(scan_id, rating).await?;
        }

        // Store certificate chain
        if let Some(cert_data) = &results.certificate_chain {
            self.store_certificates(scan_id, cert_data).await?;
        }

        Ok(scan_id)
    }

    /// Store protocols for a scan
    ///
    /// Performance optimization: Uses batch INSERT with multiple VALUES clauses
    /// instead of N individual queries. This reduces round-trips to the database.
    ///
    /// Time complexity: O(1) database round-trip instead of O(n)
    /// Expected improvement: 10-100x faster for n>10 protocols
    async fn store_protocols(&self, scan_id: i64, results: &ScanResults) -> crate::Result<()> {
        use crate::db::models::ProtocolRecord;

        if results.protocols.is_empty() {
            return Ok(());
        }

        // Build single batch INSERT with multiple VALUES
        let mut qb = self.pool.query_builder();
        let columns = &["scan_id", "protocol_name", "enabled", "preferred"];

        // Collect all bind values
        let mut all_bindings = Vec::new();
        for protocol_result in &results.protocols {
            let protocol = ProtocolRecord::new(
                scan_id,
                protocol_result.protocol.name().to_string(),
                protocol_result.supported,
                protocol_result.preferred,
            );

            all_bindings.push(vec![
                BindValue::Int64(protocol.scan_id),
                BindValue::String(protocol.protocol_name),
                BindValue::Bool(protocol.enabled),
                BindValue::Bool(protocol.preferred),
            ]);
        }

        // Build batch query
        let query = qb.batch_insert_query("protocols", columns, all_bindings.len());

        // Flatten bindings for execution
        let flat_bindings: Vec<BindValue> = all_bindings.into_iter().flatten().collect();

        self.pool
            .execute(&query, flat_bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to batch insert protocols: {}", e))
            })?;

        Ok(())
    }

    /// Store ciphers for a scan
    ///
    /// Performance optimization: Uses batch INSERT with multiple VALUES clauses
    /// instead of N individual queries. This dramatically improves performance
    /// when storing large cipher lists.
    ///
    /// Time complexity: O(1) database round-trip instead of O(n*m)
    /// Expected improvement: 50-500x faster for typical cipher counts (200-500 ciphers)
    async fn store_ciphers(&self, scan_id: i64, results: &ScanResults) -> crate::Result<()> {
        let total_ciphers: usize = results
            .ciphers
            .values()
            .map(|s| s.supported_ciphers.len())
            .sum();

        if total_ciphers == 0 {
            return Ok(());
        }

        let columns = &[
            "scan_id",
            "protocol_name",
            "cipher_name",
            "key_exchange",
            "authentication",
            "encryption",
            "mac",
            "bits",
            "forward_secrecy",
            "strength",
        ];

        let mut all_bindings = Vec::with_capacity(total_ciphers);

        for (protocol, summary) in &results.ciphers {
            let protocol_name = protocol.name();
            for cipher_result in &summary.supported_ciphers {
                let strength = match cipher_result.strength() {
                    crate::ciphers::CipherStrength::NULL => "null",
                    crate::ciphers::CipherStrength::Export => "export",
                    crate::ciphers::CipherStrength::Low => "low",
                    crate::ciphers::CipherStrength::Medium => "medium",
                    crate::ciphers::CipherStrength::High => "high",
                };

                all_bindings.push(vec![
                    BindValue::Int64(scan_id),
                    BindValue::String(protocol_name.to_string()),
                    BindValue::String(cipher_result.iana_name.clone()),
                    BindValue::OptString(Some(cipher_result.key_exchange.clone())),
                    BindValue::OptString(Some(cipher_result.authentication.clone())),
                    BindValue::OptString(Some(cipher_result.encryption.clone())),
                    BindValue::OptString(Some(cipher_result.mac.clone())),
                    BindValue::OptInt32(Some(cipher_result.bits as i32)),
                    BindValue::Bool(cipher_result.has_forward_secrecy()),
                    BindValue::String(strength.to_string()),
                ]);
            }
        }

        let mut qb = self.pool.query_builder();
        let query = qb.batch_insert_query("cipher_suites", columns, all_bindings.len());

        let flat_bindings: Vec<BindValue> = all_bindings.into_iter().flatten().collect();

        self.pool
            .execute(&query, flat_bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to batch insert ciphers: {}", e))
            })?;

        Ok(())
    }

    /// Store vulnerabilities for a scan
    async fn store_vulnerabilities(
        &self,
        scan_id: i64,
        results: &ScanResults,
    ) -> crate::Result<()> {
        let mut qb = self.pool.query_builder();
        let query = qb.insert_query(
            "vulnerabilities",
            &[
                "scan_id",
                "vulnerability_type",
                "severity",
                "description",
                "cve_id",
                "affected_component",
            ],
        );

        for vuln_result in &results.vulnerabilities {
            if !vuln_result.vulnerable {
                continue;
            }

            let severity = match vuln_result.severity {
                crate::vulnerabilities::Severity::Critical => "critical",
                crate::vulnerabilities::Severity::High => "high",
                crate::vulnerabilities::Severity::Medium => "medium",
                crate::vulnerabilities::Severity::Low => "low",
                crate::vulnerabilities::Severity::Info => "info",
            };

            self.pool
                .execute(
                    &query,
                    vec![
                        BindValue::Int64(scan_id),
                        BindValue::String(format!("{:?}", vuln_result.vuln_type)),
                        BindValue::String(severity.to_string()),
                        BindValue::OptString(Some(vuln_result.details.clone())),
                        BindValue::OptString(vuln_result.cve.clone()),
                        BindValue::OptString(None),
                    ],
                )
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to insert vulnerability: {}", e))
                })?;
        }

        Ok(())
    }

    /// Store rating components for a scan
    async fn store_ratings(
        &self,
        scan_id: i64,
        rating: &crate::rating::RatingResult,
    ) -> crate::Result<()> {
        use crate::db::models::RatingRecord;

        let mut qb = self.pool.query_builder();
        let query = qb.insert_query(
            "ratings",
            &["scan_id", "category", "score", "grade", "rationale"],
        );

        let ratings = vec![
            RatingRecord::new(scan_id, "certificate".to_string(), rating.certificate_score),
            RatingRecord::new(scan_id, "protocol".to_string(), rating.protocol_score),
            RatingRecord::new(
                scan_id,
                "key_exchange".to_string(),
                rating.key_exchange_score,
            ),
            RatingRecord::new(scan_id, "cipher".to_string(), rating.cipher_strength_score),
        ];

        for rating_record in ratings {
            self.pool
                .execute(
                    &query,
                    vec![
                        BindValue::Int64(rating_record.scan_id),
                        BindValue::String(rating_record.category),
                        BindValue::Int32(rating_record.score),
                        BindValue::OptString(rating_record.grade),
                        BindValue::OptString(rating_record.rationale),
                    ],
                )
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to insert rating: {}", e))
                })?;
        }

        Ok(())
    }

    /// Store certificate chain for a scan
    async fn store_certificates(
        &self,
        scan_id: i64,
        cert_data: &crate::scanner::CertificateAnalysisResult,
    ) -> crate::Result<()> {
        use chrono::{DateTime, Utc};

        for (position, cert_info) in cert_data.chain.certificates.iter().enumerate() {
            let fingerprint = cert_info
                .fingerprint_sha256
                .as_deref()
                .map(String::from)
                .unwrap_or_else(|| format!("unknown_{}", position));

            let not_before = DateTime::parse_from_rfc3339(&cert_info.not_before)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let not_after = DateTime::parse_from_rfc3339(&cert_info.not_after)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let cert_id = self
                .insert_or_get_certificate_direct(
                    &fingerprint,
                    &cert_info.subject,
                    &cert_info.issuer,
                    Some(&cert_info.serial_number),
                    not_before,
                    not_after,
                    Some(&cert_info.signature_algorithm),
                    Some(&cert_info.public_key_algorithm),
                    cert_info.public_key_size.map(|s| s as i32),
                    &cert_info.san,
                    cert_info.is_ca,
                    &cert_info.key_usage,
                    &cert_info.extended_key_usage,
                    Some(&cert_info.der_bytes),
                )
                .await?;

            self.link_certificate(scan_id, cert_id, position as i32)
                .await?;
        }

        Ok(())
    }

    /// Insert certificate or get existing ID by fingerprint (direct binding version)
    ///
    /// Note: Many parameters are required to fully represent an X.509 certificate.
    /// Using a struct would add complexity without benefit for this internal function.
    #[allow(clippy::too_many_arguments)]
    async fn insert_or_get_certificate_direct(
        &self,
        fingerprint: &str,
        subject: &str,
        issuer: &str,
        serial_number: Option<&str>,
        not_before: chrono::DateTime<chrono::Utc>,
        not_after: chrono::DateTime<chrono::Utc>,
        signature_algorithm: Option<&str>,
        public_key_algorithm: Option<&str>,
        public_key_size: Option<i32>,
        san_domains: &[String],
        is_ca: bool,
        key_usage: &[String],
        extended_key_usage: &[String],
        der_bytes: Option<&[u8]>,
    ) -> crate::Result<i64> {
        let mut qb = self.pool.query_builder();
        let select_query = qb.select_where_query("certificates", "cert_id", "fingerprint_sha256");

        if let Some(existing_id) = self
            .pool
            .fetch_optional_id(
                &select_query,
                vec![BindValue::String(fingerprint.to_string())],
            )
            .await?
        {
            return Ok(existing_id);
        }

        let san_json = serde_json::to_string(san_domains).unwrap_or_default();
        let key_usage_json = serde_json::to_string(key_usage).unwrap_or_default();
        let extended_key_usage_json = serde_json::to_string(extended_key_usage).unwrap_or_default();

        let mut qb = self.pool.query_builder();
        let insert_query = qb.insert_returning_query(
            "certificates",
            &[
                "fingerprint_sha256",
                "subject",
                "issuer",
                "serial_number",
                "not_before",
                "not_after",
                "signature_algorithm",
                "public_key_algorithm",
                "public_key_size",
                "san_domains",
                "is_ca",
                "key_usage",
                "extended_key_usage",
                "der_bytes",
            ],
            "cert_id",
        );

        let bindings = vec![
            BindValue::String(fingerprint.to_string()),
            BindValue::String(subject.to_string()),
            BindValue::String(issuer.to_string()),
            BindValue::OptString(serial_number.map(String::from)),
            BindValue::DateTime(not_before),
            BindValue::DateTime(not_after),
            BindValue::OptString(signature_algorithm.map(String::from)),
            BindValue::OptString(public_key_algorithm.map(String::from)),
            BindValue::OptInt32(public_key_size),
            BindValue::String(san_json),
            BindValue::Bool(is_ca),
            BindValue::String(key_usage_json),
            BindValue::String(extended_key_usage_json),
            BindValue::OptBytes(der_bytes.map(Vec::from)),
        ];

        self.pool
            .execute_insert_returning(&insert_query, bindings)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to insert certificate: {}", e))
            })
    }

    /// Link certificate to scan
    async fn link_certificate(
        &self,
        scan_id: i64,
        cert_id: i64,
        position: i32,
    ) -> crate::Result<()> {
        let mut qb = self.pool.query_builder();
        let query = qb.insert_query(
            "scan_certificates",
            &["scan_id", "cert_id", "chain_position"],
        );

        self.pool
            .execute(
                &query,
                vec![
                    BindValue::Int64(scan_id),
                    BindValue::Int64(cert_id),
                    BindValue::Int32(position),
                ],
            )
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to link certificate: {}", e))
            })
    }

    /// Get scan history for a hostname
    pub async fn get_scan_history(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ScanRecord>> {
        self.scan_repo
            .get_scans_by_hostname(hostname, port, limit)
            .await
    }

    /// Get latest scan for a hostname
    pub async fn get_latest_scan(
        &self,
        hostname: &str,
        port: u16,
    ) -> crate::Result<Option<ScanRecord>> {
        self.scan_repo.get_latest_scan(hostname, port).await
    }

    /// Cleanup old scans based on retention policy
    pub async fn cleanup_old_scans(&self, days: i64) -> crate::Result<u64> {
        self.scan_repo.delete_old_scans(days).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_database_creation() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let db = CipherRunDatabase::new(&config)
            .await
            .expect("test assertion should succeed");

        // Verify database was created
        assert!(matches!(db.pool.db_type(), DatabaseType::Sqlite));

        db.close().await;
    }
}
