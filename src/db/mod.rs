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
pub use connection::DatabasePool;
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

        if let Some(rating) = &results.rating {
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
        if let Some(rating) = &results.rating {
            self.store_ratings(scan_id, rating).await?;
        }

        // Store certificate chain
        if let Some(cert_data) = &results.certificate_chain {
            self.store_certificates(scan_id, cert_data).await?;
        }

        Ok(scan_id)
    }

    /// Store protocols for a scan
    async fn store_protocols(&self, scan_id: i64, results: &ScanResults) -> crate::Result<()> {
        use crate::db::models::ProtocolRecord;

        for protocol_result in &results.protocols {
            let protocol = ProtocolRecord::new(
                scan_id,
                protocol_result.protocol.name().to_string(),
                protocol_result.supported,
                protocol_result.preferred,
            );

            // Insert protocol
            match &self.pool {
                DatabasePool::Postgres(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO protocols (scan_id, protocol_name, enabled, preferred)
                        VALUES ($1, $2, $3, $4)
                        "#,
                    )
                    .bind(protocol.scan_id)
                    .bind(&protocol.protocol_name)
                    .bind(protocol.enabled)
                    .bind(protocol.preferred)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to insert protocol: {}", e))
                    })?;
                }
                DatabasePool::Sqlite(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO protocols (scan_id, protocol_name, enabled, preferred)
                        VALUES (?, ?, ?, ?)
                        "#,
                    )
                    .bind(protocol.scan_id)
                    .bind(&protocol.protocol_name)
                    .bind(protocol.enabled)
                    .bind(protocol.preferred)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to insert protocol: {}", e))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Store ciphers for a scan
    async fn store_ciphers(&self, scan_id: i64, results: &ScanResults) -> crate::Result<()> {
        use crate::db::models::CipherRecord;

        for (protocol, summary) in &results.ciphers {
            for cipher_result in &summary.supported_ciphers {
                let strength = match cipher_result.strength() {
                    crate::ciphers::CipherStrength::NULL => "null",
                    crate::ciphers::CipherStrength::Export => "export",
                    crate::ciphers::CipherStrength::Low => "low",
                    crate::ciphers::CipherStrength::Medium => "medium",
                    crate::ciphers::CipherStrength::High => "high",
                };

                let cipher = CipherRecord::new(
                    scan_id,
                    protocol.name().to_string(),
                    cipher_result.iana_name.clone(),
                    strength.to_string(),
                    cipher_result.has_forward_secrecy(),
                )
                .with_details(
                    cipher_result.key_exchange.clone(),
                    cipher_result.authentication.clone(),
                    cipher_result.encryption.clone(),
                    cipher_result.mac.clone(),
                    cipher_result.bits,
                );

                // Insert cipher
                match &self.pool {
                    DatabasePool::Postgres(pool) => {
                        sqlx::query(
                            r#"
                            INSERT INTO cipher_suites (scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                            "#
                        )
                        .bind(cipher.scan_id)
                        .bind(&cipher.protocol_name)
                        .bind(&cipher.cipher_name)
                        .bind(&cipher.key_exchange)
                        .bind(&cipher.authentication)
                        .bind(&cipher.encryption)
                        .bind(&cipher.mac)
                        .bind(cipher.bits)
                        .bind(cipher.forward_secrecy)
                        .bind(&cipher.strength)
                        .execute(pool)
                        .await
                        .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert cipher: {}", e)))?;
                    }
                    DatabasePool::Sqlite(pool) => {
                        sqlx::query(
                            r#"
                            INSERT INTO cipher_suites (scan_id, protocol_name, cipher_name, key_exchange, authentication, encryption, mac, bits, forward_secrecy, strength)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            "#
                        )
                        .bind(cipher.scan_id)
                        .bind(&cipher.protocol_name)
                        .bind(&cipher.cipher_name)
                        .bind(&cipher.key_exchange)
                        .bind(&cipher.authentication)
                        .bind(&cipher.encryption)
                        .bind(&cipher.mac)
                        .bind(cipher.bits)
                        .bind(cipher.forward_secrecy)
                        .bind(&cipher.strength)
                        .execute(pool)
                        .await
                        .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert cipher: {}", e)))?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Store vulnerabilities for a scan
    async fn store_vulnerabilities(
        &self,
        scan_id: i64,
        results: &ScanResults,
    ) -> crate::Result<()> {
        use crate::db::models::VulnerabilityRecord;

        for vuln_result in &results.vulnerabilities {
            if !vuln_result.vulnerable {
                continue; // Only store actual vulnerabilities
            }

            let severity = match vuln_result.severity {
                crate::vulnerabilities::Severity::Critical => "critical",
                crate::vulnerabilities::Severity::High => "high",
                crate::vulnerabilities::Severity::Medium => "medium",
                crate::vulnerabilities::Severity::Low => "low",
                crate::vulnerabilities::Severity::Info => "info",
            };

            let mut vuln = VulnerabilityRecord::new(
                scan_id,
                format!("{:?}", vuln_result.vuln_type),
                severity.to_string(),
            )
            .with_description(vuln_result.details.clone());

            if let Some(cve) = &vuln_result.cve {
                vuln = vuln.with_cve(cve.clone());
            }

            // Insert vulnerability
            match &self.pool {
                DatabasePool::Postgres(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO vulnerabilities (scan_id, vulnerability_type, severity, description, cve_id, affected_component)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        "#
                    )
                    .bind(vuln.scan_id)
                    .bind(&vuln.vulnerability_type)
                    .bind(&vuln.severity)
                    .bind(&vuln.description)
                    .bind(&vuln.cve_id)
                    .bind(&vuln.affected_component)
                    .execute(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert vulnerability: {}", e)))?;
                }
                DatabasePool::Sqlite(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO vulnerabilities (scan_id, vulnerability_type, severity, description, cve_id, affected_component)
                        VALUES (?, ?, ?, ?, ?, ?)
                        "#
                    )
                    .bind(vuln.scan_id)
                    .bind(&vuln.vulnerability_type)
                    .bind(&vuln.severity)
                    .bind(&vuln.description)
                    .bind(&vuln.cve_id)
                    .bind(&vuln.affected_component)
                    .execute(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert vulnerability: {}", e)))?;
                }
            }
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
            match &self.pool {
                DatabasePool::Postgres(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO ratings (scan_id, category, score, grade, rationale)
                        VALUES ($1, $2, $3, $4, $5)
                        "#,
                    )
                    .bind(rating_record.scan_id)
                    .bind(&rating_record.category)
                    .bind(rating_record.score)
                    .bind(&rating_record.grade)
                    .bind(&rating_record.rationale)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to insert rating: {}", e))
                    })?;
                }
                DatabasePool::Sqlite(pool) => {
                    sqlx::query(
                        r#"
                        INSERT INTO ratings (scan_id, category, score, grade, rationale)
                        VALUES (?, ?, ?, ?, ?)
                        "#,
                    )
                    .bind(rating_record.scan_id)
                    .bind(&rating_record.category)
                    .bind(rating_record.score)
                    .bind(&rating_record.grade)
                    .bind(&rating_record.rationale)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to insert rating: {}", e))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Store certificate chain for a scan
    async fn store_certificates(
        &self,
        scan_id: i64,
        cert_data: &crate::scanner::CertificateAnalysisResult,
    ) -> crate::Result<()> {
        use crate::db::models::CertificateRecord;
        use chrono::{DateTime, Utc};

        for (position, cert_info) in cert_data.chain.certificates.iter().enumerate() {
            // Create certificate record
            let fingerprint = cert_info
                .fingerprint_sha256
                .clone()
                .unwrap_or_else(|| format!("unknown_{}", position));

            let not_before = DateTime::parse_from_rfc3339(&cert_info.not_before)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let not_after = DateTime::parse_from_rfc3339(&cert_info.not_after)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            let mut cert = CertificateRecord::new(
                fingerprint,
                cert_info.subject.clone(),
                cert_info.issuer.clone(),
                not_before,
                not_after,
                cert_info.is_ca,
            );

            cert = cert.with_serial(cert_info.serial_number.clone());

            if let Some(key_size) = cert_info.public_key_size {
                cert = cert.with_algorithms(
                    cert_info.signature_algorithm.clone(),
                    cert_info.public_key_algorithm.clone(),
                    key_size,
                );
            }

            cert = cert.with_san_domains(cert_info.san.clone());
            cert = cert.with_key_usage(
                cert_info.key_usage.clone(),
                cert_info.extended_key_usage.clone(),
            );
            cert = cert.with_der_bytes(cert_info.der_bytes.clone());

            // Insert or get certificate ID (deduplication by fingerprint)
            let cert_id = self.insert_or_get_certificate(&cert).await?;

            // Link certificate to scan
            self.link_certificate(scan_id, cert_id, position as i32)
                .await?;
        }

        Ok(())
    }

    /// Insert certificate or get existing ID by fingerprint
    async fn insert_or_get_certificate(&self, cert: &CertificateRecord) -> crate::Result<i64> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                // Try to get existing certificate
                use sqlx::Row;
                let existing = sqlx::query(
                    r#"
                    SELECT cert_id
                    FROM certificates
                    WHERE fingerprint_sha256 = $1
                    "#,
                )
                .bind(&cert.fingerprint_sha256)
                .fetch_optional(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!(
                        "Failed to check existing certificate: {}",
                        e
                    ))
                })?;

                if let Some(existing) = existing {
                    return Ok(existing.get("cert_id"));
                }

                // Insert new certificate
                let san_json = serde_json::to_string(&cert.san_domains).unwrap_or_default();
                let key_usage_json = serde_json::to_string(&cert.key_usage).unwrap_or_default();
                let extended_key_usage_json =
                    serde_json::to_string(&cert.extended_key_usage).unwrap_or_default();

                let result = sqlx::query(
                    r#"
                    INSERT INTO certificates (fingerprint_sha256, subject, issuer, serial_number, not_before, not_after, signature_algorithm, public_key_algorithm, public_key_size, san_domains, is_ca, key_usage, extended_key_usage, der_bytes)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    RETURNING cert_id
                    "#
                )
                .bind(&cert.fingerprint_sha256)
                .bind(&cert.subject)
                .bind(&cert.issuer)
                .bind(&cert.serial_number)
                .bind(cert.not_before)
                .bind(cert.not_after)
                .bind(&cert.signature_algorithm)
                .bind(&cert.public_key_algorithm)
                .bind(cert.public_key_size)
                .bind(san_json)
                .bind(cert.is_ca)
                .bind(key_usage_json)
                .bind(extended_key_usage_json)
                .bind(&cert.der_bytes)
                .fetch_one(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert certificate: {}", e)))?;

                Ok(result.get("cert_id"))
            }
            DatabasePool::Sqlite(pool) => {
                // Try to get existing certificate
                use sqlx::Row;
                let existing = sqlx::query(
                    r#"
                    SELECT cert_id
                    FROM certificates
                    WHERE fingerprint_sha256 = ?
                    "#,
                )
                .bind(&cert.fingerprint_sha256)
                .fetch_optional(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!(
                        "Failed to check existing certificate: {}",
                        e
                    ))
                })?;

                if let Some(existing) = existing {
                    return Ok(existing.get("cert_id"));
                }

                // Insert new certificate
                let san_json = serde_json::to_string(&cert.san_domains).unwrap_or_default();
                let key_usage_json = serde_json::to_string(&cert.key_usage).unwrap_or_default();
                let extended_key_usage_json =
                    serde_json::to_string(&cert.extended_key_usage).unwrap_or_default();

                let result = sqlx::query(
                    r#"
                    INSERT INTO certificates (fingerprint_sha256, subject, issuer, serial_number, not_before, not_after, signature_algorithm, public_key_algorithm, public_key_size, san_domains, is_ca, key_usage, extended_key_usage, der_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&cert.fingerprint_sha256)
                .bind(&cert.subject)
                .bind(&cert.issuer)
                .bind(&cert.serial_number)
                .bind(cert.not_before)
                .bind(cert.not_after)
                .bind(&cert.signature_algorithm)
                .bind(&cert.public_key_algorithm)
                .bind(cert.public_key_size)
                .bind(san_json)
                .bind(cert.is_ca)
                .bind(key_usage_json)
                .bind(extended_key_usage_json)
                .bind(&cert.der_bytes)
                .execute(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert certificate: {}", e)))?;

                Ok(result.last_insert_rowid())
            }
        }
    }

    /// Link certificate to scan
    async fn link_certificate(
        &self,
        scan_id: i64,
        cert_id: i64,
        position: i32,
    ) -> crate::Result<()> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO scan_certificates (scan_id, cert_id, chain_position)
                    VALUES ($1, $2, $3)
                    "#,
                )
                .bind(scan_id)
                .bind(cert_id)
                .bind(position)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to link certificate: {}", e))
                })?;
            }
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    INSERT INTO scan_certificates (scan_id, cert_id, chain_position)
                    VALUES (?, ?, ?)
                    "#,
                )
                .bind(scan_id)
                .bind(cert_id)
                .bind(position)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to link certificate: {}", e))
                })?;
            }
        }

        Ok(())
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
        let db = CipherRunDatabase::new(&config).await.unwrap();

        // Verify database was created
        assert!(matches!(db.pool.db_type(), DatabaseType::Sqlite));

        db.close().await;
    }
}
