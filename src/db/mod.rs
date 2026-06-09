// Database Module
// Complete database abstraction layer for CipherRun

pub mod analytics;
pub mod certificate_inventory;
pub mod config;
pub mod connection;
pub mod history;
pub mod migrations;
pub mod models;
pub mod repositories;
pub mod scan_history;
pub mod storage;
pub mod store_factory;
pub mod traits;

// Re-exports
pub use certificate_inventory::{
    CertificateInventoryService, get_certificate as get_certificate_inventory,
    list_certificates as list_certificate_inventory,
};
pub use config::{Config, DatabaseConfig, DatabaseType, RetentionConfig};
pub use connection::{BindValue, DatabasePool, QueryBuilder};
pub use migrations::{revert_migration, run_migrations};
pub use models::*;
pub use scan_history::ScanHistoryService;
pub use store_factory::ConfigFileScanResultsStoreFactory;
pub use traits::*;

use crate::application::PersistedScan;
use crate::application::ScanResultsStore;
use async_trait::async_trait;
use repositories::ScanRepositoryImpl;

/// Main database struct
pub struct CipherRunDatabase {
    pool: DatabasePool,
    scan_repo: ScanRepositoryImpl,
}

#[async_trait]
impl ScanResultsStore for CipherRunDatabase {
    async fn store_scan(&self, scan: &PersistedScan) -> crate::Result<i64> {
        CipherRunDatabase::store_scan(self, scan).await
    }
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
    pub async fn store_scan(&self, results: &PersistedScan) -> crate::Result<i64> {
        use crate::db::models::*;

        // Create scan record
        let mut scan = ScanRecord::new(results.target_hostname.clone(), results.target_port);
        if let (Some(grade), Some(score)) = (&results.overall_grade, results.overall_score) {
            scan = scan.with_rating(grade.clone(), score);
        }
        scan = scan.with_duration(results.scan_duration_ms);

        // Insert scan
        let scan_id = self.scan_repo.create_scan(&scan).await?;

        // Write the child rows. If any fails, roll back the whole scan: the
        // child writes are not in one transaction (the dual-backend pool
        // abstraction has no transaction API), so a mid-write failure would
        // otherwise leave a partial scan that analytics read as wrong data
        // (e.g. "0 vulnerabilities"). The ON DELETE CASCADE on every child table
        // means deleting the scan row removes any rows already written.
        if let Err(error) = self.store_scan_children(scan_id, results).await {
            if let Err(cleanup) = self.scan_repo.delete_scan(scan_id).await {
                tracing::error!(
                    scan_id,
                    "failed to roll back partially-written scan after store error ({}): {}",
                    error,
                    cleanup
                );
            }
            return Err(error);
        }

        Ok(scan_id)
    }

    /// Write all child rows (protocols, ciphers, vulnerabilities, ratings,
    /// certificates) for an already-created scan.
    async fn store_scan_children(
        &self,
        scan_id: i64,
        results: &PersistedScan,
    ) -> crate::Result<()> {
        self.store_protocols(scan_id, results).await?;
        self.store_ciphers(scan_id, results).await?;
        self.store_vulnerabilities(scan_id, results).await?;

        if !results.ratings.is_empty() {
            self.store_ratings(scan_id, results).await?;
        }

        if !results.certificates.is_empty() {
            self.store_certificates(scan_id, results).await?;
        }

        Ok(())
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

    #[tokio::test]
    async fn test_store_scan_minimal() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let db = CipherRunDatabase::new(&config)
            .await
            .expect("test assertion should succeed");

        let results = PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 123,
            protocols: Vec::new(),
            ciphers: Vec::new(),
            vulnerabilities: Vec::new(),
            ratings: Vec::new(),
            certificates: Vec::new(),
        };

        let scan_id = db
            .store_scan(&results)
            .await
            .expect("test assertion should succeed");
        assert!(scan_id >= 0);

        if let DatabasePool::Sqlite(pool) = db.pool() {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scans")
                .fetch_one(pool)
                .await
                .expect("test assertion should succeed");
            assert!(row.0 >= 1);
        } else {
            panic!("expected sqlite pool");
        }

        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_scan_cascades_to_child_rows() {
        use crate::application::persistence::PersistedProtocol;

        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let db = CipherRunDatabase::new(&config)
            .await
            .expect("test assertion should succeed");

        let results = PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 1,
            protocols: vec![PersistedProtocol {
                protocol_name: "TLS 1.2".to_string(),
                enabled: true,
                preferred: true,
            }],
            ciphers: Vec::new(),
            vulnerabilities: Vec::new(),
            ratings: Vec::new(),
            certificates: Vec::new(),
        };

        let scan_id = db
            .store_scan(&results)
            .await
            .expect("test assertion should succeed");

        // Deleting the scan must cascade to the child protocol row (the rollback
        // mechanism for partially-written scans relies on this cascade).
        db.scan_repo
            .delete_scan(scan_id)
            .await
            .expect("test assertion should succeed");

        if let DatabasePool::Sqlite(pool) = db.pool() {
            let scans: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scans WHERE scan_id = ?")
                .bind(scan_id)
                .fetch_one(pool)
                .await
                .expect("test assertion should succeed");
            assert_eq!(scans.0, 0, "scan row should be deleted");

            let protocols: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM protocols WHERE scan_id = ?")
                    .bind(scan_id)
                    .fetch_one(pool)
                    .await
                    .expect("test assertion should succeed");
            assert_eq!(protocols.0, 0, "child protocol rows should cascade-delete");
        } else {
            panic!("expected sqlite pool");
        }

        db.close().await;
    }
}
