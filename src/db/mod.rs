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

#[cfg(test)]
pub(crate) fn create_unique_test_db_path(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("cipherrun-{prefix}-test{counter}.db"));
    let _ = std::fs::remove_file(&path);
    path
}

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

#[async_trait]
impl ScanResultsStore for DatabasePool {
    async fn store_scan(&self, scan: &PersistedScan) -> crate::Result<i64> {
        CipherRunDatabase::from_pool(self.clone())
            .store_scan(scan)
            .await
    }
}

impl CipherRunDatabase {
    pub fn from_pool(pool: DatabasePool) -> Self {
        let scan_repo = ScanRepositoryImpl::new(pool.clone());
        Self { pool, scan_repo }
    }

    /// Create new database instance
    pub async fn new(config: &DatabaseConfig) -> crate::Result<Self> {
        let started = std::time::Instant::now();
        let pool = DatabasePool::new(config).await?;

        // Run migrations
        run_migrations(&pool).await?;

        tracing::info!(
            event_name = "database.initialized",
            database_backend = ?pool.db_type(),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "Database connection and migrations are ready"
        );

        let scan_repo = ScanRepositoryImpl::new(pool.clone());

        Ok(Self { pool, scan_repo })
    }

    /// Create database from config file
    pub async fn from_config_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        let config = DatabaseConfig::from_file(path)?;
        Self::new(&config.database).await
    }

    /// Get database pool
    pub fn pool(&self) -> &DatabasePool {
        &self.pool
    }

    /// Close database connection
    pub async fn close(self) {
        let started = std::time::Instant::now();
        self.pool.close().await;
        tracing::info!(
            event_name = "database.closed",
            database_backend = ?self.pool.db_type(),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome = "closed",
            "Database connection closed"
        );
    }

    /// Store complete scan results
    pub async fn store_scan(&self, results: &PersistedScan) -> crate::Result<i64> {
        use crate::db::models::*;

        let started = std::time::Instant::now();

        // Create scan record
        let mut scan = ScanRecord::new(results.target_hostname.clone(), results.target_port);
        scan = scan.with_owner(
            results.principal_id.clone(),
            results.tenant_id.clone(),
            results.created_by_key_id.clone(),
        );
        if let (Some(grade), Some(score)) = (&results.overall_grade, results.overall_score) {
            scan = scan.with_rating(grade.clone(), score);
        }
        scan = scan.with_duration(results.scan_duration_ms)?;
        let revocation_json = match &results.revocation {
            Some(revocation) => Some(serde_json::to_string(revocation).map_err(|error| {
                crate::TlsError::ParseError {
                    message: format!("Failed to serialize revocation for persistence: {}", error),
                }
            })?),
            None => None,
        };
        scan = scan.with_revocation_json(revocation_json);

        // Insert scan
        let scan_id = self.scan_repo.create_scan(&scan).await?;

        // Write the child rows. If any fails, roll back the whole scan: the
        // child writes are not in one transaction (the dual-backend pool
        // abstraction has no transaction API), so a mid-write failure would
        // otherwise leave a partial scan that analytics read as wrong data
        // (e.g. "0 vulnerabilities"). The ON DELETE CASCADE on every child table
        // means deleting the scan row removes any rows already written.
        if let Err(error) = self.store_scan_children(scan_id, results).await {
            if self.scan_repo.delete_scan(scan_id).await.is_err() {
                tracing::error!(
                    event_name = "database.scan.rollback.failed",
                    scan_id,
                    error_type = "scan_child_persistence",
                    cleanup_error_type = "scan_delete",
                    "Failed to remove partially stored scan after persistence failure"
                );
            }
            return Err(error);
        }

        tracing::info!(
            event_name = "database.scan.persisted",
            operation = "store_scan",
            scan_id,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            protocol_count = results.protocols.len(),
            cipher_count = results.ciphers.len(),
            vulnerability_count = results.vulnerabilities.len(),
            rating_count = results.ratings.len(),
            certificate_count = results.certificates.len(),
            outcome = "stored",
            "Scan results persisted"
        );

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
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    async fn test_db() -> CipherRunDatabase {
        let config = DatabaseConfig::sqlite(std::path::PathBuf::from(":memory:"));
        CipherRunDatabase::new(&config)
            .await
            .expect("test assertion should succeed")
    }

    #[tokio::test]
    async fn test_database_creation() {
        let db = test_db().await;

        // Verify database was created
        assert!(matches!(db.pool.db_type(), DatabaseType::Sqlite));

        db.close().await;
    }

    #[tokio::test]
    async fn database_initialization_logs_backend_without_config_path() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(output.clone())
            .finish();
        let directory = tempfile::tempdir().expect("test database directory should exist");
        let db_path = directory.path().join("db.sqlite");
        let config = DatabaseConfig::sqlite(db_path.clone());

        let db = CipherRunDatabase::new(&config)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("database should initialize");

        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("database.initialized"));
        assert!(logs.contains("database_backend=Sqlite"));
        assert!(logs.contains("duration_ms="));
        assert!(!logs.contains(db_path.to_str().unwrap()));
        db.close().await;
    }

    #[tokio::test]
    async fn database_shutdown_logs_backend_and_duration() {
        let db = test_db().await;
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();

        db.close()
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await;

        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(logs.trim()).unwrap();
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["event_name"], "database.closed");
        assert_eq!(event["fields"]["database_backend"], "Sqlite");
        assert!(event["fields"]["duration_ms"].is_number());
        assert_eq!(event["fields"]["outcome"], "closed");
    }

    #[tokio::test]
    async fn test_store_scan_minimal() {
        let db = test_db().await;
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(output.clone())
            .finish();

        let results = PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            principal_id: None,
            tenant_id: None,
            created_by_key_id: None,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 123,
            revocation: None,
            protocols: Vec::new(),
            ciphers: Vec::new(),
            vulnerabilities: Vec::new(),
            ratings: Vec::new(),
            certificates: Vec::new(),
        };

        let scan_id = db
            .store_scan(&results)
            .with_subscriber(tracing::Dispatch::new(subscriber))
            .await
            .expect("test assertion should succeed");
        assert!(scan_id >= 0);

        let logs = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(logs.trim()).unwrap();
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["event_name"], "database.scan.persisted");
        assert_eq!(event["fields"]["operation"], "store_scan");
        assert_eq!(event["fields"]["scan_id"], scan_id);
        assert!(event["fields"]["duration_ms"].is_number());
        assert_eq!(event["fields"]["outcome"], "stored");
        assert!(!logs.contains("example.com"));

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
    async fn test_store_scan_persists_revocation_json() {
        use crate::certificates::revocation::{
            RevocationMethod, RevocationResult, RevocationStatus,
        };

        let db = test_db().await;

        let results = PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            principal_id: None,
            tenant_id: None,
            created_by_key_id: None,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 123,
            revocation: Some(RevocationResult {
                status: RevocationStatus::Good,
                method: RevocationMethod::OCSP,
                details: "OCSP".to_string(),
                ocsp_stapling: true,
                ocsp_stapling_details: None,
                must_staple: false,
            }),
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

        if let DatabasePool::Sqlite(pool) = db.pool() {
            let row: (Option<String>,) =
                sqlx::query_as("SELECT revocation_json FROM scans WHERE scan_id = ?")
                    .bind(scan_id)
                    .fetch_one(pool)
                    .await
                    .expect("test assertion should succeed");
            assert!(
                row.0
                    .as_deref()
                    .unwrap_or_default()
                    .contains("\"status\":\"Good\"")
            );
        } else {
            panic!("expected sqlite pool");
        }

        let fetched = db
            .scan_repo
            .get_scan_by_id(scan_id)
            .await
            .expect("test assertion should succeed")
            .expect("scan should exist");
        assert!(fetched.revocation_json.is_some());

        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_scan_cascades_to_child_rows() {
        use crate::application::persistence::PersistedProtocol;

        let db = test_db().await;

        let results = PersistedScan {
            target_hostname: "example.com".to_string(),
            target_port: 443,
            principal_id: None,
            tenant_id: None,
            created_by_key_id: None,
            overall_grade: None,
            overall_score: None,
            scan_duration_ms: 1,
            revocation: None,
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
