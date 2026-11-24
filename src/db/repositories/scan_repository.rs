// Scan Repository Implementation
// Handles database operations for scan records

use crate::db::connection::DatabasePool;
use crate::db::models::ScanRecord;
use crate::db::traits::ScanRepository;
use async_trait::async_trait;
use sqlx::Row;

pub struct ScanRepositoryImpl {
    pool: DatabasePool,
}

impl ScanRepositoryImpl {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Delete a single scan and all its child rows.
    ///
    /// All child tables (protocols, cipher_suites, scan_certificates, ratings,
    /// vulnerabilities) declare `ON DELETE CASCADE` on `scans(scan_id)`, so this
    /// removes the whole scan atomically. Used to roll back a partially-written
    /// scan when a child insert fails.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.delete")
    )]
    pub async fn delete_scan(&self, scan_id: i64) -> crate::Result<()> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                sqlx::query("DELETE FROM scans WHERE scan_id = $1")
                    .bind(scan_id)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to delete scan: {}", e))
                    })?;
            }
            DatabasePool::Sqlite(pool) => {
                sqlx::query("DELETE FROM scans WHERE scan_id = ?")
                    .bind(scan_id)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("Failed to delete scan: {}", e))
                    })?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ScanRepository for ScanRepositoryImpl {
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.create")
    )]
    async fn create_scan(&self, scan: &ScanRecord) -> crate::Result<i64> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query(
                    r#"
                    INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    RETURNING scan_id
                    "#
                )
                .bind(&scan.target_hostname)
                .bind(scan.target_port)
                .bind(scan.scan_timestamp)
                .bind(&scan.overall_grade)
                .bind(scan.overall_score)
                .bind(scan.scan_duration_ms)
                .bind(&scan.revocation_json)
                .bind(&scan.scanner_version)
                .bind(&scan.principal_id)
                .bind(&scan.tenant_id)
                .bind(&scan.created_by_key_id)
                .fetch_one(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert scan: {}", e)))?;

                Ok(result.get("scan_id"))
            }
            DatabasePool::Sqlite(pool) => {
                let result = sqlx::query(
                    r#"
                    INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&scan.target_hostname)
                .bind(scan.target_port)
                .bind(scan.scan_timestamp)
                .bind(&scan.overall_grade)
                .bind(scan.overall_score)
                .bind(scan.scan_duration_ms)
                .bind(&scan.revocation_json)
                .bind(&scan.scanner_version)
                .bind(&scan.principal_id)
                .bind(&scan.tenant_id)
                .bind(&scan.created_by_key_id)
                .execute(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert scan: {}", e)))?;

                Ok(result.last_insert_rowid())
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.get_by_id")
    )]
    async fn get_scan_by_id(&self, scan_id: i64) -> crate::Result<Option<ScanRecord>> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE scan_id = $1
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scan: {}", e)))?;

                Ok(result)
            }
            DatabasePool::Sqlite(pool) => {
                let result = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE scan_id = ?
                    "#
                )
                .bind(scan_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scan: {}", e)))?;

                Ok(result)
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.list_by_hostname")
    )]
    async fn get_scans_by_hostname(
        &self,
        hostname: &str,
        port: u16,
        limit: i64,
    ) -> crate::Result<Vec<ScanRecord>> {
        let port = port as i32;

        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let results = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE LOWER(target_hostname) = $1 AND target_port = $2
                    ORDER BY scan_timestamp DESC, scan_id DESC
                    LIMIT $3
                    "#
                )
                .bind(hostname)
                .bind(port)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scans: {}", e)))?;

                Ok(results)
            }
            DatabasePool::Sqlite(pool) => {
                let results = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE LOWER(target_hostname) = ? AND target_port = ?
                    ORDER BY scan_timestamp DESC, scan_id DESC
                    LIMIT ?
                    "#
                )
                .bind(hostname)
                .bind(port)
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scans: {}", e)))?;

                Ok(results)
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "scan.list_by_hostname_since"
        )
    )]
    async fn get_scans_by_hostname_since(
        &self,
        hostname: &str,
        port: u16,
        since: chrono::DateTime<chrono::Utc>,
    ) -> crate::Result<Vec<ScanRecord>> {
        let port = port as i32;

        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let results = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE LOWER(target_hostname) = $1 AND target_port = $2 AND scan_timestamp >= $3
                    ORDER BY scan_timestamp DESC, scan_id DESC
                    "#
                )
                .bind(hostname)
                .bind(port)
                .bind(since)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scans: {}", e)))?;

                Ok(results)
            }
            DatabasePool::Sqlite(pool) => {
                let results = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, revocation_json, scanner_version, principal_id, tenant_id, created_by_key_id
                    FROM scans
                    WHERE LOWER(target_hostname) = ? AND target_port = ? AND scan_timestamp >= ?
                    ORDER BY scan_timestamp DESC, scan_id DESC
                    "#
                )
                .bind(hostname)
                .bind(port)
                .bind(since)
                .fetch_all(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch scans: {}", e)))?;

                Ok(results)
            }
        }
    }

    async fn get_latest_scan(
        &self,
        hostname: &str,
        port: u16,
    ) -> crate::Result<Option<ScanRecord>> {
        let scans = self.get_scans_by_hostname(hostname, port, 1).await?;
        Ok(scans.into_iter().next())
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.delete_old")
    )]
    async fn delete_old_scans(&self, days: i64) -> crate::Result<u64> {
        let cutoff_date = crate::db::history::cleanup_cutoff_days_ago(days)?;

        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query(
                    r#"
                    DELETE FROM scans
                    WHERE scan_timestamp < $1
                    "#,
                )
                .bind(cutoff_date)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to delete old scans: {}", e))
                })?;

                Ok(result.rows_affected())
            }
            DatabasePool::Sqlite(pool) => {
                let result = sqlx::query(
                    r#"
                    DELETE FROM scans
                    WHERE scan_timestamp < ?
                    "#,
                )
                .bind(cutoff_date)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to delete old scans: {}", e))
                })?;

                Ok(result.rows_affected())
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "scan.update_rating")
    )]
    async fn update_scan_rating(&self, scan_id: i64, grade: &str, score: u8) -> crate::Result<()> {
        let score = score as i32;

        match &self.pool {
            DatabasePool::Postgres(pool) => {
                sqlx::query(
                    r#"
                    UPDATE scans
                    SET overall_grade = $1, overall_score = $2
                    WHERE scan_id = $3
                    "#,
                )
                .bind(grade)
                .bind(score)
                .bind(scan_id)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to update scan rating: {}", e))
                })?;
            }
            DatabasePool::Sqlite(pool) => {
                sqlx::query(
                    r#"
                    UPDATE scans
                    SET overall_grade = ?, overall_score = ?
                    WHERE scan_id = ?
                    "#,
                )
                .bind(grade)
                .bind(score)
                .bind(scan_id)
                .execute(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to update scan rating: {}", e))
                })?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrations::run_migrations;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test assertion should succeed");
        run_migrations(&DatabasePool::Sqlite(pool.clone()))
            .await
            .expect("test assertion should succeed");
        pool
    }

    #[tokio::test]
    async fn test_scan_repository() {
        let pool = test_pool().await;

        // Create repository
        let repo = ScanRepositoryImpl::new(DatabasePool::Sqlite(pool.clone()));

        // Create scan
        let scan = ScanRecord::new("example.com".to_string(), 443);
        let scan_id = repo
            .create_scan(&scan)
            .await
            .expect("test assertion should succeed");

        assert!(scan_id > 0);

        // Fetch scan
        let fetched = repo
            .get_scan_by_id(scan_id)
            .await
            .expect("test assertion should succeed");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().target_hostname, "example.com");

        pool.close().await;
    }

    #[tokio::test]
    async fn test_scan_repository_matches_hostname_case_insensitively() {
        let pool = test_pool().await;
        let repo = ScanRepositoryImpl::new(DatabasePool::Sqlite(pool.clone()));

        let scan = ScanRecord::new("EXAMPLE.COM".to_string(), 443);
        let scan_id = repo
            .create_scan(&scan)
            .await
            .expect("test assertion should succeed");

        assert!(scan_id > 0);

        let scans = repo
            .get_scans_by_hostname("example.com", 443, 10)
            .await
            .expect("test assertion should succeed");

        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].target_hostname, "EXAMPLE.COM");

        pool.close().await;
    }

    #[tokio::test]
    async fn scan_repository_maps_sqlite_failures_to_operation_errors() {
        let pool = test_pool().await;
        let repo = ScanRepositoryImpl::new(DatabasePool::Sqlite(pool.clone()));
        sqlx::query("DROP TABLE scans")
            .execute(&pool)
            .await
            .expect("test should remove the scans table");

        let scan = ScanRecord::new("example.com".to_string(), 443);
        assert!(
            repo.create_scan(&scan)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to insert scan")
        );
        assert!(
            repo.get_scan_by_id(1)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scan")
        );
        assert!(
            repo.get_scans_by_hostname("example.com", 443, 10)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scans")
        );
        assert!(
            repo.get_scans_by_hostname_since("example.com", 443, chrono::Utc::now())
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scans")
        );
        assert!(
            repo.delete_old_scans(30)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to delete old scans")
        );
        assert!(
            repo.update_scan_rating(1, "A", 95)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to update scan rating")
        );
        assert!(
            repo.delete_scan(1)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to delete scan")
        );

        pool.close().await;
    }

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn postgres_scan_repository_covers_success_and_error_paths() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Ok(url) = std::env::var("CIPHERRUN_TEST_POSTGRES_URL") else {
            return;
        };
        let admin = PgPoolOptions::new()
            .connect_with(PgConnectOptions::from_str(&url).expect("test URL should be valid"))
            .await
            .expect("test PostgreSQL should accept connections");
        let schema = format!("cipherrun_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("test schema should be created");

        let options = PgConnectOptions::from_str(&url)
            .expect("test URL should be valid")
            .options([("search_path", schema.as_str())]);
        let postgres = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test PostgreSQL schema should accept connections");
        let pool = DatabasePool::Postgres(postgres.clone());
        sqlx::query(
            "CREATE TABLE scans (\
                scan_id BIGSERIAL PRIMARY KEY, \
                target_hostname VARCHAR(255) NOT NULL, \
                target_port INTEGER NOT NULL DEFAULT 443, \
                scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                overall_grade VARCHAR(5), overall_score INTEGER, \
                scan_duration_ms BIGINT, revocation_json TEXT, \
                scanner_version VARCHAR(50), principal_id TEXT, \
                tenant_id TEXT, created_by_key_id TEXT\
            )",
        )
        .execute(&postgres)
        .await
        .expect("test scans table should be created");
        let repo = ScanRepositoryImpl::new(pool.clone());
        let scan = ScanRecord::new("example.com".to_string(), 443);
        let scan_id = repo
            .create_scan(&scan)
            .await
            .expect("scan should be inserted");
        let fetched = repo
            .get_scan_by_id(scan_id)
            .await
            .expect("scan lookup should succeed")
            .expect("inserted scan should exist");
        assert_eq!(fetched.target_hostname, "example.com");
        assert_eq!(
            repo.get_scans_by_hostname("example.com", 443, 10)
                .await
                .expect("hostname lookup should succeed")
                .len(),
            1
        );
        assert_eq!(
            repo.get_scans_by_hostname_since(
                "example.com",
                443,
                chrono::Utc::now() - chrono::Duration::minutes(1),
            )
            .await
            .expect("time-bounded lookup should succeed")
            .len(),
            1
        );
        assert_eq!(
            repo.get_latest_scan("example.com", 443)
                .await
                .expect("latest scan lookup should succeed")
                .expect("inserted scan should be latest")
                .scan_id,
            Some(scan_id)
        );
        repo.update_scan_rating(scan_id, "A", 98)
            .await
            .expect("scan rating should update");
        assert_eq!(repo.delete_old_scans(30).await.unwrap(), 0);
        repo.delete_scan(scan_id)
            .await
            .expect("scan should be deleted");
        assert!(repo.get_scan_by_id(scan_id).await.unwrap().is_none());

        let scan = ScanRecord::new("example.com".to_string(), 443);
        let _ = repo.create_scan(&scan).await.unwrap();
        sqlx::query("DROP TABLE scans CASCADE")
            .execute(&postgres)
            .await
            .expect("test should remove the scans table");
        assert!(
            repo.create_scan(&scan)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to insert scan")
        );
        assert!(
            repo.get_scan_by_id(1)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scan")
        );
        assert!(
            repo.get_scans_by_hostname("example.com", 443, 10)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scans")
        );
        assert!(
            repo.get_scans_by_hostname_since("example.com", 443, chrono::Utc::now())
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch scans")
        );
        assert!(
            repo.delete_old_scans(30)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to delete old scans")
        );
        assert!(
            repo.update_scan_rating(1, "A", 98)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to update scan rating")
        );
        assert!(
            repo.delete_scan(1)
                .await
                .unwrap_err()
                .to_string()
                .contains("Failed to delete scan")
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
        admin.close().await;
    }
}
