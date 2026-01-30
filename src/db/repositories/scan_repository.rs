// Scan Repository Implementation
// Handles database operations for scan records

use crate::db::connection::DatabasePool;
use crate::db::models::ScanRecord;
use crate::db::traits::ScanRepository;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use sqlx::Row;

pub struct ScanRepositoryImpl {
    pool: DatabasePool,
}

impl ScanRepositoryImpl {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScanRepository for ScanRepositoryImpl {
    async fn create_scan(&self, scan: &ScanRecord) -> crate::Result<i64> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query(
                    r#"
                    INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING scan_id
                    "#
                )
                .bind(&scan.target_hostname)
                .bind(scan.target_port)
                .bind(scan.scan_timestamp)
                .bind(&scan.overall_grade)
                .bind(scan.overall_score)
                .bind(scan.scan_duration_ms)
                .bind(&scan.scanner_version)
                .fetch_one(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert scan: {}", e)))?;

                Ok(result.get("scan_id"))
            }
            DatabasePool::Sqlite(pool) => {
                let result = sqlx::query(
                    r#"
                    INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&scan.target_hostname)
                .bind(scan.target_port)
                .bind(scan.scan_timestamp)
                .bind(&scan.overall_grade)
                .bind(scan.overall_score)
                .bind(scan.scan_duration_ms)
                .bind(&scan.scanner_version)
                .execute(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to insert scan: {}", e)))?;

                Ok(result.last_insert_rowid())
            }
        }
    }

    async fn get_scan_by_id(&self, scan_id: i64) -> crate::Result<Option<ScanRecord>> {
        match &self.pool {
            DatabasePool::Postgres(pool) => {
                let result = sqlx::query_as::<_, ScanRecord>(
                    r#"
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version
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
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version
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
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version
                    FROM scans
                    WHERE target_hostname = $1 AND target_port = $2
                    ORDER BY scan_timestamp DESC
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
                    SELECT scan_id, target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, scanner_version
                    FROM scans
                    WHERE target_hostname = ? AND target_port = ?
                    ORDER BY scan_timestamp DESC
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

    async fn get_latest_scan(
        &self,
        hostname: &str,
        port: u16,
    ) -> crate::Result<Option<ScanRecord>> {
        let scans = self.get_scans_by_hostname(hostname, port, 1).await?;
        Ok(scans.into_iter().next())
    }

    async fn delete_old_scans(&self, days: i64) -> crate::Result<u64> {
        let cutoff_date = Utc::now() - Duration::days(days);

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
    use crate::db::config::DatabaseConfig;
    use crate::db::migrations::run_migrations;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_scan_repository() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");

        // Run migrations to create tables
        run_migrations(&pool)
            .await
            .expect("test assertion should succeed");

        // Create repository
        let repo = ScanRepositoryImpl::new(pool.clone());

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
}
