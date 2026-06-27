use crate::application::{ScanHistoryEntry, ScanHistoryPort, ScanHistoryQuery};
use crate::db::DatabasePool;
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

pub struct ScanHistoryService<'a> {
    pool: &'a DatabasePool,
}

impl<'a> ScanHistoryService<'a> {
    pub fn new(pool: &'a DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl<'a> ScanHistoryPort for ScanHistoryService<'a> {
    async fn get_history(&self, query: &ScanHistoryQuery) -> crate::Result<Vec<ScanHistoryEntry>> {
        get_scan_history(self.pool, query).await
    }
}

pub async fn get_scan_history(
    pool: &DatabasePool,
    query: &ScanHistoryQuery,
) -> crate::Result<Vec<ScanHistoryEntry>> {
    match pool {
        DatabasePool::Postgres(pool) => fetch_history_postgres(pool, query).await,
        DatabasePool::Sqlite(pool) => fetch_history_sqlite(pool, query).await,
    }
}

async fn fetch_history_postgres(
    pool: &sqlx::PgPool,
    query: &ScanHistoryQuery,
) -> crate::Result<Vec<ScanHistoryEntry>> {
    let rows = sqlx::query(
        r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE target_hostname = $1 AND target_port = $2
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT $3
        "#,
    )
    .bind(&query.hostname)
    .bind(query.port as i32)
    .bind(i64::try_from(query.limit).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e)))?;

    rows.into_iter()
        .map(scan_history_entry_from_pg_row)
        .collect()
}

async fn fetch_history_sqlite(
    pool: &sqlx::SqlitePool,
    query: &ScanHistoryQuery,
) -> crate::Result<Vec<ScanHistoryEntry>> {
    let rows = sqlx::query(
        r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE target_hostname = ? AND target_port = ?
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT ?
        "#,
    )
    .bind(&query.hostname)
    .bind(query.port as i32)
    .bind(i64::try_from(query.limit).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e)))?;

    rows.into_iter()
        .map(scan_history_entry_from_sqlite_row)
        .collect()
}

fn scan_history_field_error(field: &str, error: impl std::fmt::Display) -> crate::TlsError {
    crate::TlsError::DatabaseError(format!("Invalid scan history field {}: {}", field, error))
}

fn normalize_scan_id(id: i64) -> crate::Result<u64> {
    if id < 0 {
        return Err(crate::TlsError::DatabaseError(format!(
            "Invalid scan history field scan_id: negative value {}",
            id
        )));
    }
    u64::try_from(id).map_err(|e| scan_history_field_error("scan_id", e))
}

fn normalize_score(score: i32) -> crate::Result<u8> {
    if !(0..=100).contains(&score) {
        return Err(crate::TlsError::DatabaseError(format!(
            "Invalid scan history field overall_score: out of range {}",
            score
        )));
    }
    u8::try_from(score).map_err(|e| scan_history_field_error("overall_score", e))
}

fn normalize_duration(duration_ms: i64) -> crate::Result<u64> {
    if duration_ms < 0 {
        return Err(crate::TlsError::DatabaseError(format!(
            "Invalid scan history field scan_duration_ms: negative value {}",
            duration_ms
        )));
    }
    u64::try_from(duration_ms).map_err(|e| scan_history_field_error("scan_duration_ms", e))
}

fn scan_history_entry_from_pg_row(row: PgRow) -> crate::Result<ScanHistoryEntry> {
    let scan_id = row
        .try_get("scan_id")
        .map_err(|e| scan_history_field_error("scan_id", e))
        .and_then(normalize_scan_id)?;
    let timestamp = row
        .try_get("scan_timestamp")
        .map_err(|e| scan_history_field_error("scan_timestamp", e))?;
    let grade = row
        .try_get("overall_grade")
        .map_err(|e| scan_history_field_error("overall_grade", e))?;
    let score = row
        .try_get::<Option<i32>, _>("overall_score")
        .map_err(|e| scan_history_field_error("overall_score", e))?
        .map(normalize_score)
        .transpose()?;
    let duration_ms = row
        .try_get::<Option<i64>, _>("scan_duration_ms")
        .map_err(|e| scan_history_field_error("scan_duration_ms", e))?
        .map(normalize_duration)
        .transpose()?;

    Ok(ScanHistoryEntry {
        scan_id,
        timestamp,
        grade,
        score,
        duration_ms,
    })
}

fn scan_history_entry_from_sqlite_row(row: SqliteRow) -> crate::Result<ScanHistoryEntry> {
    let scan_id = row
        .try_get("scan_id")
        .map_err(|e| scan_history_field_error("scan_id", e))
        .and_then(normalize_scan_id)?;
    let timestamp = row
        .try_get("scan_timestamp")
        .map_err(|e| scan_history_field_error("scan_timestamp", e))?;
    let grade = row
        .try_get("overall_grade")
        .map_err(|e| scan_history_field_error("overall_grade", e))?;
    let score = row
        .try_get::<Option<i32>, _>("overall_score")
        .map_err(|e| scan_history_field_error("overall_score", e))?
        .map(normalize_score)
        .transpose()?;
    let duration_ms = row
        .try_get::<Option<i64>, _>("scan_duration_ms")
        .map_err(|e| scan_history_field_error("scan_duration_ms", e))?
        .map(normalize_duration)
        .transpose()?;

    Ok(ScanHistoryEntry {
        scan_id,
        timestamp,
        grade,
        score,
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DatabaseConfig, DatabasePool, run_migrations};
    use std::path::PathBuf;

    #[tokio::test]
    async fn sqlite_scan_history_service_returns_latest_first() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("pool should be created");
        run_migrations(&pool).await.expect("migrations should run");

        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        sqlx::query(
            r#"
            INSERT INTO scans (
                target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind("example.com")
        .bind(443_i32)
        .bind(chrono::Utc::now() - chrono::Duration::minutes(5))
        .bind("B")
        .bind(80_i32)
        .bind(1500_i64)
        .execute(sqlite)
        .await
        .expect("first row");

        sqlx::query(
            r#"
            INSERT INTO scans (
                target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind("example.com")
        .bind(443_i32)
        .bind(chrono::Utc::now())
        .bind("A")
        .bind(95_i32)
        .bind(1200_i64)
        .execute(sqlite)
        .await
        .expect("second row");

        let service = ScanHistoryService::new(&pool);
        let entries = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 10,
            })
            .await
            .expect("history should load");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].grade.as_deref(), Some("A"));
        assert_eq!(entries[1].grade.as_deref(), Some("B"));
    }

    #[tokio::test]
    async fn sqlite_scan_history_rejects_invalid_timestamp() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("pool should be created");
        run_migrations(&pool).await.expect("migrations should run");

        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        sqlx::query(
            r#"
            INSERT INTO scans (
                target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind("invalid-history.test")
        .bind(443_i32)
        .bind("not-a-timestamp")
        .bind("A")
        .bind(95_i32)
        .bind(1200_i64)
        .execute(sqlite)
        .await
        .expect("row should insert");

        let service = ScanHistoryService::new(&pool);
        let err = service
            .get_history(&ScanHistoryQuery {
                hostname: "invalid-history.test".to_string(),
                port: 443,
                limit: 10,
            })
            .await
            .expect_err("invalid scan timestamp should fail history loading");

        assert!(
            err.to_string()
                .contains("Invalid scan history field scan_timestamp")
        );
    }
}
