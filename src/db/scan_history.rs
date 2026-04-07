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
        ORDER BY scan_timestamp DESC
        LIMIT $3
        "#,
    )
    .bind(&query.hostname)
    .bind(query.port as i32)
    .bind(query.limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e)))?;

    Ok(rows
        .into_iter()
        .map(scan_history_entry_from_pg_row)
        .collect())
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
        ORDER BY scan_timestamp DESC
        LIMIT ?
        "#,
    )
    .bind(&query.hostname)
    .bind(query.port as i32)
    .bind(query.limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e)))?;

    Ok(rows
        .into_iter()
        .map(scan_history_entry_from_sqlite_row)
        .collect())
}

fn scan_history_entry_from_pg_row(row: PgRow) -> ScanHistoryEntry {
    ScanHistoryEntry {
        scan_id: {
            let id = row.get::<i64, _>("scan_id");
            if id < 0 {
                tracing::error!(
                    "Corrupt negative scan_id {} in database, using absolute value",
                    id
                );
            }
            id.unsigned_abs()
        },
        timestamp: row.get("scan_timestamp"),
        grade: row.get("overall_grade"),
        score: row.get::<Option<i32>, _>("overall_score").map(|score| {
            if !(0..=100).contains(&score) {
                tracing::warn!("Score {} out of valid range [0,100], clamping", score);
            }
            score.clamp(0, 100) as u8
        }),
        duration_ms: row
            .get::<Option<i64>, _>("scan_duration_ms")
            .map(|d| d.max(0) as u64),
    }
}

fn scan_history_entry_from_sqlite_row(row: SqliteRow) -> ScanHistoryEntry {
    ScanHistoryEntry {
        scan_id: {
            let id = row.get::<i64, _>("scan_id");
            if id < 0 {
                tracing::error!(
                    "Corrupt negative scan_id {} in database, using absolute value",
                    id
                );
            }
            id.unsigned_abs()
        },
        timestamp: row.get("scan_timestamp"),
        grade: row.get("overall_grade"),
        score: row.get::<Option<i32>, _>("overall_score").map(|score| {
            if !(0..=100).contains(&score) {
                tracing::warn!("Score {} out of valid range [0,100], clamping", score);
            }
            score.clamp(0, 100) as u8
        }),
        duration_ms: row
            .get::<Option<i64>, _>("scan_duration_ms")
            .map(|d| d.max(0) as u64),
    }
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
}
