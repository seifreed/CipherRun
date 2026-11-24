use crate::application::{ScanHistoryEntry, ScanHistoryPage, ScanHistoryPort, ScanHistoryQuery};
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
    async fn get_history(&self, query: &ScanHistoryQuery) -> crate::Result<ScanHistoryPage> {
        get_scan_history(self.pool, query).await
    }
}

#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(event_name = "database.operation", operation = "scan_history.list")
)]
pub async fn get_scan_history(
    pool: &DatabasePool,
    query: &ScanHistoryQuery,
) -> crate::Result<ScanHistoryPage> {
    match pool {
        DatabasePool::Postgres(pool) => fetch_history_postgres(pool, query).await,
        DatabasePool::Sqlite(pool) => fetch_history_sqlite(pool, query).await,
    }
}

async fn fetch_history_postgres(
    pool: &sqlx::PgPool,
    query: &ScanHistoryQuery,
) -> crate::Result<ScanHistoryPage> {
    let total_scans = count_history_postgres(pool, query).await?;
    let rows = if let Some(principal_id) = &query.principal_id {
        sqlx::query(
            r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE LOWER(target_hostname) = $1 AND target_port = $2
          AND principal_id = $3 AND tenant_id IS NOT DISTINCT FROM $4
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT $5
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(principal_id)
        .bind(&query.tenant_id)
        .bind(scan_history_limit(query.limit)?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
        })?
    } else {
        sqlx::query(
            r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE LOWER(target_hostname) = $1 AND target_port = $2
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT $3
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(scan_history_limit(query.limit)?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
        })?
    };

    collect_page(total_scans, rows, scan_history_entry_from_pg_row)
}

async fn fetch_history_sqlite(
    pool: &sqlx::SqlitePool,
    query: &ScanHistoryQuery,
) -> crate::Result<ScanHistoryPage> {
    let total_scans = count_history_sqlite(pool, query).await?;
    let rows = if let Some(principal_id) = &query.principal_id {
        sqlx::query(
            r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE LOWER(target_hostname) = ? AND target_port = ?
          AND principal_id = ? AND tenant_id IS ?
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT ?
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(principal_id)
        .bind(&query.tenant_id)
        .bind(scan_history_limit(query.limit)?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
        })?
    } else {
        sqlx::query(
            r#"
        SELECT scan_id, scan_timestamp, overall_grade, overall_score, scan_duration_ms
        FROM scans
        WHERE LOWER(target_hostname) = ? AND target_port = ?
        ORDER BY scan_timestamp DESC, scan_id DESC
        LIMIT ?
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(scan_history_limit(query.limit)?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history: {}", e))
        })?
    };

    collect_page(total_scans, rows, scan_history_entry_from_sqlite_row)
}

async fn count_history_postgres(
    pool: &sqlx::PgPool,
    query: &ScanHistoryQuery,
) -> crate::Result<usize> {
    let count: i64 = if let Some(principal_id) = &query.principal_id {
        sqlx::query_scalar(
            r#"
        SELECT COUNT(*) FROM scans
        WHERE LOWER(target_hostname) = $1 AND target_port = $2
          AND principal_id = $3 AND tenant_id IS NOT DISTINCT FROM $4
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(principal_id)
        .bind(&query.tenant_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history count: {}", e))
        })?
    } else {
        sqlx::query_scalar(
            r#"
        SELECT COUNT(*)
        FROM scans
        WHERE LOWER(target_hostname) = $1 AND target_port = $2
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history count: {}", e))
        })?
    };

    usize::try_from(count)
        .map_err(|e| crate::TlsError::DatabaseError(format!("Invalid scan history count: {}", e)))
}

async fn count_history_sqlite(
    pool: &sqlx::SqlitePool,
    query: &ScanHistoryQuery,
) -> crate::Result<usize> {
    let count: i64 = if let Some(principal_id) = &query.principal_id {
        sqlx::query_scalar(
            r#"
        SELECT COUNT(*) FROM scans
        WHERE LOWER(target_hostname) = ? AND target_port = ?
          AND principal_id = ? AND tenant_id IS ?
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .bind(principal_id)
        .bind(&query.tenant_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history count: {}", e))
        })?
    } else {
        sqlx::query_scalar(
            r#"
        SELECT COUNT(*)
        FROM scans
        WHERE LOWER(target_hostname) = ? AND target_port = ?
        "#,
        )
        .bind(&query.hostname)
        .bind(query.port as i32)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to query scan history count: {}", e))
        })?
    };

    usize::try_from(count)
        .map_err(|e| crate::TlsError::DatabaseError(format!("Invalid scan history count: {}", e)))
}

fn scan_history_field_error(field: &str, error: impl std::fmt::Display) -> crate::TlsError {
    crate::TlsError::DatabaseError(format!("Invalid scan history field {}: {}", field, error))
}

fn scan_history_limit(limit: usize) -> crate::Result<i64> {
    i64::try_from(limit).map_err(|error| {
        crate::TlsError::DatabaseError(format!("Invalid scan history limit: {}", error))
    })
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

fn collect_page<T, F>(
    total_scans: usize,
    rows: Vec<T>,
    mut mapper: F,
) -> crate::Result<ScanHistoryPage>
where
    F: FnMut(T) -> crate::Result<ScanHistoryEntry>,
{
    let scans = rows
        .into_iter()
        .map(&mut mapper)
        .collect::<crate::Result<Vec<_>>>()?;
    Ok(ScanHistoryPage { total_scans, scans })
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

    async fn sqlite_pool() -> DatabasePool {
        let config = DatabaseConfig::sqlite(std::path::PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("pool should be created");
        run_migrations(&pool).await.expect("migrations should run");
        pool
    }

    #[tokio::test]
    async fn sqlite_scan_history_service_returns_latest_first() {
        let pool = sqlite_pool().await;

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
        let page = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 10,
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect("history should load");

        assert_eq!(page.total_scans, 2);
        assert_eq!(page.scans.len(), 2);
        assert_eq!(page.scans[0].grade.as_deref(), Some("A"));
        assert_eq!(page.scans[1].grade.as_deref(), Some("B"));
    }

    #[tokio::test]
    async fn sqlite_scan_history_matches_hostname_case_insensitively() {
        let pool = sqlite_pool().await;

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
        .bind("EXAMPLE.COM")
        .bind(443_i32)
        .bind(chrono::Utc::now())
        .bind("A")
        .bind(95_i32)
        .bind(1200_i64)
        .execute(sqlite)
        .await
        .expect("row should insert");

        let service = ScanHistoryService::new(&pool);
        let page = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 10,
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect("history should load");

        assert_eq!(page.total_scans, 1);
        assert_eq!(page.scans.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_scan_history_isolated_by_principal_and_tenant() {
        let pool = sqlite_pool().await;
        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        for principal in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO scans (target_hostname, target_port, principal_id, tenant_id) VALUES (?, ?, ?, ?)",
            )
            .bind("owned-history.test")
            .bind(443_i32)
            .bind(principal)
            .bind("tenant-a")
            .execute(sqlite)
            .await
            .expect("owned scan should insert");
        }

        let page = ScanHistoryService::new(&pool)
            .get_history(&ScanHistoryQuery {
                hostname: "owned-history.test".to_string(),
                port: 443,
                limit: 10,
                principal_id: Some("alice".to_string()),
                tenant_id: Some("tenant-a".to_string()),
            })
            .await
            .expect("owned history should load");

        assert_eq!(page.total_scans, 1);
    }

    #[tokio::test]
    async fn sqlite_scan_history_isolated_by_principal_without_tenant() {
        let pool = sqlite_pool().await;
        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        for (principal, tenant) in [("alice", None), ("alice", Some("tenant-a")), ("bob", None)] {
            sqlx::query(
                "INSERT INTO scans (target_hostname, target_port, principal_id, tenant_id) VALUES (?, ?, ?, ?)",
            )
            .bind("owned-history.test")
            .bind(443_i32)
            .bind(principal)
            .bind(tenant)
            .execute(sqlite)
            .await
            .expect("owned scan should insert");
        }

        let page = ScanHistoryService::new(&pool)
            .get_history(&ScanHistoryQuery {
                hostname: "owned-history.test".to_string(),
                port: 443,
                limit: 10,
                principal_id: Some("alice".to_string()),
                tenant_id: None,
            })
            .await
            .expect("history with a null tenant should load");

        assert_eq!(page.total_scans, 1);
        assert_eq!(page.scans.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_scan_history_rejects_invalid_numeric_fields() {
        let pool = sqlite_pool().await;
        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        for (hostname, scan_id, score, duration, expected_field) in [
            ("negative-id.test", Some(-1_i64), 80_i32, 100_i64, "scan_id"),
            (
                "invalid-score.test",
                None,
                101_i32,
                100_i64,
                "overall_score",
            ),
            (
                "negative-duration.test",
                None,
                80_i32,
                -1_i64,
                "scan_duration_ms",
            ),
        ] {
            sqlx::query(
                "INSERT INTO scans (scan_id, target_hostname, target_port, overall_grade, overall_score, scan_duration_ms) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(scan_id)
            .bind(hostname)
            .bind(443_i32)
            .bind("A")
            .bind(score)
            .bind(duration)
            .execute(sqlite)
            .await
            .expect("malformed history row should be insertable for validation test");

            let error = ScanHistoryService::new(&pool)
                .get_history(&ScanHistoryQuery {
                    hostname: hostname.to_string(),
                    port: 443,
                    limit: 10,
                    principal_id: None,
                    tenant_id: None,
                })
                .await
                .expect_err("malformed numeric history values should be rejected");
            assert!(error.to_string().contains(expected_field), "{error}");
        }
    }

    #[tokio::test]
    async fn sqlite_scan_history_rejects_limit_overflow_after_counting() {
        let pool = sqlite_pool().await;

        let error = ScanHistoryService::new(&pool)
            .get_history(&ScanHistoryQuery {
                hostname: "empty-history.test".to_string(),
                port: 443,
                limit: usize::MAX,
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect_err("an overflowing limit should fail before issuing the page query");

        assert!(error.to_string().contains("Invalid scan history limit"));
    }

    #[tokio::test]
    async fn sqlite_scan_history_rejects_invalid_timestamp() {
        let pool = sqlite_pool().await;

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
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect_err("invalid scan timestamp should fail history loading");

        assert!(
            err.to_string()
                .contains("Invalid scan history field scan_timestamp")
        );
    }

    #[tokio::test]
    async fn sqlite_scan_history_reports_total_count_independently_of_limit() {
        let pool = sqlite_pool().await;

        let DatabasePool::Sqlite(sqlite) = &pool else {
            panic!("expected sqlite pool");
        };

        for i in 0..3 {
            sqlx::query(
                r#"
                INSERT INTO scans (
                    target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind("paged-history.test")
            .bind(443_i32)
            .bind(chrono::Utc::now() - chrono::Duration::minutes(i))
            .bind("A")
            .bind(95_i32)
            .bind(1200_i64)
            .execute(sqlite)
            .await
            .expect("row should insert");
        }

        let service = ScanHistoryService::new(&pool);
        let page = service
            .get_history(&ScanHistoryQuery {
                hostname: "paged-history.test".to_string(),
                port: 443,
                limit: 1,
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect("history should load");

        assert_eq!(page.total_scans, 3);
        assert_eq!(page.scans.len(), 1);
    }

    #[cfg(feature = "db-postgres")]
    #[tokio::test]
    async fn postgres_scan_history_filters_owners_and_maps_rows() {
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
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test schema should accept connections");
        sqlx::query(
            "CREATE TABLE scans (\
                scan_id BIGSERIAL PRIMARY KEY, target_hostname TEXT NOT NULL, \
                target_port INTEGER NOT NULL, scan_timestamp TIMESTAMPTZ NOT NULL, \
                overall_grade TEXT, overall_score INTEGER, scan_duration_ms BIGINT, \
                principal_id TEXT, tenant_id TEXT\
            )",
        )
        .execute(&pool)
        .await
        .expect("test scans table should be created");

        let now = chrono::Utc::now();
        for (principal, tenant, grade, score) in [
            ("alice", Some("tenant-a"), "A", 95_i32),
            ("alice", None, "B", 80_i32),
            ("bob", Some("tenant-a"), "C", 60_i32),
        ] {
            sqlx::query(
                "INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, principal_id, tenant_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind("Example.com")
            .bind(443_i32)
            .bind(now)
            .bind(grade)
            .bind(score)
            .bind(1250_i64)
            .bind(principal)
            .bind(tenant)
            .execute(&pool)
            .await
            .expect("history row should insert");
        }

        let database = DatabasePool::Postgres(pool.clone());
        let service = ScanHistoryService::new(&database);
        let all = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 2,
                principal_id: None,
                tenant_id: None,
            })
            .await
            .expect("PostgreSQL history should load");
        assert_eq!(all.total_scans, 3);
        assert_eq!(all.scans.len(), 2);
        assert_eq!(all.scans[0].grade.as_deref(), Some("C"));
        assert_eq!(all.scans[0].score, Some(60));
        assert_eq!(all.scans[0].duration_ms, Some(1250));

        let tenant_history = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 10,
                principal_id: Some("alice".to_string()),
                tenant_id: Some("tenant-a".to_string()),
            })
            .await
            .expect("tenant-scoped history should load");
        assert_eq!(tenant_history.total_scans, 1);
        assert_eq!(tenant_history.scans[0].grade.as_deref(), Some("A"));

        let null_tenant_history = service
            .get_history(&ScanHistoryQuery {
                hostname: "example.com".to_string(),
                port: 443,
                limit: 10,
                principal_id: Some("alice".to_string()),
                tenant_id: None,
            })
            .await
            .expect("principal history with a null tenant should load");
        assert_eq!(null_tenant_history.total_scans, 1);
        assert_eq!(null_tenant_history.scans[0].grade.as_deref(), Some("B"));

        for (row_query, field) in [
            (
                "SELECT 'bad'::TEXT AS scan_id, TIMESTAMPTZ '2026-01-01 00:00:00+00' AS scan_timestamp, 'A'::TEXT AS overall_grade, 90::INTEGER AS overall_score, 100::BIGINT AS scan_duration_ms",
                "scan_id",
            ),
            (
                "SELECT 1::BIGINT AS scan_id, 'bad'::TEXT AS scan_timestamp, 'A'::TEXT AS overall_grade, 90::INTEGER AS overall_score, 100::BIGINT AS scan_duration_ms",
                "scan_timestamp",
            ),
            (
                "SELECT 1::BIGINT AS scan_id, TIMESTAMPTZ '2026-01-01 00:00:00+00' AS scan_timestamp, 1::INTEGER AS overall_grade, 90::INTEGER AS overall_score, 100::BIGINT AS scan_duration_ms",
                "overall_grade",
            ),
            (
                "SELECT 1::BIGINT AS scan_id, TIMESTAMPTZ '2026-01-01 00:00:00+00' AS scan_timestamp, 'A'::TEXT AS overall_grade, 'bad'::TEXT AS overall_score, 100::BIGINT AS scan_duration_ms",
                "overall_score",
            ),
            (
                "SELECT 1::BIGINT AS scan_id, TIMESTAMPTZ '2026-01-01 00:00:00+00' AS scan_timestamp, 'A'::TEXT AS overall_grade, 90::INTEGER AS overall_score, 'bad'::TEXT AS scan_duration_ms",
                "scan_duration_ms",
            ),
        ] {
            let row = sqlx::query(row_query)
                .fetch_one(&pool)
                .await
                .expect("malformed typed row should be queryable");
            let error = scan_history_entry_from_pg_row(row)
                .expect_err("invalid history field type should be rejected");
            assert!(error.to_string().contains(field), "{error}");
        }

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
        admin.close().await;
    }

    #[test]
    fn scan_history_limit_rejects_i64_overflow() {
        let err = scan_history_limit(usize::MAX).expect_err("overflowing limit should fail loudly");

        assert!(err.to_string().contains("Invalid scan history limit"));
    }
}
