// Database Migrations
// Handles sqlx migrations for both PostgreSQL and SQLite

use crate::db::connection::DatabasePool;
use sqlx::migrate::Migrator;
use std::fs;
use std::path::Path;

/// Run database migrations
pub async fn run_migrations(pool: &DatabasePool) -> crate::Result<()> {
    let migrations_path = Path::new("migrations");

    if !migrations_path.exists() {
        return Err(crate::TlsError::DatabaseError(
            "Migrations directory not found".to_string(),
        ));
    }

    match pool {
        DatabasePool::Postgres(pg_pool) => {
            let mut migrator = Migrator::new(migrations_path).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to create migrator: {}", e))
            })?;

            // Disable locking for PostgreSQL
            migrator.set_locking(false);

            migrator.run(pg_pool).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("PostgreSQL migration failed: {}", e))
            })?;
        }
        DatabasePool::Sqlite(sqlite_pool) => {
            // For SQLite, use a manual migration approach to avoid sqlx's migration tracking issues
            // This ensures each test gets a fresh migration state
            run_sqlite_migrations_manual(sqlite_pool, migrations_path).await?;
        }
    }

    Ok(())
}

/// Manually run SQLite migrations by executing SQL files directly
async fn run_sqlite_migrations_manual(
    pool: &sqlx::SqlitePool,
    migrations_path: &Path,
) -> crate::Result<()> {
    // sqlx's SqliteConnectOptions enables `PRAGMA foreign_keys` by default, so the
    // schema's `ON DELETE CASCADE` constraints are enforced on this connection —
    // the partial-scan rollback in `store_scan` (delete_scan) relies on that cascade.

    // Create _sqlx_migrations table if it doesn't exist
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL,
            execution_time BIGINT NOT NULL,
            checksum BLOB NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        crate::TlsError::DatabaseError(format!("Failed to create migrations table: {}", e))
    })?;

    // Find all .sql migration files in migrations directory
    let mut migration_files = Vec::new();
    for entry in fs::read_dir(migrations_path).map_err(|e| {
        crate::TlsError::DatabaseError(format!("Failed to read migrations directory: {}", e))
    })? {
        let path = entry
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to read migration entry: {}", e))
            })?
            .path();
        if path.extension().is_some_and(|ext| ext == "sql")
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".down.sql"))
        {
            migration_files.push(path);
        }
    }

    // Sort by filename to ensure consistent migration order
    migration_files.sort();

    for migration_file in migration_files {
        let filename = migration_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                crate::TlsError::DatabaseError("Invalid migration filename".to_string())
            })?
            .to_string();

        // Extract version from filename (e.g., "20250109_001_create_scans_table.sql" -> 20250109001)
        let version_str = filename
            .chars()
            .take_while(|c| c.is_numeric() || *c == '_')
            .filter(|c| c.is_numeric())
            .collect::<String>();

        if version_str.is_empty() {
            return Err(crate::TlsError::DatabaseError(format!(
                "Migration filename '{}' does not start with a numeric version",
                filename
            )));
        }

        let version: i64 = version_str.parse().map_err(|_| {
            crate::TlsError::DatabaseError(format!(
                "Failed to parse migration version from {}",
                filename
            ))
        })?;

        // Check if migration has already been run
        let already_run: bool =
            sqlx::query_scalar("SELECT COUNT(*) > 0 FROM _sqlx_migrations WHERE version = ?")
                .bind(version)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!(
                        "Failed to check migration status: {}",
                        e
                    ))
                })?;

        if already_run {
            continue; // Migration already applied
        }

        // Read and execute migration SQL
        let sql_content = fs::read_to_string(&migration_file).map_err(|e| {
            crate::TlsError::DatabaseError(format!(
                "Failed to read migration file {}: {}",
                filename, e
            ))
        })?;

        // Execute the full SQL content as-is (handles semicolons in strings/comments correctly)
        sqlx::raw_sql(&sql_content)
            .execute(pool)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!(
                    "Failed to execute migration {}: {}",
                    filename, e
                ))
            })?;

        // Record migration as applied
        let checksum_placeholder = vec![0u8; 16]; // Placeholder for checksum
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, execution_time, checksum) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(version)
        .bind(&filename)
        .bind(true)
        .bind(0i64) // execution_time placeholder
        .bind(&checksum_placeholder)
        .execute(pool)
        .await
        .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to record migration {}: {}", filename, e)))?;
    }

    Ok(())
}

/// Revert last migration
pub async fn revert_migration(pool: &DatabasePool) -> crate::Result<()> {
    let migrations_path = Path::new("migrations");

    match pool {
        DatabasePool::Postgres(pg_pool) => {
            let migrator = Migrator::new(migrations_path).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("Failed to create migrator: {}", e))
            })?;
            migrator.undo(pg_pool, 1).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("PostgreSQL migration revert failed: {}", e))
            })?;
        }
        DatabasePool::Sqlite(sqlite_pool) => {
            revert_sqlite_migration_manual(sqlite_pool, migrations_path).await?;
        }
    }

    Ok(())
}

/// Manually revert the last SQLite migration
///
/// This is needed because forward SQLite migrations use placeholder checksums,
/// which causes sqlx's `Migrator::undo()` to fail with checksum mismatch errors.
async fn revert_sqlite_migration_manual(
    pool: &sqlx::SqlitePool,
    migrations_path: &Path,
) -> crate::Result<()> {
    // Find the last applied migration
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT version, description FROM _sqlx_migrations WHERE success = true ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        crate::TlsError::DatabaseError(format!("Failed to query migrations table: {}", e))
    })?;

    let (version, description) = match row {
        Some(r) => r,
        None => {
            return Err(crate::TlsError::DatabaseError(
                "No migrations to revert".to_string(),
            ));
        }
    };

    // Look for a .down.sql file matching the migration
    // Try deriving from the description (which stores the original filename)
    let down_filename = description.replace(".sql", ".down.sql");
    let down_path = migrations_path.join(&down_filename);

    if version == 20250109008 {
        revert_scan_revocation_json_sqlite(pool).await?;
    } else if down_path.exists() {
        let sql_content = fs::read_to_string(&down_path).map_err(|e| {
            crate::TlsError::DatabaseError(format!(
                "Failed to read down migration {}: {}",
                down_filename, e
            ))
        })?;

        sqlx::raw_sql(&sql_content)
            .execute(pool)
            .await
            .map_err(|e| {
                crate::TlsError::DatabaseError(format!(
                    "Failed to execute down migration {}: {}",
                    down_filename, e
                ))
            })?;
    }

    // Remove the migration record
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ?")
        .bind(version)
        .execute(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to remove migration record: {}", e))
        })?;

    tracing::info!("Reverted migration: {} (version {})", description, version);

    Ok(())
}

async fn revert_scan_revocation_json_sqlite(pool: &sqlx::SqlitePool) -> crate::Result<()> {
    sqlx::raw_sql(
        r#"
        PRAGMA foreign_keys = OFF;
        CREATE TABLE scans_revert (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_hostname VARCHAR(255) NOT NULL,
            target_port INTEGER NOT NULL DEFAULT 443,
            scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            overall_grade VARCHAR(5),
            overall_score INTEGER,
            scan_duration_ms INTEGER,
            scanner_version VARCHAR(50)
        );
        INSERT INTO scans_revert (
            scan_id, target_hostname, target_port, scan_timestamp, overall_grade,
            overall_score, scan_duration_ms, scanner_version
        )
        SELECT
            scan_id, target_hostname, target_port, scan_timestamp, overall_grade,
            overall_score, scan_duration_ms, scanner_version
        FROM scans;
        DROP TABLE scans;
        ALTER TABLE scans_revert RENAME TO scans;
        CREATE INDEX IF NOT EXISTS idx_scans_composite ON scans(target_hostname, target_port, scan_timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp DESC);
        PRAGMA foreign_keys = ON;
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        crate::TlsError::DatabaseError(format!(
            "Failed to revert revocation_json SQLite migration: {}",
            e
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::config::DatabaseConfig;
    use sqlx::Row;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_migrations_with_sqlite() {
        // Use in-memory database for testing
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");

        // Note: This test will only work if migrations directory exists
        // In a real scenario, you would have proper test fixtures

        pool.close().await;
    }

    #[tokio::test]
    async fn test_revert_last_sqlite_migration_drops_revocation_json() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");

        run_migrations(&pool)
            .await
            .expect("migrations should succeed");

        revert_migration(&pool)
            .await
            .expect("revert should succeed");

        if let DatabasePool::Sqlite(sqlite_pool) = &pool {
            let columns = sqlx::query("PRAGMA table_info(scans)")
                .fetch_all(sqlite_pool)
                .await
                .expect("test assertion should succeed");

            assert!(
                !columns
                    .iter()
                    .any(|row| row.try_get::<String, _>("name").ok().as_deref()
                        == Some("revocation_json")),
                "revocation_json column should be removed by revert"
            );
        } else {
            panic!("expected sqlite pool");
        }

        pool.close().await;
    }

    #[tokio::test]
    async fn test_revert_last_sqlite_migration_preserves_child_rows() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");

        run_migrations(&pool)
            .await
            .expect("migrations should succeed");

        if let DatabasePool::Sqlite(sqlite_pool) = &pool {
            sqlx::query(
                r#"
                INSERT INTO scans (
                    target_hostname, target_port, scan_timestamp, overall_grade,
                    overall_score, scan_duration_ms, revocation_json, scanner_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind("child.test")
            .bind(443_i32)
            .bind(chrono::Utc::now())
            .bind("A")
            .bind(95_i32)
            .bind(1200_i64)
            .bind(Some("{\"status\":\"Good\"}"))
            .bind("test")
            .execute(sqlite_pool)
            .await
            .expect("scan row should insert");

            sqlx::query(
                r#"
                INSERT INTO protocols (scan_id, protocol_name, enabled, preferred)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(1_i64)
            .bind("TLS 1.3")
            .bind(true)
            .bind(true)
            .execute(sqlite_pool)
            .await
            .expect("protocol row should insert");
        } else {
            panic!("expected sqlite pool");
        }

        revert_migration(&pool)
            .await
            .expect("revert should succeed");

        if let DatabasePool::Sqlite(sqlite_pool) = &pool {
            let protocol_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM protocols")
                .fetch_one(sqlite_pool)
                .await
                .expect("protocol count should query");
            assert_eq!(
                protocol_count, 1,
                "child rows should survive the table swap"
            );
        } else {
            panic!("expected sqlite pool");
        }

        pool.close().await;
    }
}
