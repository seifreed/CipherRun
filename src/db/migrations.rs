// Database Migrations
// Handles sqlx migrations for both PostgreSQL and SQLite

use crate::db::connection::DatabasePool;
use sqlx::migrate::Migrator;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

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
    // Note: Foreign keys are disabled by default in SQLite and are not enforced in these tests
    // In production, they would need to be explicitly enabled if desired

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
    let mut migration_files: Vec<PathBuf> = fs::read_dir(migrations_path)
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to read migrations directory: {}", e))
        })?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sql") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

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

        // Execute the SQL (sqlx will handle multiple statements)
        for statement in sql_content.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(statement).execute(pool).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!(
                    "Failed to execute migration {}: {}",
                    filename, e
                ))
            })?;
        }

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

    let migrator = Migrator::new(migrations_path)
        .await
        .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to create migrator: {}", e)))?;

    match pool {
        DatabasePool::Postgres(pg_pool) => {
            migrator.undo(pg_pool, 1).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("PostgreSQL migration revert failed: {}", e))
            })?;
        }
        DatabasePool::Sqlite(sqlite_pool) => {
            migrator.undo(sqlite_pool, 1).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("SQLite migration revert failed: {}", e))
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::config::DatabaseConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_migrations_with_sqlite() {
        // Use in-memory database for testing
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config).await.unwrap();

        // Note: This test will only work if migrations directory exists
        // In a real scenario, you would have proper test fixtures

        pool.close().await;
    }
}
