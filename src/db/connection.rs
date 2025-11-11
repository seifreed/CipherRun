// Database Connection Pool
// Manages PostgreSQL and SQLite connection pools with sqlx

use crate::db::config::{DatabaseConfig, DatabaseType};
use sqlx::{Pool, Postgres, Sqlite};
use std::str::FromStr;
use std::time::Duration;

/// Database pool enum supporting both PostgreSQL and SQLite
#[derive(Clone)]
pub enum DatabasePool {
    Postgres(Pool<Postgres>),
    Sqlite(Pool<Sqlite>),
}

impl DatabasePool {
    /// Create a new database pool from configuration
    pub async fn new(config: &DatabaseConfig) -> crate::Result<Self> {
        let pool = match config.db_type {
            DatabaseType::Postgres => {
                let connection_string = config.connection_string()?;
                let max_connections = config.max_connections.unwrap_or(10);

                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(max_connections)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect(&connection_string)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!(
                            "PostgreSQL connection failed: {}",
                            e
                        ))
                    })?;

                DatabasePool::Postgres(pool)
            }
            DatabaseType::Sqlite => {
                let connection_string = config.connection_string()?;

                // Use sqlx's built-in URI parsing for SQLite connections
                // This properly handles both file paths and special SQLite URIs
                let connect_options =
                    sqlx::sqlite::SqliteConnectOptions::from_str(&connection_string)
                        .map_err(|e| {
                            crate::TlsError::DatabaseError(format!(
                                "Failed to parse SQLite connection string: {}",
                                e
                            ))
                        })?
                        .create_if_missing(true);

                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1) // SQLite is single-writer
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_with(connect_options)
                    .await
                    .map_err(|e| {
                        crate::TlsError::DatabaseError(format!("SQLite connection failed: {}", e))
                    })?;

                DatabasePool::Sqlite(pool)
            }
        };

        Ok(pool)
    }

    /// Get database type
    pub fn db_type(&self) -> DatabaseType {
        match self {
            DatabasePool::Postgres(_) => DatabaseType::Postgres,
            DatabasePool::Sqlite(_) => DatabaseType::Sqlite,
        }
    }

    /// Close the connection pool
    pub async fn close(&self) {
        match self {
            DatabasePool::Postgres(pool) => pool.close().await,
            DatabasePool::Sqlite(pool) => pool.close().await,
        }
    }

    /// Get PostgreSQL pool (panics if not PostgreSQL)
    pub fn as_postgres(&self) -> &Pool<Postgres> {
        match self {
            DatabasePool::Postgres(pool) => pool,
            DatabasePool::Sqlite(_) => panic!("Expected PostgreSQL pool, got SQLite"),
        }
    }

    /// Get SQLite pool (panics if not SQLite)
    pub fn as_sqlite(&self) -> &Pool<Sqlite> {
        match self {
            DatabasePool::Sqlite(pool) => pool,
            DatabasePool::Postgres(_) => panic!("Expected SQLite pool, got PostgreSQL"),
        }
    }

    /// Try to get PostgreSQL pool
    pub fn try_as_postgres(&self) -> Option<&Pool<Postgres>> {
        match self {
            DatabasePool::Postgres(pool) => Some(pool),
            DatabasePool::Sqlite(_) => None,
        }
    }

    /// Try to get SQLite pool
    pub fn try_as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        match self {
            DatabasePool::Sqlite(pool) => Some(pool),
            DatabasePool::Postgres(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_sqlite_pool_creation() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config).await.unwrap();

        assert_eq!(pool.db_type(), DatabaseType::Sqlite);
        pool.close().await;
    }
}
