// Database Connection Pool
// Manages PostgreSQL and SQLite connection pools with sqlx

use crate::db::config::{DatabaseConfig, DatabaseType};
use sqlx::{Pool, Postgres, Row, Sqlite};
use std::str::FromStr;
use std::time::Duration;

/// QueryBuilder that handles placeholder syntax differences between databases.
/// PostgreSQL uses $1, $2, $3... while SQLite uses ?, ?, ?...
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    db_type: DatabaseType,
    param_count: usize,
}

impl QueryBuilder {
    /// Create a new query builder for the given database type
    pub fn new(db_type: DatabaseType) -> Self {
        Self {
            db_type,
            param_count: 0,
        }
    }

    /// Get the next placeholder for the current database type
    pub fn placeholder(&mut self) -> String {
        self.param_count += 1;
        match self.db_type {
            DatabaseType::Postgres => format!("${}", self.param_count),
            DatabaseType::Sqlite => "?".to_string(),
        }
    }

    /// Generate N placeholders separated by commas
    pub fn placeholders(&mut self, count: usize) -> String {
        (0..count)
            .map(|_| self.placeholder())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Reset the placeholder counter
    pub fn reset(&mut self) {
        self.param_count = 0;
    }

    /// Build an INSERT query with the correct placeholders
    pub fn insert_query(&mut self, table: &str, columns: &[&str]) -> String {
        self.reset();
        let cols = columns.join(", ");
        let placeholders = self.placeholders(columns.len());
        format!("INSERT INTO {} ({}) VALUES ({})", table, cols, placeholders)
    }

    /// Build an INSERT query with RETURNING clause (Postgres) or without (SQLite)
    pub fn insert_returning_query(
        &mut self,
        table: &str,
        columns: &[&str],
        returning_col: &str,
    ) -> String {
        self.reset();
        let cols = columns.join(", ");
        let placeholders = self.placeholders(columns.len());
        match self.db_type {
            DatabaseType::Postgres => format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
                table, cols, placeholders, returning_col
            ),
            DatabaseType::Sqlite => {
                format!("INSERT INTO {} ({}) VALUES ({})", table, cols, placeholders)
            }
        }
    }

    /// Build a SELECT query with WHERE clause
    pub fn select_where_query(&mut self, table: &str, columns: &str, where_col: &str) -> String {
        self.reset();
        let placeholder = self.placeholder();
        format!(
            "SELECT {} FROM {} WHERE {} = {}",
            columns, table, where_col, placeholder
        )
    }

    /// Build a batch INSERT query with multiple VALUES clauses
    ///
    /// Performance optimization: Generates a single INSERT with multiple value sets
    /// instead of executing N separate INSERT statements.
    ///
    /// Example output (Postgres):
    ///   INSERT INTO table (col1, col2) VALUES ($1, $2), ($3, $4), ($5, $6)
    ///
    /// Example output (SQLite):
    ///   INSERT INTO table (col1, col2) VALUES (?, ?), (?, ?), (?, ?)
    pub fn batch_insert_query(
        &mut self,
        table: &str,
        columns: &[&str],
        row_count: usize,
    ) -> String {
        self.reset();
        let cols = columns.join(", ");

        // Build multiple value sets: (?, ?), (?, ?), ...
        let value_sets: Vec<String> = (0..row_count)
            .map(|_| {
                let placeholders = self.placeholders(columns.len());
                format!("({})", placeholders)
            })
            .collect();

        format!(
            "INSERT INTO {} ({}) VALUES {}",
            table,
            cols,
            value_sets.join(", ")
        )
    }
}

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

    /// Create a QueryBuilder for this pool's database type
    pub fn query_builder(&self) -> QueryBuilder {
        QueryBuilder::new(self.db_type())
    }

    /// Execute an INSERT and return the last inserted ID.
    /// Handles the differences between Postgres RETURNING and SQLite last_insert_rowid()
    pub async fn execute_insert_returning(
        &self,
        query: &str,
        bindings: Vec<BindValue>,
    ) -> crate::Result<i64> {
        match self {
            DatabasePool::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_postgres(q);
                }
                let row = q.fetch_one(pool).await.map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Insert query failed: {}", e))
                })?;
                Ok(row.get::<i64, _>(0))
            }
            DatabasePool::Sqlite(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_sqlite(q);
                }
                let result = q.execute(pool).await.map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Insert query failed: {}", e))
                })?;
                Ok(result.last_insert_rowid())
            }
        }
    }

    /// Execute a simple query without returning a value
    pub async fn execute(&self, query: &str, bindings: Vec<BindValue>) -> crate::Result<()> {
        match self {
            DatabasePool::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_postgres(q);
                }
                q.execute(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Query failed: {}", e)))?;
            }
            DatabasePool::Sqlite(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_sqlite(q);
                }
                q.execute(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Query failed: {}", e)))?;
            }
        }
        Ok(())
    }

    /// Execute a SELECT query and return optional row with single i64 column
    pub async fn fetch_optional_id(
        &self,
        query: &str,
        bindings: Vec<BindValue>,
    ) -> crate::Result<Option<i64>> {
        match self {
            DatabasePool::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_postgres(q);
                }
                let row = q
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Query failed: {}", e)))?;
                Ok(row.map(|r| r.get::<i64, _>(0)))
            }
            DatabasePool::Sqlite(pool) => {
                let mut q = sqlx::query(query);
                for binding in bindings {
                    q = binding.bind_sqlite(q);
                }
                let row = q
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| crate::TlsError::DatabaseError(format!("Query failed: {}", e)))?;
                Ok(row.map(|r| r.get::<i64, _>(0)))
            }
        }
    }
}

/// Enum to hold different bind value types for database-agnostic query binding
#[derive(Debug, Clone)]
pub enum BindValue {
    Int64(i64),
    Int32(i32),
    Int16(i16),
    String(String),
    Bool(bool),
    OptInt32(Option<i32>),
    OptString(Option<String>),
    OptBytes(Option<Vec<u8>>),
    DateTime(chrono::DateTime<chrono::Utc>),
}

impl BindValue {
    /// Bind this value to a Postgres query
    fn bind_postgres<'q>(
        self,
        query: sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
        match self {
            BindValue::Int64(v) => query.bind(v),
            BindValue::Int32(v) => query.bind(v),
            BindValue::Int16(v) => query.bind(v),
            BindValue::String(v) => query.bind(v),
            BindValue::Bool(v) => query.bind(v),
            BindValue::OptInt32(v) => query.bind(v),
            BindValue::OptString(v) => query.bind(v),
            BindValue::OptBytes(v) => query.bind(v),
            BindValue::DateTime(v) => query.bind(v),
        }
    }

    /// Bind this value to a SQLite query
    fn bind_sqlite<'q>(
        self,
        query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    ) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
        match self {
            BindValue::Int64(v) => query.bind(v),
            BindValue::Int32(v) => query.bind(v),
            BindValue::Int16(v) => query.bind(v as i32), // SQLite stores as i32
            BindValue::String(v) => query.bind(v),
            BindValue::Bool(v) => query.bind(v),
            BindValue::OptInt32(v) => query.bind(v),
            BindValue::OptString(v) => query.bind(v),
            BindValue::OptBytes(v) => query.bind(v),
            BindValue::DateTime(v) => query.bind(v),
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
        let pool = DatabasePool::new(&config)
            .await
            .expect("test assertion should succeed");

        assert_eq!(pool.db_type(), DatabaseType::Sqlite);
        pool.close().await;
    }
}
