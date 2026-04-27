// Database Connection Pool
// Manages PostgreSQL and SQLite connection pools with sqlx

use crate::db::config::{DatabaseConfig, DatabaseType};
use sqlx::{Pool, Postgres, Row, Sqlite};
use std::str::FromStr;

/// Sanitize a SQL identifier (table name, column name) to prevent injection.
///
/// Only allows alphanumeric characters and underscores.
/// Panics on invalid identifiers — these are programming errors since
/// table/column names should be hardcoded, never from user input.
#[inline]
fn sanitize_identifier(ident: &str) -> String {
    // Reject empty or overly long identifiers
    assert!(
        !ident.is_empty() && ident.len() <= 128,
        "SQL identifier rejected: length {} (must be 1-128 chars)",
        ident.len()
    );

    // Only allow alphanumeric and underscore
    assert!(
        ident.chars().all(|c| c.is_alphanumeric() || c == '_'),
        "SQL identifier rejected: '{}' (only alphanumeric and underscore allowed)",
        ident
    );

    ident.to_string()
}

/// Sanitize multiple identifiers for use in column list
#[inline]
fn sanitize_identifiers(idents: &[&str]) -> String {
    idents
        .iter()
        .map(|id| sanitize_identifier(id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Sanitize a comma-separated column list in SELECT statements
#[inline]
fn sanitize_select_columns(columns: &str) -> String {
    columns
        .split(',')
        .map(|col| sanitize_identifier(col.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

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
    ///
    /// # Security
    /// Table and column names are validated to prevent SQL injection.
    /// Only alphanumeric characters and underscores are allowed.
    /// Returns the query string (invalid identifiers result in empty strings which cause SQL errors).
    pub fn insert_query(&mut self, table: &str, columns: &[&str]) -> String {
        self.reset();
        let cols = sanitize_identifiers(columns);
        let placeholders = self.placeholders(columns.len());
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            sanitize_identifier(table),
            cols,
            placeholders
        )
    }

    /// Build an INSERT query with RETURNING clause (Postgres) or without (SQLite)
    ///
    /// # Security
    /// Table and column names are validated to prevent SQL injection.
    pub fn insert_returning_query(
        &mut self,
        table: &str,
        columns: &[&str],
        returning_col: &str,
    ) -> String {
        self.reset();
        let cols = sanitize_identifiers(columns);
        let placeholders = self.placeholders(columns.len());
        match self.db_type {
            DatabaseType::Postgres => format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
                sanitize_identifier(table),
                cols,
                placeholders,
                sanitize_identifier(returning_col)
            ),
            DatabaseType::Sqlite => {
                format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    sanitize_identifier(table),
                    cols,
                    placeholders
                )
            }
        }
    }

    /// Build an INSERT ... ON CONFLICT DO NOTHING query with RETURNING clause.
    ///
    /// On conflict with `conflict_col`, the row is not inserted. For Postgres,
    /// the RETURNING clause returns the ID. For SQLite, uses INSERT OR IGNORE.
    ///
    /// # Security
    /// Table and column names are validated to prevent SQL injection.
    pub fn insert_on_conflict_do_nothing_query(
        &mut self,
        table: &str,
        columns: &[&str],
        conflict_col: &str,
        returning_col: &str,
    ) -> String {
        self.reset();
        let cols = sanitize_identifiers(columns);
        let placeholders = self.placeholders(columns.len());
        match self.db_type {
            DatabaseType::Postgres => format!(
                "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT ({}) DO NOTHING RETURNING {}",
                sanitize_identifier(table),
                cols,
                placeholders,
                sanitize_identifier(conflict_col),
                sanitize_identifier(returning_col)
            ),
            DatabaseType::Sqlite => {
                format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                    sanitize_identifier(table),
                    cols,
                    placeholders
                )
            }
        }
    }

    /// Build a SELECT query with WHERE clause
    ///
    /// # Security
    /// Table and column names are validated to prevent SQL injection.
    /// For multiple columns, pass them as comma-separated string.
    pub fn select_where_query(&mut self, table: &str, columns: &str, where_col: &str) -> String {
        self.reset();
        let placeholder = self.placeholder();
        format!(
            "SELECT {} FROM {} WHERE {} = {}",
            sanitize_select_columns(columns),
            sanitize_identifier(table),
            sanitize_identifier(where_col),
            placeholder
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
        let cols = sanitize_identifiers(columns);

        // Build multiple value sets: (?, ?), (?, ?), ...
        let value_sets: Vec<String> = (0..row_count)
            .map(|_| {
                let placeholders = self.placeholders(columns.len());
                format!("({})", placeholders)
            })
            .collect();

        format!(
            "INSERT INTO {} ({}) VALUES {}",
            sanitize_identifier(table),
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
                    .acquire_timeout(crate::constants::DB_ACQUIRE_TIMEOUT)
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
                        .create_if_missing(true)
                        // Enable WAL mode for better concurrency:
                        // - Multiple readers can work concurrently
                        // - Writers don't block readers
                        // - This is essential for a connection pool > 1
                        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                        // Set busy timeout for write operations
                        // This allows waiting instead of immediately failing on lock contention
                        .busy_timeout(crate::constants::DB_BUSY_TIMEOUT);

                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    // Allow multiple connections for read concurrency
                    // With WAL mode, readers don't block writers
                    // This prevents the system from blocking if one connection is slow
                    .max_connections(5)
                    .acquire_timeout(crate::constants::DB_ACQUIRE_TIMEOUT)
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

    /// Run a simple health check query (`SELECT 1`) against the database
    pub async fn health_check(&self) -> crate::Result<()> {
        match self {
            DatabasePool::Postgres(pool) => {
                sqlx::query("SELECT 1").fetch_one(pool).await.map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Database health check failed: {}", e))
                })?;
            }
            DatabasePool::Sqlite(pool) => {
                sqlx::query("SELECT 1").fetch_one(pool).await.map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Database health check failed: {}", e))
                })?;
            }
        }
        Ok(())
    }

    /// Query top scanned domains from the last 30 days
    pub async fn get_top_domains(
        &self,
        limit: i64,
    ) -> crate::Result<Vec<(String, i64, chrono::DateTime<chrono::Utc>)>> {
        match self {
            DatabasePool::Postgres(pool) => {
                let rows = sqlx::query(
                    r#"
                    SELECT target_hostname, COUNT(*) as scan_count,
                           MAX(scan_timestamp) as last_scan
                    FROM scans
                    WHERE scan_timestamp > NOW() - INTERVAL '30 days'
                    GROUP BY target_hostname
                    ORDER BY scan_count DESC
                    LIMIT $1
                    "#,
                )
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to query top domains: {}", e))
                })?;

                Ok(rows
                    .into_iter()
                    .filter_map(|row| {
                        let count: i64 = row.get("scan_count");
                        if count < 0 {
                            tracing::warn!("Negative scan count encountered: {}", count);
                            return None;
                        }
                        Some((
                            row.get::<String, _>("target_hostname"),
                            count,
                            row.get::<chrono::DateTime<chrono::Utc>, _>("last_scan"),
                        ))
                    })
                    .collect())
            }
            DatabasePool::Sqlite(pool) => {
                let rows = sqlx::query(
                    r#"
                    SELECT target_hostname, COUNT(*) as scan_count,
                           MAX(scan_timestamp) as last_scan
                    FROM scans
                    WHERE scan_timestamp > datetime('now', '-30 days')
                    GROUP BY target_hostname
                    ORDER BY scan_count DESC
                    LIMIT ?
                    "#,
                )
                .bind(limit)
                .fetch_all(pool)
                .await
                .map_err(|e| {
                    crate::TlsError::DatabaseError(format!("Failed to query top domains: {}", e))
                })?;

                Ok(rows
                    .into_iter()
                    .filter_map(|row| {
                        let count: i64 = row.get::<i64, _>("scan_count");
                        if count < 0 {
                            tracing::warn!("Negative scan count encountered: {}", count);
                            return None;
                        }
                        Some((
                            row.get::<String, _>("target_hostname"),
                            count,
                            row.get::<chrono::DateTime<chrono::Utc>, _>("last_scan"),
                        ))
                    })
                    .collect())
            }
        }
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

    /// Get PostgreSQL pool (returns error if not PostgreSQL)
    pub fn as_postgres(&self) -> crate::Result<&Pool<Postgres>> {
        match self {
            DatabasePool::Postgres(pool) => Ok(pool),
            DatabasePool::Sqlite(_) => Err(crate::TlsError::DatabaseError(
                "Expected PostgreSQL pool, got SQLite".to_string(),
            )),
        }
    }

    /// Get SQLite pool (returns error if not SQLite)
    pub fn as_sqlite(&self) -> crate::Result<&Pool<Sqlite>> {
        match self {
            DatabasePool::Sqlite(pool) => Ok(pool),
            DatabasePool::Postgres(_) => Err(crate::TlsError::DatabaseError(
                "Expected SQLite pool, got PostgreSQL".to_string(),
            )),
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

    #[test]
    fn test_query_builder_placeholders_postgres() {
        let mut builder = QueryBuilder::new(DatabaseType::Postgres);
        assert_eq!(builder.placeholder(), "$1");
        assert_eq!(builder.placeholder(), "$2");
        assert_eq!(builder.placeholders(2), "$3, $4");
        builder.reset();
        assert_eq!(builder.placeholder(), "$1");
    }

    #[test]
    fn test_query_builder_placeholders_sqlite() {
        let mut builder = QueryBuilder::new(DatabaseType::Sqlite);
        assert_eq!(builder.placeholder(), "?");
        assert_eq!(builder.placeholder(), "?");
        assert_eq!(builder.placeholders(2), "?, ?");
        builder.reset();
        assert_eq!(builder.placeholder(), "?");
    }

    #[test]
    fn test_insert_returning_query_sqlite() {
        let mut builder = QueryBuilder::new(DatabaseType::Sqlite);
        let query = builder.insert_returning_query("items", &["a", "b"], "id");
        assert_eq!(query, "INSERT INTO items (a, b) VALUES (?, ?)");
    }

    #[test]
    fn test_batch_insert_query_postgres() {
        let mut builder = QueryBuilder::new(DatabaseType::Postgres);
        let query = builder.batch_insert_query("items", &["a", "b"], 2);
        assert_eq!(query, "INSERT INTO items (a, b) VALUES ($1, $2), ($3, $4)");
    }

    #[test]
    fn test_insert_query_postgres_and_sqlite() {
        let mut pg = QueryBuilder::new(DatabaseType::Postgres);
        let pg_query = pg.insert_query("items", &["a", "b"]);
        assert_eq!(pg_query, "INSERT INTO items (a, b) VALUES ($1, $2)");

        let mut sqlite = QueryBuilder::new(DatabaseType::Sqlite);
        let sqlite_query = sqlite.insert_query("items", &["a", "b"]);
        assert_eq!(sqlite_query, "INSERT INTO items (a, b) VALUES (?, ?)");
    }

    #[test]
    fn test_select_where_query_resets_counter() {
        let mut builder = QueryBuilder::new(DatabaseType::Postgres);
        let query = builder.select_where_query("items", "a, b", "id");
        assert_eq!(query, "SELECT a, b FROM items WHERE id = $1");
        let query2 = builder.select_where_query("items", "a", "id");
        assert_eq!(query2, "SELECT a FROM items WHERE id = $1");
    }

    #[test]
    fn test_sanitize_identifier_valid() {
        assert!(!sanitize_identifier("table_name").is_empty());
        assert!(!sanitize_identifier("column123").is_empty());
        assert!(!sanitize_identifier("a_b_c").is_empty());
    }

    #[test]
    #[should_panic(expected = "must be 1-128 chars")]
    fn test_sanitize_identifier_empty() {
        sanitize_identifier("");
    }

    #[test]
    #[should_panic(expected = "only alphanumeric and underscore allowed")]
    fn test_sanitize_identifier_invalid_chars() {
        sanitize_identifier("table-name");
    }

    #[test]
    #[should_panic(expected = "only alphanumeric and underscore allowed")]
    fn test_sanitize_identifier_injection() {
        sanitize_identifier("table;drop");
    }

    #[test]
    #[should_panic(expected = "must be 1-128 chars")]
    fn test_sanitize_identifier_too_long() {
        sanitize_identifier(&"a".repeat(200));
    }

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
