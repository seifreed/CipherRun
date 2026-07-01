// Database Configuration
// Handles PostgreSQL and SQLite database configuration

use crate::utils::network::canonical_target;
use crate::utils::path_ext::PathExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Database type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Postgres,
    Sqlite,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub db_type: DatabaseType,

    // PostgreSQL settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    // SQLite settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Delete scans older than this many days
    pub max_age_days: i64,
}

/// Full configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionConfig>,
}

impl DatabaseConfig {
    /// Create PostgreSQL configuration
    pub fn postgres(
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
    ) -> Self {
        Self {
            db_type: DatabaseType::Postgres,
            host: Some(host),
            port: Some(port),
            database: Some(database),
            username: Some(username),
            password: Some(password),
            max_connections: Some(10),
            path: None,
        }
    }

    /// Create SQLite configuration
    pub fn sqlite(path: PathBuf) -> Self {
        Self {
            db_type: DatabaseType::Sqlite,
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            max_connections: None,
            path: Some(path),
        }
    }

    /// Generate database URL for sqlx
    pub fn connection_string(&self) -> crate::Result<String> {
        match self.db_type {
            DatabaseType::Postgres => {
                let host = self.host.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing PostgreSQL host".to_string())
                })?;
                let port = self.port.ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing PostgreSQL port".to_string())
                })?;
                if port == 0 {
                    return Err(crate::TlsError::DatabaseError(
                        "PostgreSQL port must be greater than 0".to_string(),
                    ));
                }
                let database = self.database.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing database name".to_string())
                })?;
                let username = self.username.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing username".to_string())
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing password".to_string())
                })?;

                // SECURITY: URL-encode userinfo/path fields so reserved
                // characters cannot break the PostgreSQL URL structure.
                let encoded_username = urlencoding::encode(username);
                let encoded_password = urlencoding::encode(password);
                let encoded_database = urlencoding::encode(database);

                // SECURITY WARNING: Log when embedding credentials in connection string
                // Consider using environment variables or secret managers instead
                if !password.is_empty() {
                    tracing::warn!(
                        "Database password is embedded in connection string. \
                         Consider using PostgreSQL .pgpass file or environment variables \
                         for more secure credential management."
                    );
                }

                Ok(format!(
                    "postgres://{}:{}@{}/{}",
                    encoded_username,
                    encoded_password,
                    canonical_target(host, port),
                    encoded_database
                ))
            }
            DatabaseType::Sqlite => {
                let path = self.path.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing SQLite path".to_string())
                })?;
                if path.as_os_str().is_empty() {
                    return Err(crate::TlsError::DatabaseError(
                        "SQLite path must not be empty".to_string(),
                    ));
                }

                // SQLx expects a proper SQLite connection string
                let path_str = path.to_str_checked()?;
                if path_str == ":memory:" {
                    // For :memory:, use as-is
                    Ok(format!("sqlite:{}", path_str))
                } else if path_str.starts_with("/") {
                    // For absolute UNIX paths, use sqlite:// (two slashes) since path starts with /
                    Ok(format!("sqlite://{}", path_str))
                } else if cfg!(windows) && path_str.as_bytes().get(1).is_some_and(|b| *b == b':') {
                    // For Windows absolute paths (e.g., C:\...), use sqlite:/// (three slashes)
                    Ok(format!("sqlite:///{}", path_str))
                } else {
                    // For relative paths, use sqlite: (single slash prefix)
                    Ok(format!("sqlite:{}", path_str))
                }
            }
        }
    }

    /// Load configuration from TOML file
    pub fn from_file(path: impl AsRef<Path>) -> crate::Result<Config> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to read config: {}", e)))?;

        let config: Config = toml::from_str(&contents).map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to parse config: {}", e))
        })?;
        config.validate()?;

        Ok(config)
    }

    /// Create example configuration file
    pub fn create_example_config(path: &str) -> crate::Result<()> {
        let example = r#"[database]
# Database type: "postgres" or "sqlite"
type = "postgres"

# PostgreSQL configuration
host = "localhost"
port = 5432
database = "cipherrun"
username = "cipherrun_user"
password = "secure_password"
max_connections = 10

# SQLite configuration (uncomment to use)
# type = "sqlite"
# path = "./cipherrun.db"

[retention]
# Delete scans older than this (days)
max_age_days = 365
"#;

        std::fs::write(path, example).map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to write config: {}", e))
        })?;

        Ok(())
    }
}

impl Config {
    fn validate(&self) -> crate::Result<()> {
        if self.database.db_type == DatabaseType::Postgres && matches!(self.database.port, Some(0))
        {
            return Err(crate::TlsError::DatabaseError(
                "PostgreSQL port must be greater than 0".to_string(),
            ));
        }
        if matches!(self.database.max_connections, Some(0)) {
            return Err(crate::TlsError::DatabaseError(
                "max_connections must be greater than 0".to_string(),
            ));
        }
        if let Some(retention) = &self.retention
            && retention.max_age_days < 0
        {
            return Err(crate::TlsError::DatabaseError(
                "retention max_age_days must be non-negative".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::sqlite(PathBuf::from("cipherrun.db"))
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self { max_age_days: 365 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn test_postgres_connection_string() {
        let config = DatabaseConfig::postgres(
            "localhost".to_string(),
            5432,
            "testdb".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let conn_str = config
            .connection_string()
            .expect("test assertion should succeed");
        assert_eq!(conn_str, "postgres://user:pass@localhost:5432/testdb");
    }

    #[test]
    fn test_sqlite_connection_string() {
        let config = DatabaseConfig::sqlite(PathBuf::from("/tmp/test.db"));
        let conn_str = config
            .connection_string()
            .expect("test assertion should succeed");
        assert!(conn_str.contains("sqlite:"));
    }

    #[test]
    fn test_sqlite_connection_string_rejects_empty_path() {
        let config = DatabaseConfig::sqlite(PathBuf::new());
        let err = config
            .connection_string()
            .expect_err("empty SQLite path should fail");

        assert!(err.to_string().contains("SQLite path"));
    }

    #[cfg(unix)]
    #[test]
    fn test_sqlite_connection_string_rejects_non_utf8_path() {
        let invalid = OsString::from_vec(vec![b'd', b'b', 0xff]);
        let config = DatabaseConfig::sqlite(PathBuf::from(invalid));
        let err = config
            .connection_string()
            .expect_err("non-UTF-8 SQLite path should fail");

        assert!(err.to_string().contains("Invalid file path"));
    }

    #[test]
    fn test_postgres_connection_string_ipv6_host() {
        let config = DatabaseConfig::postgres(
            "::1".to_string(),
            5432,
            "testdb".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let conn_str = config
            .connection_string()
            .expect("test assertion should succeed");
        assert_eq!(conn_str, "postgres://user:pass@[::1]:5432/testdb");
    }

    #[test]
    fn test_postgres_connection_string_rejects_zero_port() {
        let config = DatabaseConfig::postgres(
            "localhost".to_string(),
            0,
            "testdb".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let err = config
            .connection_string()
            .expect_err("zero PostgreSQL port should fail");

        assert!(err.to_string().contains("PostgreSQL port"));
    }

    #[test]
    fn test_postgres_connection_string_encodes_reserved_userinfo_and_database() {
        let config = DatabaseConfig::postgres(
            "localhost".to_string(),
            5432,
            "test/db".to_string(),
            "user@tenant".to_string(),
            "p:ss@word".to_string(),
        );

        let conn_str = config
            .connection_string()
            .expect("test assertion should succeed");
        assert_eq!(
            conn_str,
            "postgres://user%40tenant:p%3Ass%40word@localhost:5432/test%2Fdb"
        );
    }

    #[test]
    fn test_postgres_connection_string_strips_existing_brackets() {
        let config = DatabaseConfig::postgres(
            "[::1]".to_string(),
            5432,
            "testdb".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let conn_str = config
            .connection_string()
            .expect("test assertion should succeed");
        assert_eq!(conn_str, "postgres://user:pass@[::1]:5432/testdb");
    }

    #[test]
    fn test_config_from_file_rejects_zero_max_connections() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("db.toml");
        std::fs::write(
            &path,
            r#"
[database]
type = "postgres"
host = "localhost"
port = 5432
database = "cipherrun"
username = "user"
password = "pass"
max_connections = 0
"#,
        )
        .expect("test assertion should succeed");

        let err = DatabaseConfig::from_file(&path).expect_err("zero max_connections should fail");

        assert!(err.to_string().contains("max_connections"));
    }

    #[test]
    fn test_config_from_file_rejects_zero_postgres_port() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("db.toml");
        std::fs::write(
            &path,
            r#"
[database]
type = "postgres"
host = "localhost"
port = 0
database = "cipherrun"
username = "user"
password = "pass"
"#,
        )
        .expect("test assertion should succeed");

        let err = DatabaseConfig::from_file(&path).expect_err("zero PostgreSQL port should fail");

        assert!(err.to_string().contains("PostgreSQL port"));
    }

    #[test]
    fn test_config_from_file_rejects_negative_retention() {
        let dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = dir.path().join("db.toml");
        std::fs::write(
            &path,
            r#"
[database]
type = "sqlite"
path = ":memory:"

[retention]
max_age_days = -1
"#,
        )
        .expect("test assertion should succeed");

        let err = DatabaseConfig::from_file(&path).expect_err("negative retention should fail");

        assert!(err.to_string().contains("max_age_days"));
    }
}
