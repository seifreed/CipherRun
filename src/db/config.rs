// Database Configuration
// Handles PostgreSQL and SQLite database configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
                let database = self.database.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing database name".to_string())
                })?;
                let username = self.username.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing username".to_string())
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing password".to_string())
                })?;

                Ok(format!(
                    "postgres://{}:{}@{}:{}/{}",
                    username, password, host, port, database
                ))
            }
            DatabaseType::Sqlite => {
                let path = self.path.as_ref().ok_or_else(|| {
                    crate::TlsError::DatabaseError("Missing SQLite path".to_string())
                })?;

                // SQLx expects a proper SQLite connection string
                let path_str = path.to_string_lossy();
                if path_str == ":memory:" {
                    // For :memory:, use as-is
                    Ok(format!("sqlite:{}", path_str))
                } else if path_str.starts_with("/") {
                    // For absolute UNIX paths, use sqlite:// (two slashes) since path starts with /
                    Ok(format!("sqlite://{}", path.display()))
                } else if cfg!(windows) && path_str.len() > 1 && path_str.as_bytes()[1] == b':' {
                    // For Windows absolute paths (e.g., C:\...), use sqlite:/// (three slashes)
                    Ok(format!("sqlite:///{}", path.display()))
                } else {
                    // For relative paths, use sqlite: (single slash prefix)
                    Ok(format!("sqlite:{}", path.display()))
                }
            }
        }
    }

    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> crate::Result<Config> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to read config: {}", e)))?;

        let config: Config = toml::from_str(&contents).map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to parse config: {}", e))
        })?;

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

    #[test]
    fn test_postgres_connection_string() {
        let config = DatabaseConfig::postgres(
            "localhost".to_string(),
            5432,
            "testdb".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let conn_str = config.connection_string().unwrap();
        assert_eq!(conn_str, "postgres://user:pass@localhost:5432/testdb");
    }

    #[test]
    fn test_sqlite_connection_string() {
        let config = DatabaseConfig::sqlite(PathBuf::from("/tmp/test.db"));
        let conn_str = config.connection_string().unwrap();
        assert!(conn_str.contains("sqlite:"));
    }
}
