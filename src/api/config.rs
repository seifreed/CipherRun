// API Configuration

use crate::Result;
use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Server host address
    pub host: String,

    /// Server port
    pub port: u16,

    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,

    /// API keys (key -> permission level)
    pub api_keys: HashMap<String, Permission>,

    /// Enable CORS
    pub enable_cors: bool,

    /// Rate limit per minute per API key
    pub rate_limit_per_minute: u32,

    /// Maximum request body size in bytes
    pub max_body_size: usize,

    /// Request timeout in seconds
    pub request_timeout_seconds: u64,

    /// WebSocket ping interval in seconds
    pub ws_ping_interval_seconds: u64,

    /// Job queue capacity
    pub job_queue_capacity: usize,

    /// Enable Swagger UI
    pub enable_swagger: bool,

    /// Directory where named scan policies are stored. When unset, the policy
    /// management endpoints (`/policies`) report 503 Service Unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Permission {
    /// Full access - can create, read, update, delete
    Admin,

    /// Standard user - can create and read scans
    User,

    /// Read-only access - can only read existing data
    ReadOnly,
}

impl Default for ApiConfig {
    fn default() -> Self {
        let mut api_keys = HashMap::new();

        // SECURITY: Generate random API key instead of hardcoded default (CWE-798)
        // This prevents unauthorized access if default config is used in production
        let random_key = generate_secure_api_key();
        api_keys.insert(random_key.clone(), Permission::User);

        // SECURITY WARNING: Show only key prefix to avoid exposing full key in logs
        // In production, users should set their own keys via config file
        let key_preview: String = random_key.chars().take(8).collect();
        tracing::warn!(
            "=============================================================================\n\
             SECURITY WARNING: Auto-generated API key created\n\
             Key prefix: {}...\n\
             \n\
             This key is randomly generated and will change on restart.\n\
             For production use:\n\
             1. Create a config file with your own API keys\n\
             2. Set strong, unique API keys for each client\n\
             3. Never use the default configuration in production\n\
             4. Restrict API access to specific IP addresses if possible\n\
             =============================================================================",
            key_preview
        );

        Self {
            // SECURITY: Bind to localhost by default to prevent external access
            // Users must explicitly configure 0.0.0.0 to allow external connections
            host: "127.0.0.1".to_string(),
            port: 8080,
            max_concurrent_scans: 10,
            api_keys,
            enable_cors: false, // SECURITY: Disable CORS by default
            rate_limit_per_minute: 100,
            max_body_size: 1024 * 1024,   // 1MB
            request_timeout_seconds: 300, // 5 minutes
            ws_ping_interval_seconds: 30,
            job_queue_capacity: 1000,
            enable_swagger: true,
            policy_dir: None,
        }
    }
}

/// Generate a cryptographically secure random API key
///
/// SECURITY: Uses system random number generator for unpredictable keys
fn generate_secure_api_key() -> String {
    use rand::RngExt;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789-_";
    const KEY_LENGTH: usize = 32;

    let mut rng = rand::rng();

    let key: String = (0..KEY_LENGTH)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            char::from(*CHARSET.get(idx).unwrap_or(&b'A'))
        })
        .collect();

    format!("auto-{}", key)
}

impl ApiConfig {
    /// Create config from file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let config = Self::from_file_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn from_file_unvalidated(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| TlsError::FileSystemError {
            path: path.display().to_string(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| TlsError::ConfigError {
            message: format!("Failed to parse API config: {e}"),
        })
    }

    /// Create example config file
    pub fn create_example(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let config = Self::default();
        let toml = toml::to_string_pretty(&config).map_err(|e| TlsError::ConfigError {
            message: format!("Failed to serialize API config: {e}"),
        })?;
        std::fs::write(path, toml).map_err(|e| TlsError::FileSystemError {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    /// Validate API key and return permission level
    ///
    /// # Security
    /// Uses a two-phase approach to minimize timing side-channel exposure:
    /// 1. Fast length-based pre-filter to avoid processing obviously invalid keys
    /// 2. Constant-time comparison for keys with matching lengths
    ///
    /// All key comparisons take the same amount of time regardless of:
    /// - How many characters match
    /// - The position of the first mismatch
    pub fn validate_key(&self, key: &str) -> Option<Permission> {
        if key.is_empty() {
            return None;
        }

        // Fast pre-filter: collect lengths of all valid keys
        // This is O(n) but doesn't leak timing about specific key content
        let valid_lengths: Vec<usize> = self.api_keys.keys().map(|k| k.len()).collect();

        // Quick reject if key length doesn't match any valid key
        // This is the only length-based optimization that doesn't leak key content
        if !valid_lengths.contains(&key.len()) {
            return None;
        }

        let mut result: Option<Permission> = None;

        for (stored_key, permission) in &self.api_keys {
            let key_bytes = key.as_bytes();
            let stored_bytes = stored_key.as_bytes();

            // Skip keys with different lengths early (but after the length check above)
            if key_bytes.len() != stored_bytes.len() {
                continue;
            }

            // Constant-time comparison for keys of matching length
            let bytes_match: subtle::Choice = key_bytes.ct_eq(stored_bytes);
            let is_match: bool = bytes_match.into();

            if is_match {
                result = Some(*permission);
                // DO NOT break early - continue checking all keys for constant timing
            }
        }

        result
    }

    /// Add API key
    pub fn add_key(&mut self, key: String, permission: Permission) {
        self.api_keys.insert(key, permission);
    }

    /// Remove API key
    pub fn remove_key(&mut self, key: &str) -> Option<Permission> {
        self.api_keys.remove(key)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(TlsError::ConfigError {
                message: "port must be between 1 and 65535".to_string(),
            });
        }
        if self.rate_limit_per_minute == 0 {
            return Err(TlsError::ConfigError {
                message: "rate_limit_per_minute must be greater than 0".to_string(),
            });
        }
        if self.max_concurrent_scans == 0 {
            return Err(TlsError::ConfigError {
                message: "max_concurrent_scans must be greater than 0".to_string(),
            });
        }
        if self.job_queue_capacity == 0 {
            return Err(TlsError::ConfigError {
                message: "job_queue_capacity must be greater than 0".to_string(),
            });
        }
        if self.request_timeout_seconds == 0 {
            return Err(TlsError::ConfigError {
                message: "request_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if self.max_body_size == 0 {
            return Err(TlsError::ConfigError {
                message: "max_body_size must be greater than 0".to_string(),
            });
        }
        if self.ws_ping_interval_seconds == 0 {
            return Err(TlsError::ConfigError {
                message: "ws_ping_interval_seconds must be greater than 0".to_string(),
            });
        }
        if self.api_keys.is_empty() {
            return Err(TlsError::ConfigError {
                message: "api_keys must contain at least one key".to_string(),
            });
        }
        if self.api_keys.keys().any(|key| key.is_empty()) {
            return Err(TlsError::ConfigError {
                message: "api_keys must not contain empty keys".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_generates_key() {
        let config = ApiConfig::default();
        assert!(!config.api_keys.is_empty());

        let (key, permission) = config.api_keys.iter().next().unwrap();
        assert_eq!(*permission, Permission::User);
        assert_eq!(config.validate_key(key), Some(Permission::User));
    }

    #[test]
    fn test_add_and_remove_key() {
        let mut config = ApiConfig::default();
        config.add_key("test-key".to_string(), Permission::Admin);

        assert_eq!(config.validate_key("test-key"), Some(Permission::Admin));
        assert_eq!(config.remove_key("test-key"), Some(Permission::Admin));
        assert_eq!(config.validate_key("test-key"), None);
    }

    #[test]
    fn test_validate_key_rejects_empty_key_even_if_configured() {
        let mut config = ApiConfig::default();
        config.add_key(String::new(), Permission::Admin);

        assert_eq!(config.validate_key(""), None);
    }

    #[test]
    fn test_create_example_writes_file() {
        let path = std::env::temp_dir().join("cipherrun-api-config.toml");
        ApiConfig::create_example(&path).expect("write should succeed");
        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(contents.contains("host"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_from_file_rejects_invalid_config() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        std::fs::write(
            &path,
            r#"
host = "127.0.0.1"
port = 8080
max_concurrent_scans = 0
api_keys = { "test-key" = "User" }
enable_cors = false
rate_limit_per_minute = 100
max_body_size = 1048576
request_timeout_seconds = 300
ws_ping_interval_seconds = 30
job_queue_capacity = 1000
enable_swagger = true
"#,
        )
        .expect("config should be written");

        let err = ApiConfig::from_file(&path).expect_err("invalid config should fail at load");
        assert!(err.to_string().contains("max_concurrent_scans"));
    }

    #[cfg(unix)]
    #[test]
    fn test_from_file_does_not_pre_reject_non_utf8_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join(OsString::from_vec(vec![
            b'a', b'p', b'i', 0xff, b'.', b't', b'o', b'm', b'l',
        ]));

        let err = match ApiConfig::from_file(&path) {
            Ok(_) => panic!("missing non-UTF-8 path should produce a filesystem error"),
            Err(err) => err,
        };

        assert!(!err.to_string().contains("Invalid config file path"));
    }
}
