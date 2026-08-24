// API Configuration

use crate::Result;
use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

const MAX_API_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Server host address
    pub host: String,

    /// Server port
    pub port: u16,

    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,

    /// Plaintext API keys for programmatic embedding and tests only.
    /// This field is never read from or written to configuration files.
    #[serde(skip)]
    pub api_keys: HashMap<String, Permission>,

    /// Hashed credentials loaded from configuration files.
    #[serde(default)]
    pub credentials: Vec<ApiCredential>,

    /// Enable CORS
    pub enable_cors: bool,

    /// Browser origins allowed when CORS is enabled
    #[serde(default)]
    pub allowed_origins: Vec<String>,

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

    /// Directory for durable standalone job storage. Memory-only when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_storage_dir: Option<PathBuf>,

    /// Retention time for completed, failed, and cancelled jobs.
    #[serde(default = "default_job_retention_seconds")]
    pub job_retention_seconds: u64,

    /// File containing the HMAC secret used to sign scan webhooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_signing_secret_file: Option<PathBuf>,

    /// PEM certificate chain for native API HTTPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_file: Option<PathBuf>,

    /// PEM private key for native API HTTPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_file: Option<PathBuf>,

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedKey {
    pub key_id: String,
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub permission: Permission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCredential {
    pub key_id: String,
    pub secret_hash: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub permission: Permission,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default = "default_true")]
    pub active: bool,
}

const fn default_true() -> bool {
    true
}

const fn default_job_retention_seconds() -> u64 {
    7 * 24 * 60 * 60
}

impl ApiCredential {
    pub fn from_secret(
        key_id: String,
        secret: &str,
        principal_id: String,
        tenant_id: Option<String>,
        permission: Permission,
    ) -> Self {
        Self {
            key_id,
            secret_hash: hash_secret(secret),
            principal_id,
            tenant_id,
            permission,
            created_at: chrono::Utc::now(),
            expires_at: None,
            active: true,
        }
    }
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
            credentials: Vec::new(),
            enable_cors: false, // SECURITY: Disable CORS by default
            allowed_origins: Vec::new(),
            rate_limit_per_minute: 100,
            max_body_size: 1024 * 1024,   // 1MB
            request_timeout_seconds: 300, // 5 minutes
            ws_ping_interval_seconds: 30,
            job_queue_capacity: 1000,
            job_storage_dir: None,
            job_retention_seconds: default_job_retention_seconds(),
            webhook_signing_secret_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            enable_swagger: false,
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
        let size = std::fs::metadata(path)
            .map_err(|e| TlsError::FileSystemError {
                path: path.display().to_string(),
                source: e,
            })?
            .len();
        if size > MAX_API_CONFIG_BYTES {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "API config file too large: {} bytes (max {})",
                    size, MAX_API_CONFIG_BYTES
                ),
            });
        }
        let content = std::fs::read_to_string(path).map_err(|e| TlsError::FileSystemError {
            path: path.display().to_string(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| TlsError::ConfigError {
            message: format!("Failed to parse API config: {e}"),
        })
    }

    /// Create example config file
    pub fn create_example(path: impl AsRef<Path>) -> Result<PathBuf> {
        let path = path.as_ref();
        let token_path = path.with_extension("token");
        let secret = generate_secure_api_key();
        let mut config = Self::default();
        config.api_keys.clear();
        config.credentials = vec![ApiCredential::from_secret(
            "bootstrap-admin".to_string(),
            &secret,
            "bootstrap-admin".to_string(),
            Some("default".to_string()),
            Permission::Admin,
        )];
        let toml = toml::to_string_pretty(&config).map_err(|e| TlsError::ConfigError {
            message: format!("Failed to serialize API config: {e}"),
        })?;

        let mut token_file = open_owner_only_new(&token_path)?;
        let mut config_file = match open_owner_only_new(path) {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_file(&token_path);
                return Err(error);
            }
        };

        let write_result = (|| {
            config_file
                .write_all(toml.as_bytes())
                .map_err(|source| TlsError::FileSystemError {
                    path: path.display().to_string(),
                    source,
                })?;
            token_file
                .write_all(secret.as_bytes())
                .map_err(|source| TlsError::FileSystemError {
                    path: token_path.display().to_string(),
                    source,
                })
        })();

        if let Err(error) = write_result {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(&token_path);
            return Err(error);
        }

        Ok(token_path)
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
        self.authenticate_key(key).map(|key| key.permission)
    }

    pub fn authenticate_key(&self, key: &str) -> Option<AuthenticatedKey> {
        if key.is_empty() {
            return None;
        }

        // Fast pre-filter: collect lengths of all valid keys
        // This is O(n) but doesn't leak timing about specific key content
        let valid_lengths: Vec<usize> = self.api_keys.keys().map(|k| k.len()).collect();

        // Quick reject if key length doesn't match any valid key
        // This is the only length-based optimization that doesn't leak key content
        if self.credentials.is_empty() && !valid_lengths.contains(&key.len()) {
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

        if let Some(permission) = result {
            let key_id = key_id(key);
            return Some(AuthenticatedKey {
                principal_id: key_id.clone(),
                key_id,
                tenant_id: None,
                permission,
            });
        }

        let presented_hash = hash_secret(key);
        let now = chrono::Utc::now();
        let mut authenticated = None;
        for credential in &self.credentials {
            let hashes_match: bool = presented_hash
                .as_bytes()
                .ct_eq(credential.secret_hash.as_bytes())
                .into();
            let usable = credential.active
                && credential
                    .expires_at
                    .is_none_or(|expires_at| expires_at > now);
            if hashes_match && usable {
                authenticated = Some(AuthenticatedKey {
                    key_id: credential.key_id.clone(),
                    principal_id: credential.principal_id.clone(),
                    tenant_id: credential.tenant_id.clone(),
                    permission: credential.permission,
                });
            }
        }
        authenticated
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
        if self.job_retention_seconds == 0 {
            return Err(TlsError::ConfigError {
                message: "job_retention_seconds must be greater than 0".to_string(),
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
        if self.api_keys.is_empty() && self.credentials.is_empty() {
            return Err(TlsError::ConfigError {
                message: "credentials must contain at least one key".to_string(),
            });
        }
        if self.api_keys.keys().any(|key| key.is_empty()) {
            return Err(TlsError::ConfigError {
                message: "api_keys must not contain empty keys".to_string(),
            });
        }
        let mut key_ids = std::collections::HashSet::new();
        for credential in &self.credentials {
            if credential.key_id.is_empty() || credential.principal_id.is_empty() {
                return Err(TlsError::ConfigError {
                    message: "credential key_id and principal_id must not be empty".to_string(),
                });
            }
            if !key_ids.insert(&credential.key_id) {
                return Err(TlsError::ConfigError {
                    message: format!("duplicate credential key_id: {}", credential.key_id),
                });
            }
            validate_secret_hash(&credential.secret_hash)?;
            if credential
                .expires_at
                .is_some_and(|expires_at| expires_at <= credential.created_at)
            {
                return Err(TlsError::ConfigError {
                    message: format!(
                        "credential {} expires_at must be after created_at",
                        credential.key_id
                    ),
                });
            }
        }
        if self.enable_cors && self.allowed_origins.is_empty() {
            return Err(TlsError::ConfigError {
                message: "allowed_origins must contain at least one origin when CORS is enabled"
                    .to_string(),
            });
        }
        if self.tls_cert_file.is_some() != self.tls_key_file.is_some() {
            return Err(TlsError::ConfigError {
                message: "tls_cert_file and tls_key_file must be configured together".to_string(),
            });
        }
        Ok(())
    }
}

fn key_id(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    format!("key-{}", hex::encode(&digest.as_ref()[..12]))
}

fn hash_secret(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    format!("sha256:{}", hex::encode(digest.as_ref()))
}

fn validate_secret_hash(hash: &str) -> Result<()> {
    let Some(encoded) = hash.strip_prefix("sha256:") else {
        return Err(TlsError::ConfigError {
            message: "credential secret_hash must use the sha256:<hex> format".to_string(),
        });
    };
    if encoded.len() != 64 || hex::decode(encoded).is_err() {
        return Err(TlsError::ConfigError {
            message: "credential secret_hash must contain a 32-byte SHA-256 digest".to_string(),
        });
    }
    Ok(())
}

fn open_owner_only_new(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| TlsError::FileSystemError {
            path: path.display().to_string(),
            source,
        })
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
    fn authenticated_key_exposes_stable_id_not_secret() {
        let mut config = ApiConfig::default();
        config.api_keys.clear();
        config.add_key("top-secret".to_string(), Permission::User);

        let authenticated = config
            .authenticate_key("top-secret")
            .expect("key should authenticate");

        assert_eq!(authenticated.permission, Permission::User);
        assert_eq!(authenticated.key_id, authenticated.principal_id);
        assert!(!authenticated.key_id.contains("top-secret"));
        assert_eq!(authenticated.key_id, key_id("top-secret"));
    }

    #[test]
    fn test_cors_requires_explicit_allowed_origin() {
        let config = ApiConfig {
            enable_cors: true,
            ..Default::default()
        };

        let err = config
            .validate()
            .expect_err("CORS without an allowlist must fail");
        assert!(err.to_string().contains("allowed_origins"));
    }

    #[test]
    fn test_tls_certificate_and_key_paths_must_match() {
        let config = ApiConfig {
            tls_cert_file: Some("server.crt".into()),
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("TLS requires both certificate and key");
        assert!(err.to_string().contains("must be configured together"));
    }

    #[test]
    fn test_validate_key_rejects_empty_key_even_if_configured() {
        let mut config = ApiConfig::default();
        config.add_key(String::new(), Permission::Admin);

        assert_eq!(config.validate_key(""), None);
    }

    #[test]
    fn test_create_example_writes_file() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        let token_path = ApiConfig::create_example(&path).expect("write should succeed");
        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        let token = std::fs::read_to_string(token_path).expect("token should be readable");
        assert!(contents.contains("host"));
        assert!(contents.contains("secret_hash"));
        assert!(!contents.contains(&token));

        let loaded = ApiConfig::from_file(&path).expect("generated config should load");
        let authenticated = loaded
            .authenticate_key(&token)
            .expect("bootstrap token should authenticate");
        assert_eq!(authenticated.key_id, "bootstrap-admin");
        assert_eq!(authenticated.tenant_id.as_deref(), Some("default"));
    }

    #[test]
    fn test_create_example_does_not_overwrite_credentials() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        std::fs::write(&path, "existing credentials").expect("fixture should be written");

        ApiConfig::create_example(&path).expect_err("existing credentials must be preserved");
        assert_eq!(
            std::fs::read_to_string(path).expect("fixture should remain readable"),
            "existing credentials"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_create_example_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        let token_path = ApiConfig::create_example(&path).expect("write should succeed");

        let mode = std::fs::metadata(path)
            .expect("config metadata should exist")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let token_mode = std::fs::metadata(token_path)
            .expect("token metadata should exist")
            .permissions()
            .mode();
        assert_eq!(token_mode & 0o777, 0o600);
    }

    #[test]
    fn hashed_credentials_enforce_active_state_and_expiry() {
        let mut config = ApiConfig::default();
        config.api_keys.clear();
        let mut credential = ApiCredential::from_secret(
            "key-1".to_string(),
            "secret",
            "principal-1".to_string(),
            Some("tenant-1".to_string()),
            Permission::User,
        );
        config.credentials.push(credential.clone());
        assert!(config.authenticate_key("secret").is_some());

        credential.active = false;
        config.credentials = vec![credential.clone()];
        assert!(config.authenticate_key("secret").is_none());

        credential.active = true;
        credential.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        config.credentials = vec![credential];
        assert!(config.authenticate_key("secret").is_none());
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

    #[test]
    fn config_file_rejects_legacy_plaintext_api_keys() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        let mut config = ApiConfig::default();
        config.api_keys.clear();
        let mut serialized = toml::to_string_pretty(&config).expect("config should serialize");
        serialized.push_str("\napi_keys = { plaintext = \"Admin\" }\n");
        std::fs::write(&path, serialized).expect("fixture should be written");

        let error = ApiConfig::from_file(&path)
            .expect_err("plaintext file credentials must not be accepted");

        assert!(error.to_string().contains("credentials"));
    }

    #[test]
    fn test_from_file_rejects_oversized_config_before_read() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("api.toml");
        let file = std::fs::File::create(&path).expect("config should be created");
        file.set_len(MAX_API_CONFIG_BYTES + 1)
            .expect("config should be resized");

        let err = ApiConfig::from_file(&path).expect_err("oversized config should fail");
        assert!(err.to_string().contains("API config file too large"));
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
