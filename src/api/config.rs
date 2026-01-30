// API Configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

        // SECURITY WARNING: Log the generated key only once at startup
        // In production, users should set their own keys via config file
        tracing::warn!(
            "=============================================================================\n\
             SECURITY WARNING: Using auto-generated API key: {}\n\
             \n\
             This key is randomly generated and will change on restart.\n\
             For production use:\n\
             1. Create a config file with your own API keys\n\
             2. Set strong, unique API keys for each client\n\
             3. Never use the default configuration in production\n\
             4. Restrict API access to specific IP addresses if possible\n\
             =============================================================================",
            random_key
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
        }
    }
}

/// Generate a cryptographically secure random API key
///
/// SECURITY: Uses system random number generator for unpredictable keys
fn generate_secure_api_key() -> String {
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789-_";
    const KEY_LENGTH: usize = 32;

    let mut rng = rand::thread_rng();

    let key: String = (0..KEY_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("auto-{}", key)
}

impl ApiConfig {
    /// Create config from file
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: ApiConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Create example config file
    pub fn create_example(path: &str) -> anyhow::Result<()> {
        let config = Self::default();
        let toml = toml::to_string_pretty(&config)?;
        std::fs::write(path, toml)?;
        Ok(())
    }

    /// Validate API key and return permission level
    pub fn validate_key(&self, key: &str) -> Option<Permission> {
        self.api_keys.get(key).copied()
    }

    /// Add API key
    pub fn add_key(&mut self, key: String, permission: Permission) {
        self.api_keys.insert(key, permission);
    }

    /// Remove API key
    pub fn remove_key(&mut self, key: &str) -> Option<Permission> {
        self.api_keys.remove(key)
    }
}
