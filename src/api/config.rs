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
        // Default demo key
        api_keys.insert("demo-key-12345".to_string(), Permission::User);

        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            max_concurrent_scans: 10,
            api_keys,
            enable_cors: true,
            rate_limit_per_minute: 100,
            max_body_size: 1024 * 1024,   // 1MB
            request_timeout_seconds: 300, // 5 minutes
            ws_ping_interval_seconds: 30,
            job_queue_capacity: 1000,
            enable_swagger: true,
        }
    }
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
