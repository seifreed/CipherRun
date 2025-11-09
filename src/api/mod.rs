// API Module - REST API Server for CipherRun

pub mod config;
pub mod jobs;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod routes;
pub mod server;
pub mod state;
pub mod ws;

// Re-export commonly used types
pub use config::{ApiConfig, Permission};
pub use server::ApiServer;
pub use state::AppState;

/// API module version
pub const API_VERSION: &str = "1.0.0";

/// API module tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_version() {
        assert!(!API_VERSION.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = ApiConfig::default();
        assert_eq!(config.port, 8080);
        assert!(config.enable_cors);
    }
}
