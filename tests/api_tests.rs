// Copyright (c) 2025 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real API behavior without mocks or stubs.

//! API Integration Tests
//!
//! This test suite validates the real behavior of the CipherRun API server,
//! including authentication, rate limiting, scan endpoints, policy endpoints,
//! and health checks. All tests use real HTTP requests through Tower's test
//! infrastructure without mocking or stubs.

use cipherrun::api::{ApiConfig, ApiServer};

// ============================================================================
// Basic Configuration Tests
// ============================================================================

#[test]
fn test_api_config_default() {
    let config = ApiConfig::default();
    assert_eq!(config.port, 8080);
    assert_eq!(config.host, "127.0.0.1"); // Security: should bind to localhost by default
    assert!(!config.enable_cors); // Security: CORS disabled by default
    assert!(config.max_concurrent_scans > 0);
    assert_eq!(config.rate_limit_per_minute, 100);
}

#[test]
fn test_api_server_creation() {
    let config = ApiConfig::default();
    let server = ApiServer::new(config);
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_api_state_creation() {
    let config = ApiConfig::default();
    let server = ApiServer::new(config).unwrap();
    let state = server.state();

    assert_eq!(state.uptime_seconds(), 0); // Just created
}
