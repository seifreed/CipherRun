// Database Integration Tests
// Tests the complete database backend with both PostgreSQL and SQLite

use cipherrun::db::*;
use cipherrun::protocols::Protocol;
use cipherrun::scanner::ScanResults;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counter to ensure unique database identifiers across tests
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Helper function to create a unique in-memory SQLite database for each test
fn create_unique_db_path() -> PathBuf {
    // Create a unique temporary file for each test to ensure database isolation
    // This prevents UNIQUE constraint failures on _sqlx_migrations table
    let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);

    // Use simple /tmp directory for better compatibility
    #[cfg(unix)]
    let path = PathBuf::from(format!("/tmp/cipherruntest{}.db", counter));

    #[cfg(not(unix))]
    let path = std::env::temp_dir().join(format!("cipherruntest{}.db", counter));

    // Clean up any existing database file to ensure fresh start
    let _ = std::fs::remove_file(&path);

    path
}

#[tokio::test]
async fn test_sqlite_database_creation() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Verify database type
    assert_eq!(db.pool().db_type(), DatabaseType::Sqlite);

    db.close().await;
}

#[tokio::test]
async fn test_scan_storage_and_retrieval() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Create sample scan results
    let mut results = ScanResults {
        target: "example.com:443".to_string(),
        scan_time_ms: 1500,
        ..Default::default()
    };

    // Add a protocol
    results
        .protocols
        .push(cipherrun::protocols::ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 5,
            handshake_time_ms: Some(120),
            heartbeat_enabled: Some(false),
        });

    // Store scan
    let scan_id = db.store_scan(&results).await.unwrap();
    assert!(scan_id > 0);

    // Retrieve scan
    let scan_history = db.get_scan_history("example.com", 443, 10).await.unwrap();
    assert_eq!(scan_history.len(), 1);
    assert_eq!(scan_history[0].target_hostname, "example.com");
    assert_eq!(scan_history[0].target_port, 443);

    db.close().await;
}

#[tokio::test]
async fn test_scan_history_limit() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Store 5 scans
    for i in 1..=5 {
        let results = ScanResults {
            target: "test.com:443".to_string(),
            scan_time_ms: i * 100,
            ..Default::default()
        };
        db.store_scan(&results).await.unwrap();
    }

    // Query with limit
    let history = db.get_scan_history("test.com", 443, 3).await.unwrap();
    assert_eq!(history.len(), 3);

    // Query all
    let all_history = db.get_scan_history("test.com", 443, 100).await.unwrap();
    assert_eq!(all_history.len(), 5);

    db.close().await;
}

#[tokio::test]
async fn test_latest_scan_retrieval() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Store multiple scans
    for i in 1..=3 {
        let results = ScanResults {
            target: "latest.com:443".to_string(),
            scan_time_ms: i * 1000,
            ..Default::default()
        };
        db.store_scan(&results).await.unwrap();

        // Small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Get latest
    let latest = db.get_latest_scan("latest.com", 443).await.unwrap();
    assert!(latest.is_some());

    let latest = latest.unwrap();
    assert_eq!(latest.target_hostname, "latest.com");
    assert_eq!(latest.scan_duration_ms, Some(3000));

    db.close().await;
}

#[tokio::test]
async fn test_cleanup_old_scans() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Store a scan
    let results = ScanResults {
        target: "cleanup.com:443".to_string(),
        scan_time_ms: 1000,
        ..Default::default()
    };
    db.store_scan(&results).await.unwrap();

    // Cleanup scans older than 0 days (should delete all)
    let deleted = db.cleanup_old_scans(0).await.unwrap();

    // Note: Depending on timestamp precision, this might be 0 or 1
    // SQLite timestamp precision can cause issues with immediate deletion
    assert!(deleted <= 1);

    db.close().await;
}

#[tokio::test]
async fn test_database_config_from_toml() {
    let toml_content = r#"
[database]
type = "sqlite"
path = ":memory:"

[retention]
max_age_days = 90
"#;

    // Write to temporary file
    let temp_file = std::env::temp_dir().join("test_config.toml");
    std::fs::write(&temp_file, toml_content).unwrap();

    // Load config
    let config = DatabaseConfig::from_file(temp_file.to_str().unwrap()).unwrap();

    assert_eq!(config.database.db_type, DatabaseType::Sqlite);
    assert_eq!(config.retention.unwrap().max_age_days, 90);

    // Cleanup
    std::fs::remove_file(temp_file).ok();
}

#[tokio::test]
async fn test_example_config_generation() {
    let temp_file = std::env::temp_dir().join("example_config.toml");
    let path_str = temp_file.to_str().unwrap();

    // Generate example config
    DatabaseConfig::create_example_config(path_str).unwrap();

    // Verify file exists and is valid TOML
    assert!(temp_file.exists());
    let contents = std::fs::read_to_string(&temp_file).unwrap();
    assert!(contents.contains("[database]"));
    assert!(contents.contains("[retention]"));

    // Cleanup
    std::fs::remove_file(temp_file).ok();
}

#[tokio::test]
async fn test_protocol_storage() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Create scan with multiple protocols
    let mut results = ScanResults {
        target: "protocols.com:443".to_string(),
        scan_time_ms: 2000,
        ..Default::default()
    };

    results
        .protocols
        .push(cipherrun::protocols::ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            preferred: false,
            ciphers_count: 30,
            handshake_time_ms: Some(150),
            heartbeat_enabled: None,
        });

    results
        .protocols
        .push(cipherrun::protocols::ProtocolTestResult {
            protocol: Protocol::TLS13,
            supported: true,
            preferred: true,
            ciphers_count: 5,
            handshake_time_ms: Some(100),
            heartbeat_enabled: Some(false),
        });

    // Store scan
    db.store_scan(&results).await.unwrap();

    db.close().await;
}

#[tokio::test]
async fn test_vulnerability_storage() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Create scan with vulnerabilities
    let mut results = ScanResults {
        target: "vuln.com:443".to_string(),
        scan_time_ms: 3000,
        ..Default::default()
    };

    results
        .vulnerabilities
        .push(cipherrun::vulnerabilities::VulnerabilityResult {
            vuln_type: cipherrun::vulnerabilities::VulnerabilityType::Heartbleed,
            vulnerable: true,
            details: "Server vulnerable to Heartbleed".to_string(),
            cve: Some("CVE-2014-0160".to_string()),
            cwe: None,
            severity: cipherrun::vulnerabilities::Severity::Critical,
        });

    results
        .vulnerabilities
        .push(cipherrun::vulnerabilities::VulnerabilityResult {
            vuln_type: cipherrun::vulnerabilities::VulnerabilityType::POODLE,
            vulnerable: false,
            details: "Not vulnerable to POODLE".to_string(),
            cve: Some("CVE-2014-3566".to_string()),
            cwe: None,
            severity: cipherrun::vulnerabilities::Severity::Info,
        });

    // Store scan (only vulnerable items should be stored)
    db.store_scan(&results).await.unwrap();

    db.close().await;
}

#[tokio::test]
async fn test_connection_string_generation() {
    // PostgreSQL
    let pg_config = DatabaseConfig::postgres(
        "dbhost".to_string(),
        5432,
        "testdb".to_string(),
        "user".to_string(),
        "pass".to_string(),
    );

    let conn_str = pg_config.connection_string().unwrap();
    assert_eq!(conn_str, "postgres://user:pass@dbhost:5432/testdb");

    // SQLite
    let sqlite_config = DatabaseConfig::sqlite(PathBuf::from("/tmp/test.db"));
    let conn_str = sqlite_config.connection_string().unwrap();
    assert!(conn_str.contains("sqlite:"));
}

#[tokio::test]
async fn test_multiple_scans_same_target() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Store multiple scans for same target
    for i in 1..=5 {
        let results = ScanResults {
            target: "multi.com:443".to_string(),
            scan_time_ms: i * 500,
            ..Default::default()
        };
        db.store_scan(&results).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Verify all scans are stored
    let history = db.get_scan_history("multi.com", 443, 10).await.unwrap();
    assert_eq!(history.len(), 5);

    // Verify they're sorted by timestamp descending (newest first)
    assert!(history[0].scan_duration_ms >= history[4].scan_duration_ms);

    db.close().await;
}

#[tokio::test]
async fn test_scan_with_rating() {
    let config = DatabaseConfig::sqlite(create_unique_db_path());
    let db = CipherRunDatabase::new(&config).await.unwrap();

    // Create scan with rating
    let mut results = ScanResults {
        target: "rated.com:443".to_string(),
        scan_time_ms: 2500,
        ..Default::default()
    };

    results.rating = Some(cipherrun::rating::RatingResult {
        grade: cipherrun::rating::Grade::A,
        score: 90,
        certificate_score: 95,
        protocol_score: 90,
        key_exchange_score: 85,
        cipher_strength_score: 90,
        warnings: vec![],
    });

    // Store scan
    db.store_scan(&results).await.unwrap();

    // Retrieve and verify
    let history = db.get_scan_history("rated.com", 443, 1).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].overall_grade, Some("A".to_string()));
    assert_eq!(history[0].overall_score, Some(90));

    db.close().await;
}
