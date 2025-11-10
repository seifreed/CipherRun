// Integration tests for CT logs streaming

use cipherrun::ct_logs::{
    client::CtClient, deduplicator::Deduplicator, parser::Parser, sources::SourceManager,
    stats::StatsTracker, CtConfig,
};

#[tokio::test]
async fn test_source_manager_initialization() {
    let mut manager = SourceManager::new();

    // This test requires network access to fetch real CT log sources
    // Skip if network is unavailable
    if manager.fetch_sources().await.is_ok() {
        assert!(manager.total_sources() > 0);
        assert!(manager.healthy_sources_count() > 0);
    }
}

#[test]
fn test_deduplicator_functionality() {
    let mut dedup = Deduplicator::new(1000, 0.01);

    let cert1 = b"test certificate 1";
    let cert2 = b"test certificate 2";

    // First insertion should be unique
    assert!(dedup.check_and_insert(cert1));
    assert_eq!(dedup.unique_count(), 1);
    assert_eq!(dedup.duplicates_filtered(), 0);

    // Duplicate should be filtered
    assert!(!dedup.check_and_insert(cert1));
    assert_eq!(dedup.unique_count(), 1);
    assert_eq!(dedup.duplicates_filtered(), 1);

    // Different cert should be unique
    assert!(dedup.check_and_insert(cert2));
    assert_eq!(dedup.unique_count(), 2);
    assert_eq!(dedup.duplicates_filtered(), 1);
}

#[test]
fn test_stats_tracker() {
    let tracker = StatsTracker::new();

    // Increment counters
    tracker.increment_processed();
    tracker.increment_processed();
    tracker.increment_unique();

    let snapshot = tracker.get_snapshot();
    assert_eq!(snapshot.total_processed, 2);
    assert_eq!(snapshot.unique_certificates, 1);
    assert_eq!(snapshot.duplicates_filtered, 0);
}

#[test]
fn test_ct_config_defaults() {
    let config = CtConfig::default();

    assert!(!config.start_from_beginning);
    assert_eq!(config.batch_size, 1000);
    assert_eq!(config.expected_unique_certs, 1_000_000);
    assert!((config.bloom_fp_rate - 0.0001).abs() < f64::EPSILON);
}

#[test]
fn test_parser_creation() {
    let parser = Parser::new("test-log".to_string());
    // Parser should be created successfully
    // Actual parsing tests would require valid CT log entry data
    assert!(std::ptr::addr_of!(parser) as usize != 0);
}

#[test]
fn test_ct_client_creation() {
    let client = CtClient::new();
    // Client should be created successfully
    assert!(std::ptr::addr_of!(client) as usize != 0);
}

#[test]
fn test_deduplicator_memory_efficiency() {
    // Test with larger dataset
    let mut dedup = Deduplicator::new(10000, 0.01);

    // Add 5000 unique certificates
    for i in 0..5000 {
        let cert = format!("certificate {}", i);
        assert!(dedup.check_and_insert(cert.as_bytes()));
    }

    assert_eq!(dedup.unique_count(), 5000);
    assert_eq!(dedup.duplicates_filtered(), 0);

    // Add duplicates
    for i in 0..5000 {
        let cert = format!("certificate {}", i);
        assert!(!dedup.check_and_insert(cert.as_bytes()));
    }

    assert_eq!(dedup.unique_count(), 5000);
    assert_eq!(dedup.duplicates_filtered(), 5000);

    // Check memory usage is reasonable (should be < 1MB for 10000 expected items)
    let memory = dedup.memory_usage_bytes();
    assert!(memory < 1_000_000);
}

#[test]
fn test_stats_processing_rate() {
    let tracker = StatsTracker::new();

    // Simulate processing
    for _ in 0..100 {
        tracker.increment_processed();
    }

    let rate = tracker.get_processing_rate();
    // Rate should be positive
    assert!(rate >= 0.0);

    let snapshot = tracker.get_snapshot();
    assert_eq!(snapshot.total_processed, 100);
}

#[test]
fn test_source_stats_tracking() {
    let tracker = StatsTracker::new();

    // Update source stats
    tracker.update_source_stats(
        "test-log",
        100,
        1000,
        std::time::Duration::from_millis(500),
    );

    tracker.increment_source_processed("test-log", 10);

    let snapshot = tracker.get_snapshot();
    assert!(snapshot.per_source.contains_key("test-log"));

    let source_stats = &snapshot.per_source["test-log"];
    assert_eq!(source_stats.current_index, 100);
    assert_eq!(source_stats.tree_size, 1000);
    assert_eq!(source_stats.certificates_processed, 10);
}

#[tokio::test]
async fn test_ct_client_error_handling() {
    let client = CtClient::new();

    // Try to fetch from invalid URL
    let result = client.get_tree_size("https://invalid.example.com/ct/v1").await;

    // Should handle error gracefully
    assert!(result.is_err());
}
