// Analytics integration tests for scan comparator, change tracker, and dashboard generator.

mod common;

use chrono::{Duration, Utc};
use cipherrun::db::analytics::{ChangeTracker, DashboardGenerator, ScanComparator};
use cipherrun::db::{BindValue, CipherRunDatabase, DatabaseConfig};
use std::sync::Arc;

async fn setup_db() -> Arc<CipherRunDatabase> {
    let config = DatabaseConfig::sqlite(common::sqlite::unique_sqlite_db_path(
        "cipherrun-analytics-test",
    ));
    let db = CipherRunDatabase::new(&config)
        .await
        .expect("test assertion should succeed");
    Arc::new(db)
}

async fn insert_scan(
    db: &CipherRunDatabase,
    hostname: &str,
    port: u16,
    timestamp: chrono::DateTime<chrono::Utc>,
    grade: Option<&str>,
    score: Option<i32>,
) -> i64 {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_returning_query(
        "scans",
        &[
            "target_hostname",
            "target_port",
            "scan_timestamp",
            "overall_grade",
            "overall_score",
            "scan_duration_ms",
            "scanner_version",
        ],
        "scan_id",
    );

    let bindings = vec![
        BindValue::String(hostname.to_string()),
        BindValue::Int32(port as i32),
        BindValue::DateTime(timestamp),
        BindValue::OptString(grade.map(|g| g.to_string())),
        BindValue::OptInt32(score),
        BindValue::OptInt32(Some(1200)),
        BindValue::OptString(Some("test".to_string())),
    ];

    db.pool()
        .execute_insert_returning(&query, bindings)
        .await
        .expect("test assertion should succeed")
}

async fn insert_protocol(
    db: &CipherRunDatabase,
    scan_id: i64,
    name: &str,
    enabled: bool,
    preferred: bool,
) {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_query(
        "protocols",
        &["scan_id", "protocol_name", "enabled", "preferred"],
    );
    let bindings = vec![
        BindValue::Int64(scan_id),
        BindValue::String(name.to_string()),
        BindValue::Bool(enabled),
        BindValue::Bool(preferred),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

async fn insert_cipher(
    db: &CipherRunDatabase,
    scan_id: i64,
    protocol: &str,
    cipher_name: &str,
    strength: &str,
    forward_secrecy: bool,
) {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_query(
        "cipher_suites",
        &[
            "scan_id",
            "protocol_name",
            "cipher_name",
            "key_exchange",
            "authentication",
            "encryption",
            "mac",
            "bits",
            "forward_secrecy",
            "strength",
        ],
    );
    let bindings = vec![
        BindValue::Int64(scan_id),
        BindValue::String(protocol.to_string()),
        BindValue::String(cipher_name.to_string()),
        BindValue::OptString(None),
        BindValue::OptString(None),
        BindValue::OptString(None),
        BindValue::OptString(None),
        BindValue::OptInt32(None),
        BindValue::Bool(forward_secrecy),
        BindValue::String(strength.to_string()),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

async fn insert_vulnerability(
    db: &CipherRunDatabase,
    scan_id: i64,
    vuln_type: &str,
    severity: &str,
) {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_query(
        "vulnerabilities",
        &[
            "scan_id",
            "vulnerability_type",
            "severity",
            "description",
            "cve_id",
            "affected_component",
        ],
    );
    let bindings = vec![
        BindValue::Int64(scan_id),
        BindValue::String(vuln_type.to_string()),
        BindValue::String(severity.to_string()),
        BindValue::OptString(None),
        BindValue::OptString(None),
        BindValue::OptString(None),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

async fn insert_rating(
    db: &CipherRunDatabase,
    scan_id: i64,
    category: &str,
    score: i32,
    grade: Option<&str>,
) {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_query(
        "ratings",
        &["scan_id", "category", "score", "grade", "rationale"],
    );
    let bindings = vec![
        BindValue::Int64(scan_id),
        BindValue::String(category.to_string()),
        BindValue::Int32(score),
        BindValue::OptString(grade.map(|g| g.to_string())),
        BindValue::OptString(None),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

async fn insert_certificate(
    db: &CipherRunDatabase,
    fingerprint: &str,
    subject: &str,
    issuer: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
    key_size: Option<i32>,
) -> i64 {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_returning_query(
        "certificates",
        &[
            "fingerprint_sha256",
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "public_key_size",
        ],
        "cert_id",
    );
    let bindings = vec![
        BindValue::String(fingerprint.to_string()),
        BindValue::String(subject.to_string()),
        BindValue::String(issuer.to_string()),
        BindValue::DateTime(not_before),
        BindValue::DateTime(not_after),
        BindValue::OptInt32(key_size),
    ];
    db.pool()
        .execute_insert_returning(&query, bindings)
        .await
        .expect("test assertion should succeed")
}

async fn link_certificate(db: &CipherRunDatabase, scan_id: i64, cert_id: i64, chain_position: i32) {
    let mut qb = db.pool().query_builder();
    let query = qb.insert_query(
        "scan_certificates",
        &["scan_id", "cert_id", "chain_position"],
    );
    let bindings = vec![
        BindValue::Int64(scan_id),
        BindValue::Int64(cert_id),
        BindValue::Int32(chain_position),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

#[tokio::test]
async fn test_scan_comparator_compare_scans() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1_time = now - Duration::days(2);
    let scan2_time = now - Duration::days(1);

    let scan1 = insert_scan(&db, "example.com", 443, scan1_time, Some("A"), Some(90)).await;
    let scan2 = insert_scan(&db, "example.com", 443, scan2_time, Some("B"), Some(80)).await;

    insert_protocol(&db, scan1, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan2, "TLS 1.3", true, true).await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_COMMON", "strong", true).await;
    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_OLD", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.2", "CIPHER_COMMON", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.3", "CIPHER_NEW", "strong", true).await;

    insert_vulnerability(&db, scan1, "Heartbleed", "critical").await;
    insert_vulnerability(&db, scan2, "Heartbleed", "critical").await;
    insert_vulnerability(&db, scan2, "POODLE", "high").await;

    insert_rating(&db, scan1, "protocol", 90, Some("A")).await;
    insert_rating(&db, scan1, "cipher", 95, Some("A")).await;
    insert_rating(&db, scan2, "protocol", 80, Some("B")).await;
    insert_rating(&db, scan2, "cipher", 95, Some("A")).await;

    let cert1 = insert_certificate(
        &db,
        "fp1",
        "CN=example.com",
        "CN=CA",
        scan1_time - Duration::days(30),
        scan1_time + Duration::days(365),
        Some(2048),
    )
    .await;
    let cert2 = insert_certificate(
        &db,
        "fp2",
        "CN=example.com",
        "CN=NewCA",
        scan2_time - Duration::days(30),
        scan2_time + Duration::days(365),
        Some(4096),
    )
    .await;
    link_certificate(&db, scan1, cert1, 0).await;
    link_certificate(&db, scan2, cert2, 0).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(
        comparison
            .protocol_diff
            .added
            .contains(&"TLS 1.3".to_string())
    );
    assert!(
        comparison
            .protocol_diff
            .removed
            .contains(&"TLS 1.2".to_string())
    );
    assert!(comparison.protocol_diff.preferred_change.is_some());

    assert!(
        comparison
            .cipher_diff
            .added
            .iter()
            .any(|c| c.name == "CIPHER_NEW")
    );
    assert!(
        comparison
            .cipher_diff
            .removed
            .iter()
            .any(|c| c.name == "CIPHER_OLD")
    );
    assert!(
        comparison
            .cipher_diff
            .unchanged
            .iter()
            .any(|c| c.name == "CIPHER_COMMON")
    );

    assert!(comparison.certificate_diff.fingerprint_changed);
    assert!(comparison.certificate_diff.issuer_changed);
    assert!(comparison.certificate_diff.key_size_changed);

    assert!(
        comparison
            .vulnerability_diff
            .new
            .iter()
            .any(|v| v.vuln_type == "POODLE")
    );
    assert!(
        comparison
            .vulnerability_diff
            .unchanged
            .iter()
            .any(|v| v.vuln_type == "Heartbleed")
    );

    assert!(comparison.rating_diff.overall_changed);
    assert!(comparison.summary.total_changes > 0);

    let json_output = comparator
        .format_comparison(&comparison, "json")
        .expect("test assertion should succeed");
    assert!(json_output.contains("\"protocol_diff\""));

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("SCAN COMPARISON"));
}

#[tokio::test]
async fn test_scan_comparator_compare_latest() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "latest.test",
        443,
        now - Duration::days(3),
        Some("A"),
        Some(95),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "latest.test",
        443,
        now - Duration::days(2),
        Some("B"),
        Some(85),
    )
    .await;
    let scan3 = insert_scan(
        &db,
        "latest.test",
        443,
        now - Duration::days(1),
        Some("C"),
        Some(75),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan2, "TLS 1.3", true, true).await;
    insert_protocol(&db, scan3, "TLS 1.3", true, true).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_latest("latest.test", 443)
        .await
        .expect("test assertion should succeed");

    assert_eq!(comparison.scan_1.scan_id, Some(scan2));
    assert_eq!(comparison.scan_2.scan_id, Some(scan3));
}

#[tokio::test]
async fn test_change_tracker_detect_changes_and_report() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1 = insert_scan(
        &db,
        "changes.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "changes.test",
        443,
        now - Duration::days(1),
        Some("B"),
        Some(70),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan2, "TLS 1.3", true, true).await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_OLD", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.2", "CIPHER_NEW", "strong", true).await;

    insert_vulnerability(&db, scan1, "Heartbleed", "critical").await;
    insert_vulnerability(&db, scan2, "POODLE", "high").await;

    let cert1 = insert_certificate(
        &db,
        "change_fp1",
        "CN=changes.test",
        "CN=CA",
        now - Duration::days(90),
        now + Duration::days(365),
        Some(2048),
    )
    .await;
    let cert2 = insert_certificate(
        &db,
        "change_fp2",
        "CN=changes.test",
        "CN=NewCA",
        now - Duration::days(90),
        now + Duration::days(365),
        Some(4096),
    )
    .await;
    link_certificate(&db, scan1, cert1, 0).await;
    link_certificate(&db, scan2, cert2, 0).await;

    insert_rating(&db, scan1, "protocol", 90, Some("A")).await;
    insert_rating(&db, scan2, "protocol", 70, Some("B")).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(changes.iter().any(|c| matches!(
        c.change_type,
        cipherrun::db::analytics::ChangeType::Protocol
    )));
    assert!(
        changes
            .iter()
            .any(|c| matches!(c.change_type, cipherrun::db::analytics::ChangeType::Cipher))
    );
    assert!(changes.iter().any(|c| matches!(
        c.change_type,
        cipherrun::db::analytics::ChangeType::Certificate
    )));
    assert!(changes.iter().any(|c| matches!(
        c.change_type,
        cipherrun::db::analytics::ChangeType::Vulnerability
    )));
    assert!(
        changes
            .iter()
            .any(|c| matches!(c.change_type, cipherrun::db::analytics::ChangeType::Rating))
    );

    let rating_change = changes
        .iter()
        .find(|c| matches!(c.change_type, cipherrun::db::analytics::ChangeType::Rating))
        .expect("rating change should exist");
    assert_eq!(
        rating_change.severity,
        cipherrun::db::analytics::ChangeSeverity::High
    );

    let report = tracker.generate_change_report(&changes);
    assert!(report.contains("Change Report"));
}

#[tokio::test]
async fn test_dashboard_generator_output() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1 = insert_scan(
        &db,
        "dashboard.test",
        443,
        now - Duration::days(5),
        Some("B"),
        Some(80),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "dashboard.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(92),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan2, "TLS 1.3", true, true).await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_WEAK", "weak", false).await;
    insert_cipher(&db, scan2, "TLS 1.3", "CIPHER_STRONG", "strong", true).await;

    insert_vulnerability(&db, scan1, "Heartbleed", "critical").await;
    insert_vulnerability(&db, scan2, "POODLE", "high").await;

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    assert_eq!(dashboard.summary.total_scans, 2);
    assert_eq!(dashboard.summary.latest_grade, Some("A".to_string()));
    assert_eq!(dashboard.summary.latest_score, Some(92));
    assert_eq!(dashboard.rating_timeseries.len(), 2);

    assert!(
        dashboard
            .vulnerability_distribution
            .iter()
            .any(|d| d.label == "critical" && d.value == 1)
    );
    assert!(
        dashboard
            .vulnerability_distribution
            .iter()
            .any(|d| d.label == "high" && d.value == 1)
    );

    assert!(
        dashboard
            .protocol_distribution
            .iter()
            .any(|d| d.label == "TLS 1.2")
    );
    assert!(
        dashboard
            .protocol_distribution
            .iter()
            .any(|d| d.label == "TLS 1.3")
    );

    assert!(
        dashboard
            .cipher_strength
            .iter()
            .any(|d| d.label == "weak" && d.value == 1)
    );
    assert!(
        dashboard
            .cipher_strength
            .iter()
            .any(|d| d.label == "strong" && d.value == 1)
    );

    let json_output = generator
        .to_json(&dashboard, true)
        .expect("test assertion should succeed");
    assert!(json_output.contains("\"summary\""));
}
