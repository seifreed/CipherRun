// Analytics integration tests for scan comparator, change tracker, and dashboard generator.

mod common;

use chrono::{Duration, Utc};
use cipherrun::db::analytics::{
    ChangeEvent, ChangeSeverity, ChangeTracker, ChangeType, DashboardGenerator, ScanComparator,
};
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
    insert_rating_with_rationale(db, scan_id, category, score, grade, None).await;
}

async fn insert_rating_with_rationale(
    db: &CipherRunDatabase,
    scan_id: i64,
    category: &str,
    score: i32,
    grade: Option<&str>,
    rationale: Option<&str>,
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
        BindValue::OptString(rationale.map(|value| value.to_string())),
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
async fn test_scan_comparator_does_not_report_protocol_changes_for_name_format_variants() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1 = insert_scan(
        &db,
        "comparator-protocol-format.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "comparator-protocol-format.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.3", true, true).await;
    insert_protocol(&db, scan1, "TLS 1.2", true, false).await;
    insert_protocol(&db, scan2, "TLSv1.3", true, true).await;
    insert_protocol(&db, scan2, "tlsv1.2", true, false).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(comparison.protocol_diff.added.is_empty());
    assert!(comparison.protocol_diff.removed.is_empty());
    assert_eq!(comparison.protocol_diff.unchanged.len(), 2);
    assert!(comparison.protocol_diff.preferred_change.is_none());
    assert_eq!(comparison.summary.protocol_changes, 0);
}

#[tokio::test]
async fn test_scan_comparator_renders_component_rating_changes_without_overall_change() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "rating-components.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "rating-components.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_rating(&db, scan1, "certificate", 90, Some("A")).await;
    insert_rating(&db, scan2, "certificate", 90, Some("A")).await;
    insert_rating(&db, scan1, "protocol", 80, Some("B")).await;
    insert_rating(&db, scan2, "protocol", 80, Some("B")).await;
    insert_rating(&db, scan1, "key_exchange", 70, Some("C")).await;
    insert_rating(&db, scan2, "key_exchange", 70, Some("C")).await;
    insert_rating(&db, scan1, "cipher", 95, Some("A")).await;
    insert_rating(&db, scan2, "cipher", 90, Some("A")).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(!comparison.rating_diff.overall_changed);
    assert_eq!(comparison.summary.rating_changes, 1);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("RATING CHANGES"));
    assert!(terminal_output.contains("cipher:"));
    assert!(terminal_output.contains("Fields: score"));
    assert!(terminal_output.contains("Before: score=95 grade=A rationale=N/A"));
    assert!(terminal_output.contains("After:  score=90 grade=A rationale=N/A"));
}

#[tokio::test]
async fn test_scan_comparator_marks_rating_grade_and_rationale_changes_as_changed() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "rating-metadata-change.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "rating-metadata-change.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_rating_with_rationale(
        &db,
        scan1,
        "protocol",
        90,
        Some("A"),
        Some("Legacy protocol allowed"),
    )
    .await;
    insert_rating_with_rationale(
        &db,
        scan2,
        "protocol",
        90,
        Some("B"),
        Some("TLS 1.3 required"),
    )
    .await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let protocol_rating = comparison
        .rating_diff
        .component_diffs
        .iter()
        .find(|component| component.category == "protocol")
        .expect("protocol rating diff should exist");
    assert!(protocol_rating.changed);
    assert_eq!(protocol_rating.scan_1_score, Some(90));
    assert_eq!(protocol_rating.scan_2_score, Some(90));
    assert_eq!(protocol_rating.scan_1_grade.as_deref(), Some("A"));
    assert_eq!(protocol_rating.scan_2_grade.as_deref(), Some("B"));
    assert_eq!(
        protocol_rating.scan_1_rationale.as_deref(),
        Some("Legacy protocol allowed")
    );
    assert_eq!(
        protocol_rating.scan_2_rationale.as_deref(),
        Some("TLS 1.3 required")
    );
    assert_eq!(comparison.summary.rating_changes, 1);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("protocol:"));
    assert!(terminal_output.contains("Fields: grade, rationale"));
    assert!(terminal_output.contains("Before: score=90 grade=A rationale=Legacy protocol allowed"));
    assert!(terminal_output.contains("After:  score=90 grade=B rationale=TLS 1.3 required"));
}

#[tokio::test]
async fn test_scan_comparator_renders_preferred_only_protocol_changes() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "preferred-change.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "preferred-change.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.2", true, true).await;
    insert_protocol(&db, scan1, "TLS 1.3", true, false).await;
    insert_protocol(&db, scan2, "TLS 1.2", true, false).await;
    insert_protocol(&db, scan2, "TLS 1.3", true, true).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(comparison.protocol_diff.added.is_empty());
    assert!(comparison.protocol_diff.removed.is_empty());
    assert_eq!(
        comparison.protocol_diff.preferred_change,
        Some((Some("TLS 1.2".to_string()), Some("TLS 1.3".to_string())))
    );
    assert_eq!(comparison.summary.protocol_changes, 1);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("PROTOCOL CHANGES"));
    assert!(terminal_output.contains("Preferred: Some(\"TLS 1.2\") → Some(\"TLS 1.3\")"));
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
async fn test_scan_comparator_protocol_and_cipher_diffs_are_order_stable() {
    let db = setup_db().await;
    let now = Utc::now();

    let pair_a_old = insert_scan(
        &db,
        "order-a.test",
        443,
        now - Duration::days(3),
        Some("A"),
        Some(95),
    )
    .await;
    let pair_a_new = insert_scan(
        &db,
        "order-a.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(96),
    )
    .await;

    insert_protocol(&db, pair_a_old, "TLS 1.2", true, true).await;
    insert_protocol(&db, pair_a_old, "TLS 1.0", true, false).await;
    insert_protocol(&db, pair_a_new, "TLS 1.3", true, true).await;
    insert_protocol(&db, pair_a_new, "TLS 1.1", true, false).await;

    insert_cipher(&db, pair_a_old, "TLS 1.2", "CIPHER_A", "strong", true).await;
    insert_cipher(&db, pair_a_old, "TLS 1.2", "CIPHER_B", "weak", true).await;
    insert_cipher(&db, pair_a_new, "TLS 1.3", "CIPHER_D", "medium", true).await;
    insert_cipher(&db, pair_a_new, "TLS 1.3", "CIPHER_C", "strong", true).await;

    let pair_b_old = insert_scan(
        &db,
        "order-b.test",
        444,
        now - Duration::days(3),
        Some("A"),
        Some(95),
    )
    .await;
    let pair_b_new = insert_scan(
        &db,
        "order-b.test",
        444,
        now - Duration::days(2),
        Some("A"),
        Some(96),
    )
    .await;

    insert_protocol(&db, pair_b_old, "TLS 1.0", true, false).await;
    insert_protocol(&db, pair_b_old, "TLS 1.2", true, true).await;
    insert_protocol(&db, pair_b_new, "TLS 1.1", true, false).await;
    insert_protocol(&db, pair_b_new, "TLS 1.3", true, true).await;

    insert_cipher(&db, pair_b_old, "TLS 1.2", "CIPHER_B", "weak", true).await;
    insert_cipher(&db, pair_b_old, "TLS 1.2", "CIPHER_A", "strong", true).await;
    insert_cipher(&db, pair_b_new, "TLS 1.3", "CIPHER_C", "strong", true).await;
    insert_cipher(&db, pair_b_new, "TLS 1.3", "CIPHER_D", "medium", true).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison_a = comparator
        .compare_scans(pair_a_old, pair_a_new)
        .await
        .expect("test assertion should succeed");
    let comparison_b = comparator
        .compare_scans(pair_b_old, pair_b_new)
        .await
        .expect("test assertion should succeed");

    assert_eq!(
        serde_json::to_string(&comparison_a.protocol_diff).expect("protocol json"),
        serde_json::to_string(&comparison_b.protocol_diff).expect("protocol json"),
    );
    assert_eq!(
        serde_json::to_string(&comparison_a.cipher_diff).expect("cipher json"),
        serde_json::to_string(&comparison_b.cipher_diff).expect("cipher json"),
    );

    assert_eq!(
        comparison_a.protocol_diff.added,
        vec!["TLS 1.1".to_string(), "TLS 1.3".to_string()]
    );
    assert_eq!(
        comparison_a.protocol_diff.removed,
        vec!["TLS 1.0".to_string(), "TLS 1.2".to_string()]
    );
    assert_eq!(
        comparison_a
            .cipher_diff
            .added
            .iter()
            .map(|cipher| cipher.name.as_str())
            .collect::<Vec<_>>(),
        vec!["CIPHER_C", "CIPHER_D"]
    );
    assert_eq!(
        comparison_a
            .cipher_diff
            .removed
            .iter()
            .map(|cipher| cipher.name.as_str())
            .collect::<Vec<_>>(),
        vec!["CIPHER_A", "CIPHER_B"]
    );
}

#[tokio::test]
async fn test_scan_comparator_marks_vulnerability_severity_changes_as_changed() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "severity-change.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "severity-change.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_vulnerability(&db, scan1, "SeverityFlip", "high").await;
    insert_vulnerability(&db, scan2, "SeverityFlip", "critical").await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert_eq!(comparison.vulnerability_diff.new.len(), 0);
    assert_eq!(comparison.vulnerability_diff.resolved.len(), 0);
    assert_eq!(comparison.vulnerability_diff.changed.len(), 1);
    assert_eq!(
        comparison.vulnerability_diff.changed[0].vuln_type,
        "SeverityFlip"
    );
    assert_eq!(
        comparison.vulnerability_diff.changed[0].severity,
        "critical"
    );
    assert_eq!(comparison.summary.vulnerability_changes, 1);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("Changed Vulnerabilities"));
}

#[tokio::test]
async fn test_scan_comparator_does_not_pair_unrelated_same_type_vulnerabilities() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "unrelated-vulns.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "unrelated-vulns.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_vulnerability(&db, scan1, "GenericIssue", "critical").await;
    insert_vulnerability(&db, scan1, "GenericIssue", "high").await;
    insert_vulnerability(&db, scan2, "GenericIssue", "low").await;
    insert_vulnerability(&db, scan2, "GenericIssue", "info").await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(comparison.vulnerability_diff.changed.is_empty());
    assert_eq!(comparison.vulnerability_diff.new.len(), 2);
    assert_eq!(comparison.vulnerability_diff.resolved.len(), 2);
    assert_eq!(comparison.summary.vulnerability_changes, 4);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("New Vulnerabilities"));
    assert!(terminal_output.contains("Resolved Vulnerabilities"));
}

#[tokio::test]
async fn test_scan_comparator_marks_cipher_attribute_changes_as_changed() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "cipher-change.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(92),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "cipher-change.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(93),
    )
    .await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_STABLE", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.2", "CIPHER_STABLE", "weak", false).await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(comparison.cipher_diff.added.is_empty());
    assert!(comparison.cipher_diff.removed.is_empty());
    assert!(comparison.cipher_diff.unchanged.is_empty());
    assert_eq!(comparison.cipher_diff.changed.len(), 1);
    assert_eq!(
        comparison.cipher_diff.changed[0].current.name,
        "CIPHER_STABLE"
    );
    assert_eq!(
        comparison.cipher_diff.changed[0].changed_fields,
        vec!["forward_secrecy".to_string(), "strength".to_string()]
    );
    assert_eq!(comparison.summary.cipher_changes, 1);

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("Changed (1)"));
    assert!(terminal_output.contains("CIPHER_STABLE"));
}

#[tokio::test]
async fn test_scan_comparator_ipv6_terminal_format() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "2001:db8::1",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "2001:db8::1",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    let comparator = ScanComparator::new(Arc::clone(&db));
    let comparison = comparator
        .compare_scans(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let terminal_output = comparator
        .format_comparison(&comparison, "terminal")
        .expect("test assertion should succeed");
    assert!(terminal_output.contains("Target: [2001:db8::1]:443"));
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
async fn test_change_tracker_does_not_report_protocol_changes_for_name_format_variants() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1 = insert_scan(
        &db,
        "protocol-format-change.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "protocol-format-change.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_protocol(&db, scan1, "TLS 1.3", true, true).await;
    insert_protocol(&db, scan1, "TLS 1.2", true, false).await;
    insert_protocol(&db, scan2, "TLSv1.3", true, true).await;
    insert_protocol(&db, scan2, "tlsv1.2", true, false).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(
        changes
            .iter()
            .all(|change| !matches!(change.change_type, ChangeType::Protocol)),
        "format-only protocol name differences should not produce protocol changes: {changes:?}"
    );
}

#[tokio::test]
async fn test_change_tracker_marks_vulnerability_severity_changes_as_changed() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "change-tracker-severity.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-severity.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_vulnerability(&db, scan1, "SeverityFlip", "high").await;
    insert_vulnerability(&db, scan2, "SeverityFlip", "critical").await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let vulnerability_changes: Vec<_> = changes
        .iter()
        .filter(|change| matches!(change.change_type, ChangeType::Vulnerability))
        .collect();
    assert_eq!(vulnerability_changes.len(), 1);
    assert_eq!(
        vulnerability_changes[0].description,
        "Vulnerability changed: SeverityFlip"
    );
    assert_eq!(vulnerability_changes[0].severity, ChangeSeverity::Critical);
    assert_eq!(
        vulnerability_changes[0].previous_value.as_deref(),
        Some("severity=high")
    );
    assert_eq!(
        vulnerability_changes[0].current_value.as_deref(),
        Some("severity=critical")
    );

    let report = tracker.generate_change_report(&changes);
    assert!(report.contains("Vulnerability changed: SeverityFlip"));
    assert!(!report.contains("Vulnerability resolved: SeverityFlip"));
    assert!(!report.contains("New vulnerability detected: SeverityFlip"));
}

#[tokio::test]
async fn test_change_tracker_normalizes_vulnerability_severity_labels() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan1 = insert_scan(
        &db,
        "change-tracker-severity-label.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-severity-label.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_vulnerability(&db, scan2, "UppercaseSeverity", "Critical").await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let vulnerability_change = changes
        .iter()
        .find(|change| matches!(change.change_type, ChangeType::Vulnerability))
        .expect("new vulnerability should be reported");

    assert_eq!(vulnerability_change.severity, ChangeSeverity::Critical);
}

#[tokio::test]
async fn test_change_tracker_does_not_pair_unrelated_same_type_vulnerabilities() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "change-tracker-unrelated.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-unrelated.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_vulnerability(&db, scan1, "GenericIssue", "critical").await;
    insert_vulnerability(&db, scan1, "GenericIssue", "high").await;
    insert_vulnerability(&db, scan2, "GenericIssue", "low").await;
    insert_vulnerability(&db, scan2, "GenericIssue", "info").await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let vulnerability_changes: Vec<_> = changes
        .iter()
        .filter(|change| matches!(change.change_type, ChangeType::Vulnerability))
        .collect();
    assert_eq!(vulnerability_changes.len(), 4);
    assert_eq!(
        vulnerability_changes
            .iter()
            .filter(|change| change.description.starts_with("Vulnerability changed"))
            .count(),
        0
    );
    assert_eq!(
        vulnerability_changes
            .iter()
            .filter(|change| change.description.starts_with("Vulnerability resolved"))
            .count(),
        2
    );
    assert_eq!(
        vulnerability_changes
            .iter()
            .filter(|change| change.description.starts_with("New vulnerability detected"))
            .count(),
        2
    );

    let report = tracker.generate_change_report(&changes);
    assert!(report.contains("Vulnerability resolved: GenericIssue"));
    assert!(report.contains("New vulnerability detected: GenericIssue"));
    assert!(!report.contains("Vulnerability changed: GenericIssue"));
}

#[tokio::test]
async fn test_change_tracker_detects_cipher_protocol_and_attribute_changes() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "change-tracker-cipher.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-cipher.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_SHARED", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.3", "CIPHER_SHARED", "strong", true).await;
    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_TWEAK", "strong", true).await;
    insert_cipher(&db, scan2, "TLS 1.2", "CIPHER_TWEAK", "weak", false).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let cipher_changes: Vec<_> = changes
        .iter()
        .filter(|change| matches!(change.change_type, ChangeType::Cipher))
        .collect();
    assert_eq!(cipher_changes.len(), 3);
    assert!(
        cipher_changes
            .iter()
            .any(|change| change.description == "Cipher added: CIPHER_SHARED [TLS 1.3]")
    );
    assert!(
        cipher_changes
            .iter()
            .any(|change| change.description == "Cipher removed: CIPHER_SHARED [TLS 1.2]")
    );
    let changed = cipher_changes
        .iter()
        .find(|change| change.description == "Cipher changed: CIPHER_TWEAK [TLS 1.2]")
        .expect("cipher changed event should exist");
    assert_eq!(
        changed.previous_value.as_deref(),
        Some(
            "protocol=TLS 1.2, cipher=CIPHER_TWEAK, key_exchange=N/A, authentication=N/A, encryption=N/A, mac=N/A, bits=N/A, forward_secrecy=true, strength=strong"
        )
    );
    assert_eq!(
        changed.current_value.as_deref(),
        Some(
            "protocol=TLS 1.2, cipher=CIPHER_TWEAK, key_exchange=N/A, authentication=N/A, encryption=N/A, mac=N/A, bits=N/A, forward_secrecy=false, strength=weak"
        )
    );
}

#[tokio::test]
async fn test_change_tracker_treats_added_low_cipher_as_weak() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "change-tracker-low-cipher.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-low-cipher.test",
        443,
        now - Duration::days(1),
        Some("C"),
        Some(55),
    )
    .await;

    insert_cipher(&db, scan2, "TLS 1.2", "CIPHER_LOW", "low", false).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let low_cipher_change = changes
        .iter()
        .find(|change| change.description == "Cipher added: CIPHER_LOW [TLS 1.2]")
        .expect("low cipher addition should be reported");

    assert_eq!(low_cipher_change.severity, ChangeSeverity::High);
}

#[tokio::test]
async fn test_change_tracker_does_not_report_cipher_changes_for_protocol_name_format_variants() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "change-tracker-cipher-format.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "change-tracker-cipher-format.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_cipher(&db, scan1, "TLS 1.2", "CIPHER_STABLE", "strong", true).await;
    insert_cipher(&db, scan2, "TLSv1.2", "CIPHER_STABLE", "strong", true).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    assert!(
        changes
            .iter()
            .all(|change| !matches!(change.change_type, ChangeType::Cipher)),
        "format-only protocol name differences should not produce cipher changes: {changes:?}"
    );
}

#[tokio::test]
async fn test_change_tracker_detects_component_rating_changes_without_overall_change() {
    let db = setup_db().await;
    let now = Utc::now();

    let scan1 = insert_scan(
        &db,
        "rating-components.test",
        443,
        now - Duration::days(2),
        Some("A"),
        Some(90),
    )
    .await;
    let scan2 = insert_scan(
        &db,
        "rating-components.test",
        443,
        now - Duration::days(1),
        Some("A"),
        Some(90),
    )
    .await;

    insert_rating(&db, scan1, "protocol", 90, Some("A")).await;
    insert_rating(&db, scan2, "protocol", 70, Some("B")).await;
    insert_rating(&db, scan1, "certificate", 95, Some("A")).await;
    insert_rating(&db, scan2, "certificate", 95, Some("A")).await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes = tracker
        .detect_changes_between(scan1, scan2)
        .await
        .expect("test assertion should succeed");

    let rating_changes: Vec<_> = changes
        .iter()
        .filter(|change| matches!(change.change_type, ChangeType::Rating))
        .collect();
    assert!(
        rating_changes
            .iter()
            .any(|change| change.description == "Rating changed: protocol")
    );
    assert!(
        rating_changes
            .iter()
            .all(|change| change.description != "Overall rating changed")
    );
    assert!(
        rating_changes
            .iter()
            .all(|change| change.description != "Rating changed: certificate")
    );
}

#[tokio::test]
async fn test_change_tracker_report_is_deterministic() {
    let tracker = ChangeTracker::new(setup_db().await);
    let timestamp = Utc::now();

    let changes = vec![
        ChangeEvent {
            change_type: ChangeType::Cipher,
            severity: ChangeSeverity::Medium,
            description: "Cipher added: CIPHER_B".to_string(),
            previous_value: None,
            current_value: Some("strong".to_string()),
            timestamp,
        },
        ChangeEvent {
            change_type: ChangeType::Protocol,
            severity: ChangeSeverity::High,
            description: "Protocol added: TLS 1.3".to_string(),
            previous_value: Some("disabled".to_string()),
            current_value: Some("enabled".to_string()),
            timestamp,
        },
        ChangeEvent {
            change_type: ChangeType::Protocol,
            severity: ChangeSeverity::Low,
            description: "Protocol removed: TLS 1.2".to_string(),
            previous_value: Some("enabled".to_string()),
            current_value: Some("disabled".to_string()),
            timestamp,
        },
    ];

    let mut reversed = changes.clone();
    reversed.reverse();

    assert_eq!(
        tracker.generate_change_report(&changes),
        tracker.generate_change_report(&reversed)
    );
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
    insert_vulnerability(&db, scan1, "AlphaIssue", "high").await;
    insert_vulnerability(&db, scan2, "ZuluIssue", "high").await;

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
            .any(|d| d.label == "high" && d.value == 3)
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
    assert_eq!(
        dashboard
            .protocol_distribution
            .iter()
            .map(|d| d.label.as_str())
            .collect::<Vec<_>>(),
        vec!["TLS 1.2", "TLS 1.3"]
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
    assert_eq!(
        dashboard
            .top_issues
            .iter()
            .map(|i| i.title.as_str())
            .collect::<Vec<_>>(),
        vec!["Heartbleed", "AlphaIssue", "POODLE", "ZuluIssue"]
    );

    let json_output = generator
        .to_json(&dashboard, true)
        .expect("test assertion should succeed");
    assert!(json_output.contains("\"summary\""));
}

#[tokio::test]
async fn test_dashboard_summary_counts_all_issues_before_truncation() {
    let db = setup_db().await;
    let now = Utc::now();
    let scan = insert_scan(
        &db,
        "dashboard-counts.test",
        443,
        now - Duration::days(1),
        None,
        None,
    )
    .await;

    for idx in 0..12 {
        insert_vulnerability(&db, scan, &format!("CriticalIssue{:02}", idx), "critical").await;
    }

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard-counts.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    assert_eq!(dashboard.top_issues.len(), 10);
    assert_eq!(dashboard.summary.total_vulnerabilities, 12);
    assert_eq!(dashboard.summary.critical_vulnerabilities, 12);
}

#[tokio::test]
async fn test_dashboard_top_issue_uses_worst_observed_severity() {
    let db = setup_db().await;
    let older_scan = insert_scan(
        &db,
        "dashboard-severity.test",
        443,
        Utc::now() - Duration::days(2),
        Some("A"),
        Some(92),
    )
    .await;
    let newer_scan = insert_scan(
        &db,
        "dashboard-severity.test",
        443,
        Utc::now() - Duration::days(1),
        Some("A"),
        Some(94),
    )
    .await;

    insert_vulnerability(&db, older_scan, "LoadBalancerIssue", "medium").await;
    insert_vulnerability(&db, newer_scan, "LoadBalancerIssue", "critical").await;

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard-severity.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    assert_eq!(dashboard.top_issues.len(), 1);
    assert_eq!(dashboard.top_issues[0].title, "LoadBalancerIssue");
    assert_eq!(dashboard.top_issues[0].severity, "critical");
    assert_eq!(dashboard.summary.total_vulnerabilities, 2);
    assert_eq!(dashboard.summary.critical_vulnerabilities, 2);
}

#[tokio::test]
async fn test_dashboard_unknown_severity_bucket_is_rendered() {
    let db = setup_db().await;
    let scan = insert_scan(
        &db,
        "dashboard-unknown.test",
        443,
        Utc::now() - Duration::days(1),
        None,
        None,
    )
    .await;

    insert_vulnerability(&db, scan, "KnownIssue", "critical").await;
    insert_vulnerability(&db, scan, "WeirdIssue", "experimental").await;

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard-unknown.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    let labels: Vec<_> = dashboard
        .vulnerability_distribution
        .iter()
        .map(|point| point.label.as_str())
        .collect();
    assert_eq!(labels, vec!["critical", "unknown"]);

    let unknown_bucket = dashboard
        .vulnerability_distribution
        .iter()
        .find(|point| point.label == "unknown")
        .expect("unknown bucket should exist");
    assert_eq!(unknown_bucket.value, 1);

    let total_percentage: f64 = dashboard
        .vulnerability_distribution
        .iter()
        .map(|point| point.percentage)
        .sum();
    assert!((total_percentage - 100.0).abs() < 1e-9);
}

#[tokio::test]
async fn test_dashboard_cipher_strength_unknown_bucket_is_rendered() {
    let db = setup_db().await;
    let scan = insert_scan(
        &db,
        "dashboard-cipher-unknown.test",
        443,
        Utc::now() - Duration::days(1),
        None,
        None,
    )
    .await;

    insert_cipher(&db, scan, "TLS 1.2", "CIPHER_STRONG", "strong", true).await;
    insert_cipher(&db, scan, "TLS 1.2", "CIPHER_WEAK", "weak", false).await;
    insert_cipher(
        &db,
        scan,
        "TLS 1.2",
        "CIPHER_UNKNOWN",
        "experimental",
        false,
    )
    .await;

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard-cipher-unknown.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    let labels: Vec<_> = dashboard
        .cipher_strength
        .iter()
        .map(|point| point.label.as_str())
        .collect();
    assert_eq!(labels, vec!["strong", "weak", "unknown"]);

    assert!(
        dashboard
            .cipher_strength
            .iter()
            .any(|point| point.label == "unknown" && point.value == 1)
    );

    let total_percentage: f64 = dashboard
        .cipher_strength
        .iter()
        .map(|point| point.percentage)
        .sum();
    assert!((total_percentage - 100.0).abs() < 1e-9);
}

#[tokio::test]
async fn test_dashboard_counts_low_cipher_strength_as_weak() {
    let db = setup_db().await;
    let scan = insert_scan(
        &db,
        "dashboard-cipher-low.test",
        443,
        Utc::now() - Duration::days(1),
        None,
        None,
    )
    .await;

    insert_cipher(&db, scan, "TLS 1.2", "CIPHER_LOW", "low", false).await;

    let generator = DashboardGenerator::new(Arc::clone(&db));
    let dashboard = generator
        .generate_dashboard("dashboard-cipher-low.test", 443, 30)
        .await
        .expect("test assertion should succeed");

    assert!(
        dashboard
            .cipher_strength
            .iter()
            .any(|point| point.label == "weak" && point.value == 1)
    );
    assert!(
        !dashboard
            .cipher_strength
            .iter()
            .any(|point| point.label == "unknown")
    );
}

#[tokio::test]
async fn test_change_tracker_json_is_deterministic() {
    let db = setup_db().await;
    let now = Utc::now();

    let pair_a_old = insert_scan(
        &db,
        "changes-json.test",
        443,
        now - Duration::days(3),
        Some("A"),
        Some(90),
    )
    .await;
    let pair_a_new = insert_scan(
        &db,
        "changes-json.test",
        443,
        now - Duration::days(2),
        Some("B"),
        Some(80),
    )
    .await;

    insert_protocol(&db, pair_a_old, "TLS 1.2", true, true).await;
    insert_protocol(&db, pair_a_old, "TLS 1.0", true, false).await;
    insert_protocol(&db, pair_a_new, "TLS 1.3", true, true).await;
    insert_protocol(&db, pair_a_new, "TLS 1.1", true, false).await;

    insert_cipher(&db, pair_a_old, "TLS 1.2", "CIPHER_OLD_A", "strong", true).await;
    insert_cipher(&db, pair_a_old, "TLS 1.2", "CIPHER_OLD_B", "weak", true).await;
    insert_cipher(&db, pair_a_new, "TLS 1.3", "CIPHER_NEW_A", "strong", true).await;
    insert_cipher(&db, pair_a_new, "TLS 1.3", "CIPHER_NEW_B", "medium", true).await;

    insert_vulnerability(&db, pair_a_old, "Heartbleed", "critical").await;
    insert_vulnerability(&db, pair_a_old, "POODLE", "high").await;
    insert_vulnerability(&db, pair_a_new, "DROWN", "critical").await;
    insert_vulnerability(&db, pair_a_new, "BEAST", "medium").await;

    let pair_b_old = insert_scan(
        &db,
        "changes-json.test",
        444,
        now - Duration::days(3),
        Some("A"),
        Some(90),
    )
    .await;
    let pair_b_new = insert_scan(
        &db,
        "changes-json.test",
        444,
        now - Duration::days(2),
        Some("B"),
        Some(80),
    )
    .await;

    insert_protocol(&db, pair_b_old, "TLS 1.0", true, false).await;
    insert_protocol(&db, pair_b_old, "TLS 1.2", true, true).await;
    insert_protocol(&db, pair_b_new, "TLS 1.1", true, false).await;
    insert_protocol(&db, pair_b_new, "TLS 1.3", true, true).await;

    insert_cipher(&db, pair_b_old, "TLS 1.2", "CIPHER_OLD_B", "weak", true).await;
    insert_cipher(&db, pair_b_old, "TLS 1.2", "CIPHER_OLD_A", "strong", true).await;
    insert_cipher(&db, pair_b_new, "TLS 1.3", "CIPHER_NEW_B", "medium", true).await;
    insert_cipher(&db, pair_b_new, "TLS 1.3", "CIPHER_NEW_A", "strong", true).await;

    insert_vulnerability(&db, pair_b_old, "POODLE", "high").await;
    insert_vulnerability(&db, pair_b_old, "Heartbleed", "critical").await;
    insert_vulnerability(&db, pair_b_new, "BEAST", "medium").await;
    insert_vulnerability(&db, pair_b_new, "DROWN", "critical").await;

    let tracker = ChangeTracker::new(Arc::clone(&db));
    let changes_a = tracker
        .detect_changes_between(pair_a_old, pair_a_new)
        .await
        .expect("test assertion should succeed");
    let changes_b = tracker
        .detect_changes_between(pair_b_old, pair_b_new)
        .await
        .expect("test assertion should succeed");

    let json_a = serde_json::to_string(&changes_a).expect("serialization should succeed");
    let json_b = serde_json::to_string(&changes_b).expect("serialization should succeed");
    assert_eq!(json_a, json_b);
}

#[tokio::test]
async fn test_get_scan_history_breaks_timestamp_ties_by_scan_id() {
    let db = setup_db().await;
    let timestamp = Utc::now();

    let first = insert_scan(
        &db,
        "history-order.test",
        443,
        timestamp,
        Some("B"),
        Some(80),
    )
    .await;
    let second = insert_scan(
        &db,
        "history-order.test",
        443,
        timestamp,
        Some("A"),
        Some(95),
    )
    .await;

    let scans = db
        .get_scan_history("history-order.test", 443, 10)
        .await
        .expect("history should load");

    assert_eq!(scans.len(), 2);
    assert!(scans[0].scan_id > scans[1].scan_id);
    assert_eq!(scans[0].scan_id, Some(second));
    assert_eq!(scans[1].scan_id, Some(first));
    assert_eq!(scans[0].overall_grade.as_deref(), Some("A"));
}

#[tokio::test]
async fn test_get_scan_history_since_returns_all_rows_in_window() {
    let db = setup_db().await;

    for i in 0..101 {
        insert_scan(
            &db,
            "history-window.test",
            443,
            Utc::now() - Duration::minutes(i as i64),
            Some("A"),
            Some(100 - i),
        )
        .await;
    }

    let scans = db
        .get_scan_history_since("history-window.test", 443, Utc::now() - Duration::days(2))
        .await
        .expect("history should load");

    assert_eq!(scans.len(), 101);
    assert!(
        scans
            .windows(2)
            .all(|pair| pair[0].scan_timestamp <= pair[1].scan_timestamp)
    );
}
