use crate::db::{BindValue, CipherRunDatabase, DatabaseConfig, create_unique_test_db_path};
use chrono::{DateTime, Utc};
use std::sync::Arc;

pub(crate) async fn setup_db(prefix: &str) -> Arc<CipherRunDatabase> {
    let config = DatabaseConfig::sqlite(create_unique_test_db_path(prefix));
    let db = CipherRunDatabase::new(&config)
        .await
        .expect("test assertion should succeed");
    Arc::new(db)
}

pub(crate) async fn insert_scan(
    db: &CipherRunDatabase,
    hostname: &str,
    port: u16,
    timestamp: DateTime<Utc>,
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

pub(crate) async fn insert_protocol(
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

pub(crate) async fn insert_cipher(
    db: &CipherRunDatabase,
    scan_id: i64,
    protocol: &str,
    cipher_name: &str,
    strength: &str,
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
        BindValue::Bool(true),
        BindValue::String(strength.to_string()),
    ];
    db.pool()
        .execute(&query, bindings)
        .await
        .expect("test assertion should succeed");
}

pub(crate) async fn insert_vulnerability(
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
