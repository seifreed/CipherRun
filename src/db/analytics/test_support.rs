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
