// Success-path tests for certificate routes using SQLite (no mocks).

mod common;

use axum::extract::{Path, Query, State};
use chrono::{Duration, Utc};
use cipherrun::api::config::ApiConfig;
use cipherrun::api::models::request::CertificateQuery;
use cipherrun::api::routes::certificates::{get_certificate, list_certificates};
use cipherrun::api::state::AppState;
use cipherrun::db::{DatabaseConfig, DatabasePool, run_migrations};
use std::sync::Arc;

async fn setup_state() -> Arc<AppState> {
    let config =
        DatabaseConfig::sqlite(common::sqlite::unique_sqlite_db_path("cipherrun-cert-test"));
    let pool = DatabasePool::new(&config)
        .await
        .expect("test assertion should succeed");
    run_migrations(&pool)
        .await
        .expect("test assertion should succeed");

    let mut state = AppState::new(ApiConfig::default()).expect("test assertion should succeed");
    state.db_pool = Some(Arc::new(pool));
    Arc::new(state)
}

async fn insert_scan_and_cert(
    pool: &DatabasePool,
    hostname: &str,
    fingerprint: &str,
    subject: &str,
    not_after: chrono::DateTime<Utc>,
) -> i64 {
    let now = Utc::now();
    let scan_id = match pool {
        DatabasePool::Sqlite(sqlite) => {
            let result = sqlx::query(
                r#"
                INSERT INTO scans (target_hostname, target_port, scan_timestamp)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(hostname)
            .bind(443_i32)
            .bind(now)
            .execute(sqlite)
            .await
            .expect("test assertion should succeed");
            result.last_insert_rowid()
        }
        _ => panic!("expected sqlite"),
    };

    let cert_id = match pool {
        DatabasePool::Sqlite(sqlite) => {
            let result = sqlx::query(
                r#"
                INSERT INTO certificates (fingerprint_sha256, subject, issuer, not_before, not_after, san_domains, is_ca)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                "#,
            )
            .bind(fingerprint)
            .bind(subject)
            .bind("CN=Test CA")
            .bind(now - Duration::days(30))
            .bind(not_after)
            .bind(r#"["example.com","www.example.com"]"#)
            .execute(sqlite)
            .await
            .expect("test assertion should succeed");
            result.last_insert_rowid()
        }
        _ => panic!("expected sqlite"),
    };

    if let DatabasePool::Sqlite(sqlite) = pool {
        sqlx::query(
            r#"
            INSERT INTO scan_certificates (scan_id, cert_id, chain_position)
            VALUES (?, ?, 0)
            "#,
        )
        .bind(scan_id)
        .bind(cert_id)
        .execute(sqlite)
        .await
        .expect("test assertion should succeed");
    }

    scan_id
}

#[tokio::test]
async fn test_list_certificates_basic_and_filters() {
    let state = setup_state().await;
    let pool = state.db_pool.as_ref().unwrap().clone();

    let soon = Utc::now() + Duration::days(5);
    let later = Utc::now() + Duration::days(90);

    insert_scan_and_cert(&pool, "example.com", "fp1", "CN=example.com", soon).await;
    insert_scan_and_cert(&pool, "example.org", "fp2", "example.org", later).await;

    // Default query (no filters) should return both.
    let query = CertificateQuery::default();
    let response = list_certificates(State(state.clone()), Query(query))
        .await
        .expect("test assertion should succeed");
    assert_eq!(response.0.total, 2);

    // Filter by hostname should return one.
    let query = CertificateQuery {
        hostname: Some("example.com".to_string()),
        ..CertificateQuery::default()
    };
    let response = list_certificates(State(state.clone()), Query(query))
        .await
        .expect("test assertion should succeed");
    assert_eq!(response.0.total, 1);
    assert_eq!(response.0.certificates[0].common_name, "example.com");

    // Filter by expiring within days should return the soon expiring cert.
    let query = CertificateQuery {
        expiring_within_days: Some(10),
        ..CertificateQuery::default()
    };
    let response = list_certificates(State(state.clone()), Query(query))
        .await
        .expect("test assertion should succeed");
    assert_eq!(response.0.total, 1);
    assert_eq!(response.0.certificates[0].fingerprint, "fp1");

    // Combined filters, ordering, and pagination should remain stable.
    let query = CertificateQuery {
        hostname: Some("example.com".to_string()),
        expiring_within_days: Some(10),
        sort: "expiry_desc".to_string(),
        limit: 1,
        offset: 0,
    };
    let response = list_certificates(State(state.clone()), Query(query))
        .await
        .expect("test assertion should succeed");
    assert_eq!(response.0.total, 1);
    assert_eq!(response.0.offset, 0);
    assert_eq!(response.0.limit, 1);
    assert_eq!(response.0.certificates.len(), 1);
    assert_eq!(response.0.certificates[0].fingerprint, "fp1");
}

#[tokio::test]
async fn test_get_certificate_success_and_not_found() {
    let state = setup_state().await;
    let pool = state.db_pool.as_ref().unwrap().clone();

    let soon = Utc::now() + Duration::days(20);
    insert_scan_and_cert(&pool, "example.com", "fp-ok", "CN=example.com", soon).await;

    let response = get_certificate(State(state.clone()), Path("fp-ok".to_string()))
        .await
        .expect("test assertion should succeed");
    assert_eq!(response.0.fingerprint, "fp-ok");
    assert_eq!(response.0.common_name, "example.com");

    let err = get_certificate(State(state.clone()), Path("missing".to_string()))
        .await
        .expect_err("test assertion should fail");
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn test_list_certificates_rejects_hostname_filter_with_port() {
    let state = setup_state().await;

    let err = list_certificates(
        State(state),
        Query(CertificateQuery {
            hostname: Some("example.com:443".to_string()),
            ..CertificateQuery::default()
        }),
    )
    .await
    .expect_err("hostname filter with port should fail");

    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_list_certificates_rejects_invalid_hostname_filter() {
    let state = setup_state().await;

    let err = list_certificates(
        State(state),
        Query(CertificateQuery {
            hostname: Some("example..com".to_string()),
            ..CertificateQuery::default()
        }),
    )
    .await
    .expect_err("invalid hostname filter should fail");

    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}
