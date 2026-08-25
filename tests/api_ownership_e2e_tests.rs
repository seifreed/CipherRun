//! HTTP-level tenant ownership checks against the production router.

mod common;

use axum::Router;
use chrono::{Duration, Utc};
use cipherrun::api::ApiServer;
use cipherrun::api::config::{ApiConfig, ApiCredential, Permission};
use cipherrun::db::{DatabasePool, run_migrations};
use serde_json::Value;
use std::sync::Arc;

fn tenant_config() -> ApiConfig {
    let mut config = ApiConfig::default();
    config.api_keys.clear();
    config.credentials = vec![
        ApiCredential::from_secret(
            "admin-key".to_string(),
            "admin-secret",
            "admin-principal".to_string(),
            None,
            Permission::Admin,
        ),
        ApiCredential::from_secret(
            "tenant-a-key".to_string(),
            "tenant-a-secret",
            "shared-principal".to_string(),
            Some("tenant-a".to_string()),
            Permission::User,
        ),
        ApiCredential::from_secret(
            "tenant-b-key".to_string(),
            "tenant-b-secret",
            "shared-principal".to_string(),
            Some("tenant-b".to_string()),
            Permission::User,
        ),
    ];
    config.rate_limit_per_minute = 1000;
    config
}

async fn insert_owned_scan_and_certificate(
    pool: &DatabasePool,
    tenant: &str,
    grade: &str,
    fingerprint: &str,
) {
    let now = Utc::now();
    let scan_id = match pool {
        DatabasePool::Sqlite(sqlite) => sqlx::query(
            "INSERT INTO scans (target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms, principal_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind("shared.example")
        .bind(443_i32)
        .bind(now)
        .bind(grade)
        .bind(90_i32)
        .bind(100_i64)
        .bind("shared-principal")
        .bind(tenant)
        .execute(sqlite)
        .await
        .expect("owned scan should insert")
        .last_insert_rowid(),
        DatabasePool::Postgres(_) => panic!("test uses SQLite"),
    };

    let cert_id = match pool {
        DatabasePool::Sqlite(sqlite) => sqlx::query(
            "INSERT INTO certificates (fingerprint_sha256, subject, issuer, not_before, not_after, san_domains, is_ca) VALUES (?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(fingerprint)
        .bind("CN=shared.example")
        .bind("CN=Test CA")
        .bind(now - Duration::days(1))
        .bind(now + Duration::days(30))
        .bind(r#"["shared.example"]"#)
        .execute(sqlite)
        .await
        .expect("owned certificate should insert")
        .last_insert_rowid(),
        DatabasePool::Postgres(_) => panic!("test uses SQLite"),
    };

    if let DatabasePool::Sqlite(sqlite) = pool {
        sqlx::query(
            "INSERT INTO scan_certificates (scan_id, cert_id, chain_position) VALUES (?, ?, 0)",
        )
        .bind(scan_id)
        .bind(cert_id)
        .execute(sqlite)
        .await
        .expect("scan certificate link should insert");
    }
}

async fn setup() -> (Router, Arc<cipherrun::api::state::AppState>) {
    let config = common::sqlite::unique_sqlite_config("cipherrun-ownership-e2e");
    let pool = DatabasePool::new(&config)
        .await
        .expect("SQLite pool should open");
    run_migrations(&pool)
        .await
        .expect("SQLite migrations should run");

    let server = ApiServer::with_db_pool(tenant_config(), Some(Arc::new(pool)))
        .expect("production API server should build");
    let state = server.state();
    insert_owned_scan_and_certificate(
        state.db_pool.as_ref().expect("database should be attached"),
        "tenant-a",
        "A",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .await;
    insert_owned_scan_and_certificate(
        state.db_pool.as_ref().expect("database should be attached"),
        "tenant-b",
        "B",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .await;

    {
        let mut stats = state.stats.write().await;
        stats.increment_scans_for_owner("shared-principal", Some("tenant-a"));
        stats.increment_scans_for_owner("shared-principal", Some("tenant-b"));
    }

    (
        server.router().expect("production router should build"),
        state,
    )
}

fn total(body: &Value) -> usize {
    body["total"]
        .as_u64()
        .expect("response should include total") as usize
}

#[tokio::test]
async fn production_http_routes_preserve_tenant_ownership() {
    let (app, _state) = setup().await;

    let (status, tenant_a_certificates) =
        common::api::send_get_json(&app, "/api/v1/certificates", Some("tenant-a-secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(total(&tenant_a_certificates), 1);
    assert_eq!(
        tenant_a_certificates["certificates"][0]["fingerprint"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let (status, tenant_b_certificates) =
        common::api::send_get_json(&app, "/api/v1/certificates", Some("tenant-b-secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(total(&tenant_b_certificates), 1);
    assert_eq!(
        tenant_b_certificates["certificates"][0]["fingerprint"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );

    let (status, _) = common::api::send_get_json(
        &app,
        "/api/v1/certificates/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Some("tenant-b-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    let (status, tenant_a_history) = common::api::send_get_json(
        &app,
        "/api/v1/history/shared.example?port=443&limit=10",
        Some("tenant-a-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(tenant_a_history["total_scans"], 1);
    assert_eq!(tenant_a_history["scans"][0]["grade"], "A");

    let (status, tenant_b_history) = common::api::send_get_json(
        &app,
        "/api/v1/history/shared.example?port=443&limit=10",
        Some("tenant-b-secret"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(tenant_b_history["total_scans"], 1);
    assert_eq!(tenant_b_history["scans"][0]["grade"], "B");

    let (status, tenant_a_stats) =
        common::api::send_get_json(&app, "/api/v1/stats", Some("tenant-a-secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(tenant_a_stats["total_scans"], 1);

    let (status, tenant_b_stats) =
        common::api::send_get_json(&app, "/api/v1/stats", Some("tenant-b-secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(tenant_b_stats["total_scans"], 1);

    let (status, admin_certificates) =
        common::api::send_get_json(&app, "/api/v1/certificates", Some("admin-secret")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(total(&admin_certificates), 2);
}
