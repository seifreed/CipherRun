use std::sync::Arc;

use axum::{Router, routing::get};
use serde_json::Value;

use cipherrun::api::routes::history;
use cipherrun::api::state::AppState;
use cipherrun::db::{DatabaseConfig, DatabasePool, run_migrations};

mod common;

async fn sqlite_state() -> Arc<AppState> {
    let mut state = common::api::test_api_state_owned();

    let db_config = DatabaseConfig::sqlite(":memory:".into());
    let pool = DatabasePool::new(&db_config).await.unwrap();
    run_migrations(&pool).await.unwrap();

    state.db_pool = Some(Arc::new(pool));
    Arc::new(state)
}

async fn insert_history_scan(
    state: &Arc<AppState>,
    hostname: &str,
    port: u16,
    offset_minutes: i64,
    grade: &str,
) {
    let pool = state.db_pool.as_ref().unwrap().clone();

    if let DatabasePool::Sqlite(sqlite) = pool.as_ref() {
        sqlx::query(
            r#"
            INSERT INTO scans (
                target_hostname, target_port, scan_timestamp, overall_grade, overall_score, scan_duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(hostname)
        .bind(port as i32)
        .bind(chrono::Utc::now() + chrono::Duration::minutes(offset_minutes))
        .bind(grade)
        .bind(95_i32)
        .bind(1200_i64)
        .execute(sqlite)
        .await
        .unwrap();
    } else {
        panic!("expected sqlite pool");
    }
}

#[tokio::test]
async fn test_history_route_returns_not_found_when_no_history_exists() {
    let state = sqlite_state().await;

    let app = Router::new()
        .route("/history/{domain}", get(history::get_history))
        .with_state(state);

    assert_eq!(
        common::api::send_status(&app, common::api::request("GET", "/history/example.com")).await,
        axum::http::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_history_route_returns_inserted_scan() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
}

#[tokio::test]
async fn test_history_route_filters_by_port() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;
    insert_history_scan(&state, "example.com", 8443, 0, "B").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 10,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_applies_limit_and_desc_order() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -10, "C").await;
    insert_history_scan(&state, "example.com", 443, -5, "B").await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
    assert_eq!(json["scans"][1]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_returns_not_found_for_unknown_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("missing.example".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .expect_err("unknown domain should return not found");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_history_route_applies_limit_with_matching_port_only() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -15, "C").await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
}

#[tokio::test]
async fn test_history_route_unknown_domain_returns_not_found_even_with_other_matching_port() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("missing.example".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 1,
        }),
    )
    .await
    .expect_err("unknown domain should return not found");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_preserves_desc_order_for_same_port() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -20, "D").await;
    insert_history_scan(&state, "example.com", 8443, -10, "C").await;
    insert_history_scan(&state, "example.com", 8443, -5, "B").await;
    insert_history_scan(&state, "example.com", 8443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 3,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(3));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
    assert_eq!(json["scans"][1]["grade"], Value::from("B"));
    assert_eq!(json["scans"][2]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_one_returns_latest_scan_for_port() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -30, "D").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
}

#[tokio::test]
async fn test_history_route_ignores_other_ports_when_limit_is_high() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("A"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_zero_limit_returns_bad_request_even_with_matching_domain_and_port() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -5, "B").await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 0,
        }),
    )
    .await
    .expect_err("zero limit should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_zero_limit_returns_bad_request_for_unknown_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("missing.example".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 0,
        }),
    )
    .await
    .expect_err("zero limit should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_returns_not_found_for_known_domain_when_port_does_not_match() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 10,
        }),
    )
    .await
    .expect_err("missing port history should return not found");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_history_route_returns_only_matching_port_when_other_port_has_newer_data() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_ignores_newer_matching_port_results_from_other_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "other.example", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_limit_one_still_ignores_other_domain_newer_scan() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -5, "B").await;
    insert_history_scan(&state, "other.example", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_limit_zero_returns_bad_request_even_with_other_domain_and_port_matches()
{
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -5, "B").await;
    insert_history_scan(&state, "other.example", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 0,
        }),
    )
    .await
    .expect_err("zero limit should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_one_returns_same_domain_requested_port_only() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -15, "C").await;
    insert_history_scan(&state, "example.com", 8443, -5, "B").await;
    insert_history_scan(&state, "other.example", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_two_ignores_other_domain_even_when_newer() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "other.example", 443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_two_ignores_newer_other_port_from_same_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, 0, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_one_ignores_newer_other_domain_and_other_port_together() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -5, "A").await;
    insert_history_scan(&state, "other.example", 443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_rejects_domain_with_embedded_port() {
    let state = sqlite_state().await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com:443".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .expect_err("embedded port in domain path should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_rejects_invalid_hostname() {
    let state = sqlite_state().await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example..com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 10,
        }),
    )
    .await
    .expect_err("invalid hostname should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_two_ignores_other_domain_and_other_port_even_when_both_newer() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -30, "D").await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -5, "A").await;
    insert_history_scan(&state, "other.example", 443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_two_for_non_default_port_ignores_newer_other_port_and_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -30, "C").await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;
    insert_history_scan(&state, "other.example", 8443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_one_for_non_default_port_ignores_newer_other_port_and_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -20, "C").await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;
    insert_history_scan(&state, "other.example", 8443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_unknown_domain_non_default_port_returns_not_found_with_newer_matching_noise()
 {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;
    insert_history_scan(&state, "other.example", 8443, 0, "A+").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("missing.example".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 2,
        }),
    )
    .await
    .expect_err("unknown domain should return not found");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_zero_for_non_default_port_returns_bad_request() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -10, "B").await;
    insert_history_scan(&state, "example.com", 443, -5, "A").await;
    insert_history_scan(&state, "other.example", 8443, 0, "A+").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 8443,
            limit: 0,
        }),
    )
    .await
    .expect_err("zero limit should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_one_for_default_port_ignores_newer_non_default_port_and_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -5, "A").await;
    insert_history_scan(&state, "other.example", 443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_limit_two_for_default_port_ignores_newer_non_default_port_and_domain() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -30, "D").await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -5, "A").await;
    insert_history_scan(&state, "other.example", 443, 0, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_zero_for_default_port_returns_bad_request() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -5, "A").await;
    insert_history_scan(&state, "other.example", 443, 0, "A+").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 0,
        }),
    )
    .await
    .expect_err("zero limit should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_port_zero_returns_bad_request() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, 0, "A").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery { port: 0, limit: 10 }),
    )
    .await
    .expect_err("port zero should fail");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::BadRequest(_)
    ));
}

#[tokio::test]
async fn test_history_route_unknown_default_port_returns_not_found_with_same_domain_other_port_noise()
 {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 8443, -2, "A").await;
    insert_history_scan(&state, "other.example", 443, -1, "A+").await;

    let err = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("missing.example".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .expect_err("unknown domain should return not found");
    assert!(matches!(
        err,
        cipherrun::api::models::error::ApiError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_history_route_limit_two_for_default_port_ignores_same_domain_newer_non_default_only()
{
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -1, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_one_for_default_port_ignores_same_domain_newer_non_default_only()
{
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "example.com", 8443, -1, "A").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}

#[tokio::test]
async fn test_history_route_limit_two_for_default_port_ignores_only_other_domain_noise() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "other.example", 443, -1, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 2,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(2));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
    assert_eq!(json["scans"][1]["grade"], Value::from("C"));
}

#[tokio::test]
async fn test_history_route_limit_one_for_default_port_ignores_only_other_domain_noise() {
    let state = sqlite_state().await;
    insert_history_scan(&state, "example.com", 443, -20, "C").await;
    insert_history_scan(&state, "example.com", 443, -10, "B").await;
    insert_history_scan(&state, "other.example", 443, -1, "A+").await;

    let response = history::get_history(
        axum::extract::State(state),
        axum::extract::Path("example.com".to_string()),
        axum::extract::Query(history::HistoryQuery {
            port: 443,
            limit: 1,
        }),
    )
    .await
    .unwrap();

    let json = serde_json::to_value(response.0).unwrap();
    assert_eq!(json["total_scans"], Value::from(1));
    assert_eq!(json["scans"][0]["grade"], Value::from("B"));
}
