use std::sync::Arc;

use axum::{routing::get, Router};
use tower::ServiceExt;

use cipherrun::api::config::ApiConfig;
use cipherrun::api::routes::history;
use cipherrun::api::state::AppState;
use cipherrun::db::{DatabaseConfig, DatabasePool, run_migrations};

async fn sqlite_state() -> Arc<AppState> {
    let config = ApiConfig::default();
    let mut state = AppState::new(config).unwrap();

    let db_config = DatabaseConfig::sqlite(":memory:".into());
    let pool = DatabasePool::new(&db_config).await.unwrap();
    run_migrations(&pool).await.unwrap();

    state.db_pool = Some(Arc::new(pool));
    Arc::new(state)
}

#[tokio::test]
async fn test_history_route_empty() {
    let state = sqlite_state().await;

    let app = Router::new()
        .route("/history/:domain", get(history::get_history))
        .with_state(state);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/history/example.com")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
