// Health Check Route

use crate::api::{
    models::response::HealthResponse, presenters::health::present_health_response, state::AppState,
};
use axum::{Json, extract::State};
use std::sync::Arc;

/// Health check endpoint
///
/// Returns the health status of the API service
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let active_scans = state.active_scans().await;
    let queued_scans = state.queued_scans().await;

    // Check database health if configured
    let database_status = if let Some(db) = &state.db_pool {
        match check_database_health(db).await {
            Ok(_) => Some("connected".to_string()),
            Err(e) => Some(format!("error: {}", e)),
        }
    } else {
        Some("not_configured".to_string())
    };

    Json(present_health_response(
        env!("CARGO_PKG_VERSION").to_string(),
        state.uptime_seconds(),
        active_scans,
        queued_scans,
        database_status,
    ))
}

/// Check database health with a simple query
async fn check_database_health(db: &crate::db::connection::DatabasePool) -> crate::Result<()> {
    use crate::db::connection::DatabasePool;

    match db {
        DatabasePool::Postgres(pool) => {
            sqlx::query("SELECT 1").fetch_one(pool).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("Database health check failed: {}", e))
            })?;
            Ok(())
        }
        DatabasePool::Sqlite(pool) => {
            sqlx::query("SELECT 1").fetch_one(pool).await.map_err(|e| {
                crate::TlsError::DatabaseError(format!("Database health check failed: {}", e))
            })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::db::{DatabaseConfig, DatabasePool};
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_health_check_without_db() {
        let state = AppState::new(ApiConfig::default()).expect("state should build");
        let Json(response) = health_check(State(Arc::new(state))).await;

        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.database.as_deref(), Some("not_configured"));
        assert_eq!(response.active_scans, 0);
        assert_eq!(response.queued_scans, 0);
    }

    #[tokio::test]
    async fn test_health_check_with_sqlite_db() {
        let config = DatabaseConfig::sqlite(PathBuf::from(":memory:"));
        let pool = DatabasePool::new(&config).await.expect("db should build");

        let mut state = AppState::new(ApiConfig::default()).expect("state should build");
        state.db_pool = Some(Arc::new(pool));

        let Json(response) = health_check(State(Arc::new(state))).await;
        assert_eq!(response.database.as_deref(), Some("connected"));
    }
}
