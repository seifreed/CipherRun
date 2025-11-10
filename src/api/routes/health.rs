// Health Check Route

use crate::api::{models::response::HealthResponse, state::AppState};
use axum::{extract::State, Json};
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

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime_seconds(),
        active_scans,
        queued_scans,
        database: database_status,
    })
}

/// Check database health with a simple query
async fn check_database_health(db: &crate::db::connection::DatabasePool) -> crate::Result<()> {
    use crate::db::connection::DatabasePool;

    match db {
        DatabasePool::Postgres(pool) => {
            sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Database health check failed: {}", e)))?;
            Ok(())
        }
        DatabasePool::Sqlite(pool) => {
            sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .map_err(|e| crate::TlsError::DatabaseError(format!("Database health check failed: {}", e)))?;
            Ok(())
        }
    }
}
