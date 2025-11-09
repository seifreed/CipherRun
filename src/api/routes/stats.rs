// Statistics Routes

use crate::api::{
    models::response::{ApiUsageStats, DomainStats, StatsResponse},
    state::AppState,
};
use axum::{extract::State, Json};
use chrono::Utc;
use std::sync::Arc;

/// Get API statistics
///
/// Returns overall API usage and scan statistics
#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "stats",
    responses(
        (status = 200, description = "API statistics", body = StatsResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = state.get_stats().await;

    // Calculate average scan duration
    let avg_scan_duration_seconds = stats.avg_scan_duration() / 1000.0;

    // TODO: Get top domains from database
    let top_domains = vec![
        // Placeholder - would come from database in production
    ];

    // Calculate API usage stats
    let requests_last_hour = stats.requests_in_last_hour();

    let api_usage = ApiUsageStats {
        requests_last_hour,
        requests_last_day: stats.total_requests, // Simplified
        avg_response_time_ms: 0.0, // TODO: Track response times
    };

    Json(StatsResponse {
        total_scans: stats.total_scans,
        completed_scans: stats.completed_scans,
        failed_scans: stats.failed_scans,
        avg_scan_duration_seconds,
        scans_last_24h: stats.total_scans, // Simplified
        scans_last_7d: stats.total_scans,  // Simplified
        top_domains,
        api_usage,
    })
}
