// Compliance Routes

use crate::api::{
    models::error::{ApiError, ApiErrorResponse},
    state::AppState,
};
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;

/// Check compliance
///
/// Runs a compliance check against a specific framework
#[utoipa::path(
    get,
    path = "/api/v1/compliance/{framework}",
    tag = "compliance",
    params(
        ("framework" = String, Path, description = "Compliance framework (pci-dss-v4, nist-sp800-52r2, etc.)")
    ),
    responses(
        (status = 200, description = "Compliance report"),
        (status = 400, description = "Invalid framework", body = ApiErrorResponse),
        (status = 404, description = "Framework not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn check_compliance(
    State(state): State<Arc<AppState>>,
    Path(framework): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // TODO: Implement compliance checking
    // This would integrate with the compliance module once it's implemented

    match framework.as_str() {
        "pci-dss-v4" | "nist-sp800-52r2" | "fedramp" | "hipaa" => {
            Ok(Json(serde_json::json!({
                "framework": framework,
                "status": "not_implemented",
                "message": "Compliance checking will be implemented with the compliance module"
            })))
        }
        _ => Err(ApiError::NotFound(format!(
            "Unknown compliance framework: {}",
            framework
        ))),
    }
}
