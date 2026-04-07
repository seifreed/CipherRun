// Compliance Routes

use crate::api::{
    adapters::compliance as compliance_adapter,
    models::error::{ApiError, ApiErrorResponse},
    presenters::compliance::present_compliance_report,
    state::AppState,
};
use crate::compliance::BuiltinFrameworkSource;
use crate::scanner::DefaultScannerPort;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

/// Compliance check query parameters
#[derive(Debug, Deserialize, utoipa::IntoParams, ToSchema)]
pub struct ComplianceQuery {
    /// Target to check (hostname:port)
    #[serde(default)]
    pub target: Option<String>,

    /// Output format (json, terminal, csv)
    #[serde(default = "default_format")]
    pub format: String,

    /// Include detailed requirement information
    #[serde(default)]
    pub detailed: bool,
}

fn default_format() -> String {
    "json".to_string()
}

/// Compliance check response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComplianceCheckResponse {
    /// Framework ID
    pub framework_id: String,

    /// Framework name
    pub framework_name: String,

    /// Framework version
    pub framework_version: String,

    /// Target evaluated
    pub target: String,

    /// Overall compliance status
    pub status: String,

    /// Compliance summary
    pub summary: ComplianceSummary,

    /// Detailed requirement results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Vec<RequirementResult>>,

    /// Evaluation timestamp
    pub evaluated_at: String,
}

/// Compliance summary
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComplianceSummary {
    /// Total requirements
    pub total: usize,

    /// Passed requirements
    pub passed: usize,

    /// Failed requirements
    pub failed: usize,

    /// Warnings
    pub warnings: usize,

    /// Compliance percentage
    pub compliance_percentage: f64,
}

/// Individual requirement result
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RequirementResult {
    /// Requirement ID
    pub id: String,

    /// Requirement name
    pub name: String,

    /// Category
    pub category: String,

    /// Status (pass, fail, warning)
    pub status: String,

    /// Severity
    pub severity: String,

    /// Number of violations
    pub violation_count: usize,

    /// Violation details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<ViolationDetail>>,

    /// Remediation guidance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Violation detail
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ViolationDetail {
    /// Rule type that was violated
    pub rule_type: String,

    /// Violation message
    pub message: String,

    /// Evidence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Check compliance
///
/// Runs a compliance check against a specific framework
#[utoipa::path(
    get,
    path = "/api/v1/compliance/{framework}",
    tag = "compliance",
    params(
        ("framework" = String, Path, description = "Compliance framework (pci-dss-v4, nist-sp800-52r2, etc.)"),
        ComplianceQuery
    ),
    responses(
        (status = 200, description = "Compliance report", body = ComplianceCheckResponse),
        (status = 400, description = "Invalid framework or target", body = ApiErrorResponse),
        (status = 404, description = "Framework not found", body = ApiErrorResponse)
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn check_compliance(
    State(_state): State<Arc<AppState>>,
    Path(framework_id): Path<String>,
    Query(query): Query<ComplianceQuery>,
) -> Result<Json<ComplianceCheckResponse>, ApiError> {
    // Validate target is provided
    let target = query
        .target
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Target parameter is required".to_string()))?;

    // Load compliance framework via adapter
    let framework = compliance_adapter::load_framework(&BuiltinFrameworkSource, &framework_id)?;

    // Run scan and evaluate compliance via adapter
    let scanner = DefaultScannerPort;
    let evaluator = crate::compliance::engine::DefaultComplianceEvaluator;
    let (_assessment, report) =
        compliance_adapter::run_compliance_check(&scanner, &evaluator, &framework, target).await?;

    Ok(Json(present_compliance_report(
        &framework,
        target,
        &report,
        query.detailed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{InMemoryJobQueue, ScanExecutor};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::state::{ApiStats, AppState};
    use axum::extract::{Path, Query, State};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;

    fn build_state() -> Arc<AppState> {
        let config = Arc::new(ApiConfig::default());
        let job_queue = Arc::new(InMemoryJobQueue::new(10));
        let executor = Arc::new(ScanExecutor::new(job_queue.clone(), 1));
        let progress_tx = executor.progress_broadcaster();

        Arc::new(AppState {
            config,
            job_queue,
            executor,
            progress_tx,
            start_time: Instant::now(),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            rate_limiter: Arc::new(PerKeyRateLimiter::new(100)),
            db_pool: None,
            policy_dir: None,
        })
    }

    #[tokio::test]
    async fn test_check_compliance_missing_target() {
        let state = build_state();
        let query = ComplianceQuery {
            target: None,
            format: "json".to_string(),
            detailed: false,
        };

        let err = check_compliance(State(state), Path("pci-dss-v4".to_string()), Query(query))
            .await
            .expect_err("missing target should error");

        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_check_compliance_unknown_framework() {
        let state = build_state();
        let query = ComplianceQuery {
            target: Some("example.com:443".to_string()),
            format: "json".to_string(),
            detailed: false,
        };

        let err = check_compliance(
            State(state),
            Path("unknown-framework".to_string()),
            Query(query),
        )
        .await
        .expect_err("unknown framework should error");

        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[test]
    fn test_default_format_is_json() {
        assert_eq!(default_format(), "json");
    }

    #[test]
    fn test_compliance_query_defaults() {
        let query: ComplianceQuery =
            serde_json::from_str("{}").expect("test assertion should succeed");
        assert!(query.target.is_none());
        assert_eq!(query.format, "json");
        assert!(!query.detailed);
    }
}
