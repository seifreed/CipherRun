// Compliance Routes

use crate::api::{
    models::error::{ApiError, ApiErrorResponse},
    state::AppState,
};
use crate::compliance::{
    engine::ComplianceEngine,
    loader::FrameworkLoader,
    ComplianceStatus,
};
use crate::scanner::Scanner;
use axum::{
    extract::{Path, Query, State},
    Json,
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

    // Load compliance framework
    let framework = FrameworkLoader::load_builtin(&framework_id)
        .map_err(|e| {
            if e.to_string().contains("Unknown framework") {
                ApiError::NotFound(format!("Unknown compliance framework: {}", framework_id))
            } else {
                ApiError::Internal(format!("Failed to load framework: {}", e))
            }
        })?;

    // Parse target (hostname:port)
    let parts: Vec<&str> = target.split(':').collect();
    let hostname = parts.first().ok_or_else(|| {
        ApiError::BadRequest("Invalid target format. Expected hostname:port".to_string())
    })?;
    let port = parts
        .get(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    // Perform TLS scan - Create Args struct for Scanner
    let args = crate::Args {
        target: Some(format!("{}:{}", hostname, port)),
        port: Some(port),
        ..Default::default()
    };

    let mut scanner = Scanner::new(args)
        .map_err(|e| ApiError::Internal(format!("Failed to create scanner: {}", e)))?;

    let scan_results = scanner
        .run()
        .await
        .map_err(|e| ApiError::Internal(format!("Scan failed: {}", e)))?;

    // Create compliance engine and evaluate
    let engine = ComplianceEngine::new(framework.clone());
    let report = engine
        .evaluate(&scan_results)
        .map_err(|e| ApiError::Internal(format!("Compliance evaluation failed: {}", e)))?;

    // Convert report to response
    let status = match report.overall_status {
        ComplianceStatus::Pass => "pass",
        ComplianceStatus::Fail => "fail",
        ComplianceStatus::Warning => "warning",
    };

    let summary = ComplianceSummary {
        total: report.summary.total,
        passed: report.summary.passed,
        failed: report.summary.failed,
        warnings: report.summary.warnings,
        compliance_percentage: if report.summary.total > 0 {
            (report.summary.passed as f64 / report.summary.total as f64) * 100.0
        } else {
            0.0
        },
    };

    // Build requirement results if detailed flag is set
    let requirements = if query.detailed {
        Some(
            report
                .requirements
                .iter()
                .map(|req| {
                    let status_str = match req.status {
                        crate::compliance::RequirementStatus::Pass => "pass",
                        crate::compliance::RequirementStatus::Fail => "fail",
                        crate::compliance::RequirementStatus::Warning => "warning",
                        crate::compliance::RequirementStatus::NotApplicable => "not_applicable",
                    };

                    let severity_str = match req.severity {
                        crate::compliance::Severity::Critical => "critical",
                        crate::compliance::Severity::High => "high",
                        crate::compliance::Severity::Medium => "medium",
                        crate::compliance::Severity::Low => "low",
                        crate::compliance::Severity::Info => "info",
                    };

                    let violations = if !req.violations.is_empty() {
                        Some(
                            req.violations
                                .iter()
                                .map(|v| ViolationDetail {
                                    rule_type: v.violation_type.clone(),
                                    message: v.description.clone(),
                                    evidence: Some(v.evidence.clone()),
                                })
                                .collect(),
                        )
                    } else {
                        None
                    };

                    RequirementResult {
                        id: req.requirement_id.clone(),
                        name: req.name.clone(),
                        category: req.category.clone(),
                        status: status_str.to_string(),
                        severity: severity_str.to_string(),
                        violation_count: req.violations.len(),
                        violations,
                        remediation: Some(req.remediation.clone()),
                    }
                })
                .collect(),
        )
    } else {
        None
    };

    Ok(Json(ComplianceCheckResponse {
        framework_id: framework.id,
        framework_name: framework.name,
        framework_version: framework.version,
        target: target.clone(),
        status: status.to_string(),
        summary,
        requirements,
        evaluated_at: report.scan_timestamp.to_rfc3339(),
    }))
}
