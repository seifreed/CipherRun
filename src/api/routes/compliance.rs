// Compliance Routes

use crate::api::{
    adapters::compliance as compliance_adapter,
    models::error::{ApiError, ApiErrorResponse},
    presenters::compliance::present_compliance_report,
    state::AppState,
};
use crate::compliance::{BuiltinFrameworkSource, ComplianceFramework, ComplianceReport, Reporter};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComplianceResponseFormat {
    Json,
    Terminal,
    Csv,
}

impl ComplianceResponseFormat {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "terminal" => Ok(Self::Terminal),
            "csv" => Ok(Self::Csv),
            other => Err(ApiError::BadRequest(format!(
                "Unsupported compliance format '{}'. Supported formats: json, terminal, csv",
                other
            ))),
        }
    }

    fn render(
        self,
        framework: &ComplianceFramework,
        report: &ComplianceReport,
        detailed: bool,
    ) -> Result<Response, ApiError> {
        match self {
            Self::Json => {
                Ok(Json(present_compliance_report(framework, report, detailed)).into_response())
            }
            Self::Terminal => Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                Reporter::to_terminal(report),
            )
                .into_response()),
            Self::Csv => Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
                Reporter::to_csv(report)
                    .map_err(|e| ApiError::Internal(format!("Failed to render CSV: {}", e)))?,
            )
                .into_response()),
        }
    }
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
        (status = 200, description = "Compliance report", content(
            (ComplianceCheckResponse = "application/json"),
            (String = "text/plain"),
            (String = "text/csv")
        )),
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
) -> Result<Response, ApiError> {
    // Validate target is provided
    let target = query
        .target
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Target parameter is required".to_string()))?;
    let format = ComplianceResponseFormat::parse(&query.format)?;

    // Load compliance framework via adapter
    let framework = compliance_adapter::load_framework(&BuiltinFrameworkSource, &framework_id)?;

    // Run scan and evaluate compliance via adapter
    let (_assessment, report) =
        compliance_adapter::run_compliance_check_with_defaults(&framework, target).await?;

    format.render(&framework, &report, query.detailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::ApiConfig;
    use crate::api::jobs::{InMemoryJobQueue, ScanExecutor};
    use crate::api::middleware::rate_limit::PerKeyRateLimiter;
    use crate::api::state::{ApiStats, AppState};
    use crate::compliance::{
        ComplianceFramework, ComplianceReport, RequirementResult as ComplianceRequirementResult,
        RequirementStatus, Severity, Violation,
    };
    use axum::body::to_bytes;
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

    fn test_framework() -> ComplianceFramework {
        ComplianceFramework {
            id: "pci-dss-v4".to_string(),
            name: "PCI DSS".to_string(),
            version: "4.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        }
    }

    fn test_report() -> ComplianceReport {
        let framework = test_framework();
        let mut report = ComplianceReport::new(&framework, "example.com:443".to_string());
        report.add_requirement_result(ComplianceRequirementResult {
            requirement_id: "REQ-1".to_string(),
            name: "Strong TLS".to_string(),
            description: String::new(),
            category: "protocols".to_string(),
            severity: Severity::High,
            status: RequirementStatus::Fail,
            violations: vec![Violation {
                violation_type: "protocol".to_string(),
                description: "TLS 1.0 enabled".to_string(),
                evidence: "tls1.0".to_string(),
                severity: Severity::High,
            }],
            remediation: "Disable TLS 1.0".to_string(),
        });
        report.finalize();
        report
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

    #[tokio::test]
    async fn test_check_compliance_invalid_format() {
        let state = build_state();
        let query = ComplianceQuery {
            target: Some("example.com:443".to_string()),
            format: "yaml".to_string(),
            detailed: false,
        };

        let err = check_compliance(State(state), Path("pci-dss-v4".to_string()), Query(query))
            .await
            .expect_err("invalid format should error");

        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_check_compliance_rejects_private_target() {
        let state = build_state();
        let query = ComplianceQuery {
            target: Some("127.0.0.1:443".to_string()),
            format: "json".to_string(),
            detailed: false,
        };

        let err = check_compliance(State(state), Path("pci-dss-v4".to_string()), Query(query))
            .await
            .expect_err("private target should error");

        assert!(matches!(err, ApiError::BadRequest(_)));
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

    #[test]
    fn test_parse_compliance_response_format() {
        assert_eq!(
            ComplianceResponseFormat::parse("json").expect("json should parse"),
            ComplianceResponseFormat::Json
        );
        assert_eq!(
            ComplianceResponseFormat::parse("TERMINAL").expect("terminal should parse"),
            ComplianceResponseFormat::Terminal
        );
        assert_eq!(
            ComplianceResponseFormat::parse(" csv ").expect("csv should parse"),
            ComplianceResponseFormat::Csv
        );
        assert!(matches!(
            ComplianceResponseFormat::parse("xml"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn test_render_compliance_response_json() {
        let framework = test_framework();
        let report = test_report();

        let response = ComplianceResponseFormat::Json
            .render(&framework, &report, true)
            .expect("json render should succeed");

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid json");

        assert_eq!(content_type.as_deref(), Some("application/json"));
        assert_eq!(json["framework_id"], "pci-dss-v4");
        assert_eq!(json["target"], "example.com:443");
    }

    #[tokio::test]
    async fn test_render_compliance_response_terminal() {
        let framework = test_framework();
        let report = test_report();

        let response = ComplianceResponseFormat::Terminal
            .render(&framework, &report, true)
            .expect("terminal render should succeed");

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let text = String::from_utf8(body.to_vec()).expect("body should be utf-8");

        assert_eq!(content_type.as_deref(), Some("text/plain; charset=utf-8"));
        assert!(text.contains("Compliance Report"));
        assert!(text.contains("PCI DSS"));
    }

    #[tokio::test]
    async fn test_render_compliance_response_csv() {
        let framework = test_framework();
        let report = test_report();

        let response = ComplianceResponseFormat::Csv
            .render(&framework, &report, true)
            .expect("csv render should succeed");

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should read");
        let csv = String::from_utf8(body.to_vec()).expect("body should be utf-8");

        assert_eq!(content_type.as_deref(), Some("text/csv; charset=utf-8"));
        assert!(csv.contains("Requirement ID,Name,Category,Severity,Status,Violations,Evidence"));
        assert!(csv.contains("\"REQ-1\""));
    }
}
