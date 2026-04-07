use crate::api::models::error::ApiError;
use crate::api::presenters::target_input::scan_request_from_target;
use crate::application::ports::ScannerPort;
use crate::application::use_cases::EvaluateCompliance;
use crate::application::{ComplianceEvaluatorPort, ComplianceFrameworkSource, ScanAssessment};
use crate::compliance::ComplianceFramework;

/// Load a compliance framework by ID, mapping errors to ApiError.
pub fn load_framework(
    source: &dyn ComplianceFrameworkSource,
    framework_id: &str,
) -> Result<ComplianceFramework, ApiError> {
    source.load_framework(framework_id).map_err(|e| {
        if e.to_string().contains("Unknown framework") {
            ApiError::NotFound(format!("Unknown compliance framework: {}", framework_id))
        } else {
            ApiError::Internal(format!("Failed to load framework: {}", e))
        }
    })
}

/// Run a full compliance check: scan target, then evaluate against framework.
pub async fn run_compliance_check(
    scanner: &dyn ScannerPort,
    evaluator: &dyn ComplianceEvaluatorPort,
    framework: &ComplianceFramework,
    target: &str,
) -> Result<(ScanAssessment, crate::compliance::ComplianceReport), ApiError> {
    let request = scan_request_from_target(target)?;

    let scan_results = scanner
        .scan(request)
        .await
        .map_err(|e| ApiError::Internal(format!("Scan failed: {}", e)))?;

    let assessment = ScanAssessment::from_scan_results(&scan_results);
    let report = EvaluateCompliance::execute(evaluator, framework, &assessment)
        .map_err(|e| ApiError::Internal(format!("Compliance evaluation failed: {}", e)))?;

    Ok((assessment, report))
}
