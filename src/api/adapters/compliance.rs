use crate::api::models::error::ApiError;
use crate::api::presenters::target_input::full_scan_request_from_target;
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

/// Run a full compliance check using the default scanner and evaluator implementations.
pub async fn run_compliance_check_with_defaults(
    framework: &ComplianceFramework,
    target: &str,
) -> Result<(ScanAssessment, crate::compliance::ComplianceReport), ApiError> {
    let scanner = crate::scanner::DefaultScannerPort;
    let evaluator = crate::compliance::engine::DefaultComplianceEvaluator;
    run_compliance_check(&scanner, &evaluator, framework, target).await
}

/// Run a full compliance check: scan target, then evaluate against framework.
pub async fn run_compliance_check(
    scanner: &dyn ScannerPort,
    evaluator: &dyn ComplianceEvaluatorPort,
    framework: &ComplianceFramework,
    target: &str,
) -> Result<(ScanAssessment, crate::compliance::ComplianceReport), ApiError> {
    let request = full_scan_request_from_target(target)?;

    let scan_results = scanner
        .scan(request)
        .await
        .map_err(|e| ApiError::Internal(format!("Scan failed: {}", e)))?;

    let assessment = ScanAssessment::from_scan_results(&scan_results);
    let report = EvaluateCompliance::execute(evaluator, framework, &assessment)
        .map_err(|e| ApiError::Internal(format!("Compliance evaluation failed: {}", e)))?;

    Ok((assessment, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc;

    struct RecordingScanner {
        captured: Arc<Mutex<Vec<crate::application::ScanRequest>>>,
    }

    #[async_trait]
    impl ScannerPort for RecordingScanner {
        async fn scan(
            &self,
            request: crate::application::ScanRequest,
        ) -> crate::Result<crate::scanner::ScanResults> {
            self.captured.lock().push(request.clone());
            Ok(crate::scanner::ScanResults {
                target: request.target.clone().unwrap_or_default(),
                ..Default::default()
            })
        }
    }

    struct PassThroughEvaluator;

    impl ComplianceEvaluatorPort for PassThroughEvaluator {
        fn evaluate(
            &self,
            framework: &ComplianceFramework,
            assessment: &ScanAssessment,
        ) -> crate::Result<crate::compliance::ComplianceReport> {
            Ok(crate::compliance::ComplianceReport::new(
                framework,
                assessment.target.clone(),
            ))
        }
    }

    fn test_framework() -> ComplianceFramework {
        ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test framework".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: Vec::new(),
        }
    }

    #[tokio::test]
    async fn run_compliance_check_uses_full_scan_request() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let scanner = RecordingScanner {
            captured: captured.clone(),
        };
        let evaluator = PassThroughEvaluator;

        let (_assessment, report) =
            run_compliance_check(&scanner, &evaluator, &test_framework(), "example.com:8443")
                .await
                .expect("compliance check should succeed");

        let captured = captured.lock();
        assert_eq!(captured.len(), 1);
        let request = &captured[0];
        assert_eq!(request.target.as_deref(), Some("example.com:8443"));
        assert!(request.scan.scope.full);
        assert!(request.scan.proto.enabled);
        assert!(request.scan.ciphers.each_cipher);
        assert!(request.scan.vulns.vulnerabilities);
        assert!(request.scan.certs.analyze_certificates);
        assert!(request.scan.prefs.headers);
        assert!(request.fingerprint.client_simulation);
        assert_eq!(report.target, "example.com:8443");
    }

    #[tokio::test]
    async fn run_compliance_check_rejects_private_target() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let scanner = RecordingScanner {
            captured: captured.clone(),
        };
        let evaluator = PassThroughEvaluator;

        let err = run_compliance_check(&scanner, &evaluator, &test_framework(), "127.0.0.1:443")
            .await
            .expect_err("private target should fail");

        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(captured.lock().is_empty());
    }
}
