use crate::api::models::error::ApiError;
use crate::application::ports::{PolicyEvaluatorPort, ScannerPort};
use crate::application::use_cases::EvaluatePolicy;
use crate::application::{ScanAssessment, ScanRequest};
use crate::policy::{Policy, PolicyResult};
use crate::scanner::ScanResults;

fn map_scan_error(context: &str, error: crate::TlsError) -> ApiError {
    match error {
        crate::TlsError::InvalidInput { message } => ApiError::BadRequest(message),
        other => ApiError::Internal(format!("{}: {}", context, other)),
    }
}

/// Run a full policy check using the provided scanner and evaluator port implementations.
pub async fn run_policy_check(
    scanner: &dyn ScannerPort,
    evaluator: &dyn PolicyEvaluatorPort,
    policy: &Policy,
    request: ScanRequest,
) -> Result<(ScanResults, PolicyResult), ApiError> {
    let scan_results = scanner
        .scan(request)
        .await
        .map_err(|e| map_scan_error("Scan failed", e))?;

    let assessment = ScanAssessment::from_scan_results(&scan_results);
    let policy_result = EvaluatePolicy::execute(evaluator, policy, &assessment)
        .map_err(|e| ApiError::Internal(format!("Policy evaluation failed: {}", e)))?;

    Ok((scan_results, policy_result))
}

/// Run a full policy check using the default scanner and evaluator implementations.
pub async fn run_policy_check_with_defaults(
    policy: &Policy,
    request: ScanRequest,
) -> Result<(ScanResults, PolicyResult), ApiError> {
    let scanner = crate::scanner::DefaultScannerPort;
    let evaluator = crate::policy::evaluator::DefaultPolicyEvaluator;
    run_policy_check(&scanner, &evaluator, policy, request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ScanRequest;
    use async_trait::async_trait;

    struct FailingScanner;

    #[async_trait]
    impl ScannerPort for FailingScanner {
        async fn scan(&self, _request: ScanRequest) -> crate::Result<ScanResults> {
            Err(crate::TlsError::InvalidInput {
                message: "target rejected".to_string(),
            })
        }
    }

    struct StubEvaluator;

    impl PolicyEvaluatorPort for StubEvaluator {
        fn evaluate(
            &self,
            policy: &Policy,
            _assessment: &ScanAssessment,
        ) -> crate::Result<PolicyResult> {
            Ok(PolicyResult::new(policy.clone(), vec![]))
        }
    }

    fn stub_policy() -> Policy {
        Policy {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: None,
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: None,
            compliance: None,
            exceptions: vec![],
        }
    }

    fn stub_request() -> ScanRequest {
        ScanRequest::default()
    }

    #[tokio::test]
    async fn run_policy_check_maps_invalid_input_to_bad_request() {
        let err = run_policy_check(
            &FailingScanner,
            &StubEvaluator,
            &stub_policy(),
            stub_request(),
        )
        .await
        .expect_err("failing scanner should propagate error");

        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
