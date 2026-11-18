use crate::Result;
use crate::application::{PolicyEvaluatorPort, PolicySource, ScanAssessment};
use crate::policy::PolicyResult;
use std::path::Path;

/// Application use case for policy evaluation.
pub struct EvaluatePolicy;

impl EvaluatePolicy {
    pub fn execute(
        evaluator: &dyn PolicyEvaluatorPort,
        policy: &crate::policy::Policy,
        assessment: &ScanAssessment,
    ) -> Result<PolicyResult> {
        evaluator.evaluate(policy, assessment)
    }

    pub fn execute_with_provider(
        evaluator: &dyn PolicyEvaluatorPort,
        provider: &dyn PolicySource,
        policy_path: &Path,
        assessment: &ScanAssessment,
    ) -> Result<PolicyResult> {
        let policy = provider.load_policy(policy_path)?;
        Self::execute(evaluator, &policy, assessment)
    }
}

#[cfg(test)]
mod tests {
    use super::EvaluatePolicy;
    use crate::application::{PolicyEvaluatorPort, PolicySource, ScanAssessment};
    use crate::policy::{Policy, PolicyOverallResult, PolicyResult, PolicySummary};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    struct EchoEvaluator;

    impl PolicyEvaluatorPort for EchoEvaluator {
        fn evaluate(
            &self,
            policy: &Policy,
            assessment: &ScanAssessment,
        ) -> crate::Result<PolicyResult> {
            Ok(PolicyResult {
                policy_name: policy.name.clone(),
                policy_version: policy.version.clone(),
                target: assessment.target.clone(),
                evaluation_time: chrono::Utc::now(),
                violations: Vec::new(),
                exceptions_applied: Vec::new(),
                summary: PolicySummary {
                    total_checks: 0,
                    passed: 0,
                    failed: 0,
                    warnings: 0,
                    info: 0,
                    overall_result: PolicyOverallResult::Pass,
                },
            })
        }
    }

    struct RecordingPolicySource {
        policy: Policy,
        loaded_path: Mutex<Option<PathBuf>>,
    }

    impl PolicySource for RecordingPolicySource {
        fn load_policy(&self, policy_path: &Path) -> crate::Result<Policy> {
            *self.loaded_path.lock().unwrap() = Some(policy_path.to_path_buf());
            Ok(self.policy.clone())
        }
    }

    struct FailingPolicySource;

    impl PolicySource for FailingPolicySource {
        fn load_policy(&self, _policy_path: &Path) -> crate::Result<Policy> {
            Err(crate::TlsError::Other("policy load failed".to_string()))
        }
    }

    fn policy() -> Policy {
        Policy {
            name: "test-policy".to_string(),
            version: "1".to_string(),
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
            exceptions: Vec::new(),
        }
    }

    #[test]
    fn loads_policy_and_forwards_it_to_the_evaluator() {
        let source = RecordingPolicySource {
            policy: policy(),
            loaded_path: Mutex::new(None),
        };
        let assessment = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };

        let result = EvaluatePolicy::execute_with_provider(
            &EchoEvaluator,
            &source,
            Path::new("policies/strict.yml"),
            &assessment,
        )
        .unwrap();

        assert_eq!(result.policy_name, "test-policy");
        assert_eq!(result.target, "example.com:443");
        assert_eq!(
            *source.loaded_path.lock().unwrap(),
            Some(PathBuf::from("policies/strict.yml"))
        );
    }

    #[test]
    fn propagates_policy_source_errors_without_evaluating() {
        let error = EvaluatePolicy::execute_with_provider(
            &EchoEvaluator,
            &FailingPolicySource,
            Path::new("missing.yml"),
            &ScanAssessment::default(),
        )
        .unwrap_err();

        assert!(matches!(error, crate::TlsError::Other(_)));
    }
}
