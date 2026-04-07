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
