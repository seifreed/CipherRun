use crate::Result;
use crate::application::{PolicySource, ScanAssessment};
use crate::policy::{PolicyResult, evaluator::PolicyEvaluator};
use std::path::Path;

/// Application use case for policy evaluation.
pub struct EvaluatePolicy;

impl EvaluatePolicy {
    pub fn execute_assessment(
        policy: &crate::policy::Policy,
        assessment: &ScanAssessment,
    ) -> Result<PolicyResult> {
        let evaluator = PolicyEvaluator::new(policy.clone());
        evaluator.evaluate(assessment)
    }

    pub fn execute_with_provider(
        provider: &dyn PolicySource,
        policy_path: &Path,
        assessment: &ScanAssessment,
    ) -> Result<PolicyResult> {
        let policy = provider.load_policy(policy_path)?;
        Self::execute_assessment(&policy, assessment)
    }
}
