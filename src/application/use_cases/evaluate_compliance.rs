use crate::Result;
use crate::application::{ComplianceEvaluatorPort, ComplianceFrameworkSource, ScanAssessment};
use crate::compliance::ComplianceReport;

/// Application use case for compliance evaluation.
pub struct EvaluateCompliance;

impl EvaluateCompliance {
    pub fn execute(
        evaluator: &dyn ComplianceEvaluatorPort,
        framework: &crate::compliance::ComplianceFramework,
        assessment: &ScanAssessment,
    ) -> Result<ComplianceReport> {
        evaluator.evaluate(framework, assessment)
    }

    pub fn execute_with_provider(
        evaluator: &dyn ComplianceEvaluatorPort,
        provider: &dyn ComplianceFrameworkSource,
        framework_id: &str,
        assessment: &ScanAssessment,
    ) -> Result<ComplianceReport> {
        let framework = provider.load_framework(framework_id)?;
        Self::execute(evaluator, &framework, assessment)
    }
}
