use crate::Result;
use crate::application::{ComplianceFrameworkSource, ScanAssessment};
use crate::compliance::{ComplianceReport, engine::ComplianceEngine};

/// Application use case for compliance evaluation.
pub struct EvaluateCompliance;

impl EvaluateCompliance {
    pub fn execute_assessment(
        framework: &crate::compliance::ComplianceFramework,
        assessment: &ScanAssessment,
    ) -> Result<ComplianceReport> {
        let engine = ComplianceEngine::new(framework.clone());
        Ok(engine.evaluate(assessment)?)
    }

    pub fn execute_with_provider(
        provider: &dyn ComplianceFrameworkSource,
        framework_id: &str,
        assessment: &ScanAssessment,
    ) -> Result<ComplianceReport> {
        let framework = provider.load_framework(framework_id)?;
        Self::execute_assessment(&framework, assessment)
    }
}
