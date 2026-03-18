use crate::Result;
use crate::application::{
    ComplianceFrameworkSource, PolicySource, ScanAssessment, ScanExecutionReport, ScanRequest,
    ScanResultsStoreFactory, use_cases::*,
};
use crate::scanner::ScanResults;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct ScanWorkflowInput {
    pub request: ScanRequest,
    pub compliance_framework: Option<String>,
    pub policy_path: Option<PathBuf>,
    pub store_results: bool,
    pub database_config_path: Option<PathBuf>,
    pub compliance_framework_source: Option<Arc<dyn ComplianceFrameworkSource>>,
    pub policy_source: Option<Arc<dyn PolicySource>>,
    pub scan_results_store_factory: Option<Arc<dyn ScanResultsStoreFactory>>,
}

/// Application workflow for the single-target scan flow.
pub struct ScanWorkflow;

impl ScanWorkflow {
    fn compliance_source(
        input: &ScanWorkflowInput,
    ) -> Result<&dyn ComplianceFrameworkSource> {
        input
            .compliance_framework_source
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Compliance framework source is required when compliance is requested"
                    .to_string(),
            })
            .map_err(Into::into)
    }

    fn policy_source(input: &ScanWorkflowInput) -> Result<&dyn PolicySource> {
        input
            .policy_source
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Policy source is required when policy evaluation is requested"
                    .to_string(),
            })
            .map_err(Into::into)
    }

    fn results_store_factory(
        input: &ScanWorkflowInput,
    ) -> Result<&dyn ScanResultsStoreFactory> {
        input
            .scan_results_store_factory
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Scan results store factory is required when result storage is requested"
                    .to_string(),
            })
            .map_err(Into::into)
    }

    fn build_assessment(scan_results: &ScanResults) -> ScanAssessment {
        ScanAssessment::from_scan_results(scan_results)
    }

    pub async fn execute(input: ScanWorkflowInput) -> Result<ScanExecutionReport> {
        let request = input.request.clone();
        let scan_results = RunScan::execute(request).await?;
        let assessment = if input.compliance_framework.is_some() || input.policy_path.is_some() {
            Some(Self::build_assessment(&scan_results))
        } else {
            None
        };

        let compliance_report = match input.compliance_framework.as_deref() {
            Some(framework_id) => Some(EvaluateCompliance::execute_with_provider(
                Self::compliance_source(&input)?,
                framework_id,
                assessment
                    .as_ref()
                    .expect("assessment should exist when compliance is requested"),
            )?),
            None => None,
        };

        let policy_result = match input.policy_path.as_deref() {
            Some(policy_path) => Some(EvaluatePolicy::execute_with_provider(
                Self::policy_source(&input)?,
                policy_path,
                assessment
                    .as_ref()
                    .expect("assessment should exist when policy is requested"),
            )?),
            None => None,
        };

        if input.store_results && input.database_config_path.is_none() {
            return Err(crate::TlsError::ConfigError {
                message:
                    "store_results=true requires a database_config_path so results can be persisted"
                        .to_string(),
            });
        }

        let stored_scan_id = match (input.store_results, input.database_config_path.as_deref()) {
            (true, Some(config_path)) => {
                Some(
                    StoreScanResults::execute_with_factory(
                        Self::results_store_factory(&input)?,
                        config_path,
                        &scan_results,
                    )
                    .await?,
                )
            }
            _ => None,
        };

        Ok(ScanExecutionReport::new(
            scan_results,
            compliance_report,
            policy_result,
            stored_scan_id,
        ))
    }
}
