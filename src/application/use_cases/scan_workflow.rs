use crate::Result;
use crate::application::{
    ComplianceEvaluatorPort, ComplianceFrameworkSource, PolicyEvaluatorPort, PolicySource,
    ScanAssessment, ScanExecutionReport, ScanRequest, ScanResults, ScanResultsStoreFactory,
    ScannerPort, use_cases::*,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Pure data describing what the workflow should do.
#[derive(Clone, Default)]
pub struct ScanWorkflowInput {
    pub request: ScanRequest,
    pub compliance_framework: Option<String>,
    pub policy_path: Option<PathBuf>,
    pub store_results: bool,
    pub database_config_path: Option<PathBuf>,
}

/// Injected service dependencies for executing the workflow.
pub struct ScanWorkflowServices {
    pub scanner_port: Arc<dyn ScannerPort>,
    pub compliance_framework_source: Option<Arc<dyn ComplianceFrameworkSource>>,
    pub compliance_evaluator: Option<Arc<dyn ComplianceEvaluatorPort>>,
    pub policy_source: Option<Arc<dyn PolicySource>>,
    pub policy_evaluator: Option<Arc<dyn PolicyEvaluatorPort>>,
    pub scan_results_store_factory: Option<Arc<dyn ScanResultsStoreFactory>>,
}

/// Application workflow for the single-target scan flow.
pub struct ScanWorkflow;

impl ScanWorkflow {
    fn compliance_source(
        services: &ScanWorkflowServices,
    ) -> Result<&dyn ComplianceFrameworkSource> {
        services
            .compliance_framework_source
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Compliance framework source is required when compliance is requested"
                    .to_string(),
            })
    }

    fn policy_source(services: &ScanWorkflowServices) -> Result<&dyn PolicySource> {
        services
            .policy_source
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Policy source is required when policy evaluation is requested"
                    .to_string(),
            })
    }

    fn compliance_evaluator(
        services: &ScanWorkflowServices,
    ) -> Result<&dyn ComplianceEvaluatorPort> {
        services
            .compliance_evaluator
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Compliance evaluator is required when compliance is requested"
                    .to_string(),
            })
    }

    fn policy_evaluator(services: &ScanWorkflowServices) -> Result<&dyn PolicyEvaluatorPort> {
        services
            .policy_evaluator
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Policy evaluator is required when policy evaluation is requested"
                    .to_string(),
            })
    }

    fn results_store_factory(
        services: &ScanWorkflowServices,
    ) -> Result<&dyn ScanResultsStoreFactory> {
        services
            .scan_results_store_factory
            .as_deref()
            .ok_or_else(|| crate::TlsError::ConfigError {
                message: "Scan results store factory is required when result storage is requested"
                    .to_string(),
            })
    }

    fn build_assessment(scan_results: &ScanResults) -> ScanAssessment {
        ScanAssessment::from_scan_results(scan_results)
    }

    pub async fn execute(
        input: ScanWorkflowInput,
        services: &ScanWorkflowServices,
    ) -> Result<ScanExecutionReport> {
        let request = input.request.clone();
        let scan_results = RunScan::execute(request, services.scanner_port.as_ref()).await?;
        let assessment = if input.compliance_framework.is_some() || input.policy_path.is_some() {
            Some(Self::build_assessment(&scan_results))
        } else {
            None
        };

        let compliance_report = match input.compliance_framework.as_deref() {
            Some(framework_id) => Some(EvaluateCompliance::execute_with_provider(
                Self::compliance_evaluator(services)?,
                Self::compliance_source(services)?,
                framework_id,
                assessment
                    .as_ref()
                    .ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when compliance is requested".to_string(),
                    })?,
            )?),
            None => None,
        };

        let policy_result = match input.policy_path.as_deref() {
            Some(policy_path) => Some(EvaluatePolicy::execute_with_provider(
                Self::policy_evaluator(services)?,
                Self::policy_source(services)?,
                policy_path,
                assessment
                    .as_ref()
                    .ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when policy is requested".to_string(),
                    })?,
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
            (true, Some(config_path)) => Some(
                StoreScanResults::execute_with_factory(
                    Self::results_store_factory(services)?,
                    config_path,
                    &scan_results,
                )
                .await?,
            ),
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
