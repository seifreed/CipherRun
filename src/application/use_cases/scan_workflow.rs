use crate::Result;
use crate::application::{
    ComplianceEvaluatorPort, ComplianceFrameworkSource, PolicyEvaluatorPort, PolicySource,
    ScanAssessment, ScanExecutionReport, ScanRequest, ScanResults, ScanResultsStoreFactory,
    ScannerPort, use_cases::*,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

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
        let started = Instant::now();
        let compliance_requested = input.compliance_framework.is_some();
        let policy_requested = input.policy_path.is_some();
        let persistence_requested = input.store_results;
        let result: Result<ScanExecutionReport> = async {
            if input.store_results && input.database_config_path.is_none() {
                return Err(crate::TlsError::ConfigError {
                    message: "store_results=true requires a database_config_path so results can be persisted"
                        .to_string(),
                });
            }

            let request = input.request.clone();
            let scan_results = RunScan::execute(request, services.scanner_port.as_ref()).await?;
            let assessment = if input.compliance_framework.is_some() || input.policy_path.is_some()
            {
                Some(Self::build_assessment(&scan_results))
            } else {
                None
            };

            let compliance_report = match input.compliance_framework.as_deref() {
                Some(framework_id) => Some(EvaluateCompliance::execute_with_provider(
                    Self::compliance_evaluator(services)?,
                    Self::compliance_source(services)?,
                    framework_id,
                    assessment.as_ref().ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when compliance is requested"
                            .to_string(),
                    })?,
                )?),
                None => None,
            };

            let policy_result = match input.policy_path.as_deref() {
                Some(policy_path) => Some(EvaluatePolicy::execute_with_provider(
                    Self::policy_evaluator(services)?,
                    Self::policy_source(services)?,
                    policy_path,
                    assessment.as_ref().ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when policy is requested".to_string(),
                    })?,
                )?),
                None => None,
            };

            let stored_scan_id = match (input.store_results, input.database_config_path.as_deref())
            {
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
        .await;

        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(_) => tracing::info!(
                event_name = "scan.workflow.finished",
                operation = "scan_workflow",
                compliance_requested,
                policy_requested,
                persistence_requested,
                duration_ms,
                outcome = "success",
                "Scan workflow finished"
            ),
            Err(error)
                if matches!(
                    error.observability_code(),
                    "configuration_error" | "invalid_input"
                ) =>
            {
                tracing::warn!(
                    event_name = "scan.workflow.failed",
                    operation = "scan_workflow",
                    compliance_requested,
                    policy_requested,
                    persistence_requested,
                    duration_ms,
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "failed",
                    "Scan workflow failed"
                );
            }
            Err(error) => tracing::error!(
                event_name = "scan.workflow.failed",
                operation = "scan_workflow",
                compliance_requested,
                policy_requested,
                persistence_requested,
                duration_ms,
                error_type = "TlsError",
                error_code = error.observability_code(),
                outcome = "failed",
                "Scan workflow failed"
            ),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{ComplianceEvaluatorPort, ScanResults, ScannerPort};
    use async_trait::async_trait;

    struct EmptyScanner;

    #[async_trait]
    impl ScannerPort for EmptyScanner {
        async fn scan(&self, _request: ScanRequest) -> Result<ScanResults> {
            Ok(ScanResults::default())
        }
    }

    struct FailingScanner;

    #[async_trait]
    impl ScannerPort for FailingScanner {
        async fn scan(&self, _request: ScanRequest) -> Result<ScanResults> {
            Err(crate::TlsError::InvalidInput {
                message: "invalid test target".to_string(),
            })
        }
    }

    struct UnusedComplianceEvaluator;

    impl ComplianceEvaluatorPort for UnusedComplianceEvaluator {
        fn evaluate(
            &self,
            _framework: &crate::compliance::ComplianceFramework,
            _assessment: &ScanAssessment,
        ) -> Result<crate::compliance::ComplianceReport> {
            unreachable!("missing framework source should fail before evaluation")
        }
    }

    struct UnusedPolicyEvaluator;

    impl crate::application::PolicyEvaluatorPort for UnusedPolicyEvaluator {
        fn evaluate(
            &self,
            _policy: &crate::policy::Policy,
            _assessment: &ScanAssessment,
        ) -> Result<crate::policy::PolicyResult> {
            unreachable!("missing policy source should fail before evaluation")
        }
    }

    fn make_services(scanner_port: Arc<dyn ScannerPort>) -> ScanWorkflowServices {
        ScanWorkflowServices {
            scanner_port,
            compliance_framework_source: None,
            compliance_evaluator: None,
            policy_source: None,
            policy_evaluator: None,
            scan_results_store_factory: None,
        }
    }

    fn default_input() -> ScanWorkflowInput {
        ScanWorkflowInput::default()
    }

    fn is_config_error(result: Result<ScanExecutionReport>) -> bool {
        matches!(result, Err(crate::TlsError::ConfigError { .. }))
    }

    #[tokio::test]
    async fn execute_returns_scan_report_without_optional_operations() {
        let services = make_services(Arc::new(EmptyScanner));

        let report = ScanWorkflow::execute(default_input(), &services)
            .await
            .expect("default workflow should succeed");

        assert!(!report.has_compliance_report());
        assert!(!report.has_policy_result());
        assert!(!report.has_stored_scan());
    }

    #[tokio::test]
    async fn execute_rejects_persistence_without_database_path() {
        let services = make_services(Arc::new(EmptyScanner));
        let input = ScanWorkflowInput {
            store_results: true,
            ..default_input()
        };

        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));
    }

    #[tokio::test]
    async fn execute_reports_missing_compliance_dependencies() {
        let services = make_services(Arc::new(EmptyScanner));
        let input = ScanWorkflowInput {
            compliance_framework: Some("baseline".to_string()),
            ..default_input()
        };
        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));

        let mut services = make_services(Arc::new(EmptyScanner));
        services.compliance_evaluator = Some(Arc::new(UnusedComplianceEvaluator));
        let input = ScanWorkflowInput {
            compliance_framework: Some("baseline".to_string()),
            ..default_input()
        };
        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));
    }

    #[tokio::test]
    async fn execute_reports_missing_policy_dependencies() {
        let services = make_services(Arc::new(EmptyScanner));
        let input = ScanWorkflowInput {
            policy_path: Some(PathBuf::from("policy.yaml")),
            ..default_input()
        };
        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));

        let mut services = make_services(Arc::new(EmptyScanner));
        services.policy_evaluator = Some(Arc::new(UnusedPolicyEvaluator));
        let input = ScanWorkflowInput {
            policy_path: Some(PathBuf::from("policy.yaml")),
            ..default_input()
        };
        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));
    }

    #[tokio::test]
    async fn execute_reports_missing_results_store_factory() {
        let services = make_services(Arc::new(EmptyScanner));
        let input = ScanWorkflowInput {
            store_results: true,
            database_config_path: Some(PathBuf::from("database.toml")),
            ..default_input()
        };

        assert!(is_config_error(
            ScanWorkflow::execute(input, &services).await
        ));
    }

    #[tokio::test]
    async fn execute_returns_scanner_errors() {
        let services = make_services(Arc::new(FailingScanner));

        assert!(matches!(
            ScanWorkflow::execute(default_input(), &services).await,
            Err(crate::TlsError::InvalidInput { .. })
        ));
    }
}
