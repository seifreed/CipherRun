// MxTestCommand - MX record testing for mail servers
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_exporter::{ExportKind, ScanExportOutcome, ScanExporter};
use super::scan_notice_presenter::ScanNoticePresenter;
use super::scan_post_presenter::ScanPostPresenter;
use super::{Command, CommandExit};
use crate::application::use_cases::{EvaluateCompliance, EvaluatePolicy, StoreScanResults};
use crate::application::{ScanAssessment, ScanExecutionReport};
use crate::compliance::{BuiltinFrameworkSource, engine::DefaultComplianceEvaluator};
use crate::db::ConfigFileScanResultsStoreFactory;
use crate::policy::{FilesystemPolicySource, evaluator::DefaultPolicyEvaluator};
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use std::sync::Arc;

/// MxTestCommand handles MX record testing for mail servers
///
/// This command is responsible for:
/// - Resolving MX records for a domain
/// - Scanning all MX servers
/// - Generating summary reports
/// - Exporting results to JSON if requested
pub struct MxTestCommand {
    args: Args,
}

impl MxTestCommand {
    /// Create a new MxTestCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    fn workflow_dependencies(&self) -> MxWorkflowDependencies {
        MxWorkflowDependencies {
            compliance_framework_source: Arc::new(BuiltinFrameworkSource),
            compliance_evaluator: Arc::new(DefaultComplianceEvaluator),
            policy_source: Arc::new(FilesystemPolicySource),
            policy_evaluator: Arc::new(DefaultPolicyEvaluator),
            scan_results_store_factory: Arc::new(ConfigFileScanResultsStoreFactory),
        }
    }

    fn needs_aggregated_post_processing(&self) -> bool {
        self.args.compliance.framework.is_some()
            || self.args.compliance.policy.is_some()
            || self.args.database.store_results
            || self.args.output.csv.is_some()
            || self.args.output.html.is_some()
            || self.args.output.xml.is_some()
    }

    fn export_collection_json(
        &self,
        mx_domain: &str,
        results: &[(
            crate::utils::mx::MxRecord,
            Result<crate::scanner::ScanResults>,
        )],
    ) -> Result<bool> {
        let exporter = ScanExporter::new(&self.args);
        let json_path = exporter.collection_json_output_path();

        let Some(json_file) = json_path else {
            return Ok(false);
        };

        use serde_json::json;
        let json_data = json!({
            "scan_type": "mx_records",
            "domain": mx_domain,
            "total_mx_servers": results.len(),
            "results": results.iter().map(|(mx, result)| {
                json!({
                    "priority": mx.priority,
                    "hostname": mx.hostname,
                    "success": result.is_ok(),
                    "scan_results": result.as_ref().ok(),
                    "error": result.as_ref().err().map(|e| e.to_string()),
                })
            }).collect::<Vec<_>>(),
        });

        let json_string = if self.args.output.json_pretty {
            serde_json::to_string_pretty(&json_data)?
        } else {
            serde_json::to_string(&json_data)?
        };

        exporter.write_text_file(&json_file, &json_string, "JSON", ExportKind::Json)?;
        Ok(true)
    }

    async fn build_execution_report(
        &self,
        mx_tester: &crate::utils::mx::MxTester,
        results: &[(
            crate::utils::mx::MxRecord,
            Result<crate::scanner::ScanResults>,
        )],
    ) -> Result<ScanExecutionReport> {
        let aggregated_results = mx_tester.aggregate_scan_results(results)?;
        let assessment =
            if self.args.compliance.framework.is_some() || self.args.compliance.policy.is_some() {
                Some(ScanAssessment::from_scan_results(&aggregated_results))
            } else {
                None
            };
        let dependencies = self.workflow_dependencies();

        let compliance_report = match self.args.compliance.framework.as_deref() {
            Some(framework_id) => Some(EvaluateCompliance::execute_with_provider(
                dependencies.compliance_evaluator.as_ref(),
                dependencies.compliance_framework_source.as_ref(),
                framework_id,
                assessment
                    .as_ref()
                    .ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when compliance is requested".to_string(),
                    })?,
            )?),
            None => None,
        };

        let policy_result = match self.args.compliance.policy.as_deref() {
            Some(policy_path) => Some(EvaluatePolicy::execute_with_provider(
                dependencies.policy_evaluator.as_ref(),
                dependencies.policy_source.as_ref(),
                policy_path,
                assessment
                    .as_ref()
                    .ok_or_else(|| crate::TlsError::ConfigError {
                        message: "assessment should exist when policy is requested".to_string(),
                    })?,
            )?),
            None => None,
        };

        let stored_scan_id = if self.args.database.store_results {
            let config_path = self.args.database.config.as_deref().ok_or_else(|| {
                crate::TlsError::ConfigError {
                    message: "store_results=true requires a database_config_path so results can be persisted"
                        .to_string(),
                }
            })?;

            Some(
                StoreScanResults::execute_with_factory(
                    dependencies.scan_results_store_factory.as_ref(),
                    config_path,
                    &aggregated_results,
                )
                .await?,
            )
        } else {
            None
        };

        Ok(ScanExecutionReport::new(
            aggregated_results,
            compliance_report,
            policy_result,
            stored_scan_id,
        ))
    }

    fn export_aggregated_artifacts(
        &self,
        report: &ScanExecutionReport,
    ) -> Result<ScanExportOutcome> {
        let cli_view = report.cli_view(self.args.compliance.enforce);
        if !cli_view.should_export_artifacts() {
            return Ok(ScanExportOutcome::none());
        }

        let exporter = ScanExporter::new(&self.args);
        let mut plan = exporter.build_plan_from_view(cli_view.export_view());
        plan.json_file = None;
        plan.json_multi_ip = None;

        if !plan.has_export_targets() {
            return Ok(ScanExportOutcome::none());
        }

        exporter.export(plan)
    }

    fn render_post_scan_notices(
        &self,
        report: &ScanExecutionReport,
        export_outcome: &ScanExportOutcome,
    ) {
        let cli_view = report.cli_view(self.args.compliance.enforce);
        let notices = ScanNoticePresenter::new();

        if let Some(scan_id) = cli_view.stored_scan_id_for_artifact_notices() {
            notices.render_storage_notice(Some(scan_id));
        }

        if cli_view.should_render_post_scan_export_spacing(export_outcome.exported()) {
            notices.render_export_spacing(true);
        }
    }
}

struct MxWorkflowDependencies {
    compliance_framework_source: Arc<BuiltinFrameworkSource>,
    compliance_evaluator: Arc<DefaultComplianceEvaluator>,
    policy_source: Arc<FilesystemPolicySource>,
    policy_evaluator: Arc<DefaultPolicyEvaluator>,
    scan_results_store_factory: Arc<ConfigFileScanResultsStoreFactory>,
}

#[async_trait]
impl Command for MxTestCommand {
    async fn execute(&self) -> Result<CommandExit> {
        use crate::utils::mx::MxTester;

        let mx_domain = self
            .args
            .mx_domain
            .as_ref()
            .ok_or_else(|| TlsError::InvalidInput {
                message: "MX domain is required".to_string(),
            })?;

        if self.args.database.store_results && self.args.database.config.is_none() {
            return Err(crate::TlsError::ConfigError {
                message:
                    "store_results=true requires a database_config_path so results can be persisted"
                        .to_string(),
            });
        }

        let mx_tester =
            MxTester::with_resolvers(mx_domain.clone(), self.args.network.resolvers.clone());
        let results = mx_tester.scan_all_mx(self.args.clone()).await?;

        if !self.args.output.quiet {
            println!("{}", MxTester::generate_mx_summary(&results));
        }

        self.export_collection_json(mx_domain, &results)?;

        if !self.needs_aggregated_post_processing() {
            return Ok(CommandExit::success());
        }

        let report = self.build_execution_report(&mx_tester, &results).await?;
        let cli_view = report.cli_view(self.args.compliance.enforce);
        let post_exit = if self.args.output.quiet {
            ScanPostPresenter::new(&self.args).exit_for_post_view(&cli_view.post_view())
        } else {
            ScanPostPresenter::new(&self.args).render(&cli_view.post_view())?
        };
        let export_outcome = self.export_aggregated_artifacts(&report)?;
        if !self.args.output.quiet {
            self.render_post_scan_notices(&report, &export_outcome);
        }

        Ok(post_exit)
    }

    fn name(&self) -> &'static str {
        "MxTestCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mx_test_command_name() {
        let cmd = MxTestCommand::new(Args::default());
        assert_eq!(cmd.name(), "MxTestCommand");
    }

    #[tokio::test]
    async fn test_mx_test_command_requires_domain() {
        let args = Args::default();
        let cmd = MxTestCommand::new(args);
        let err = cmd.execute().await.unwrap_err();
        assert!(format!("{err}").contains("MX domain is required"));
    }
}
