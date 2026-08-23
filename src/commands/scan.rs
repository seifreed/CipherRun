// ScanCommand - Single target TLS/SSL scanning
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_diff::ScanDiffCommand;
use super::scan_presenter::ScanPresenter;
use super::{Command, CommandExit};
use crate::application::use_cases::{ScanWorkflow, ScanWorkflowInput, ScanWorkflowServices};
use crate::compliance::{BuiltinFrameworkSource, engine::DefaultComplianceEvaluator};
use crate::db::ConfigFileScanResultsStoreFactory;
use crate::policy::{FilesystemPolicySource, evaluator::DefaultPolicyEvaluator};
use crate::scanner::DefaultScannerPort;
use crate::{Args, Result};
use async_trait::async_trait;
use std::sync::Arc;

/// ScanCommand handles single target TLS/SSL security scanning
///
/// This command is responsible for:
/// - Scanning a single target (hostname:port)
/// - Running all requested security tests
/// - Evaluating compliance frameworks if requested
/// - Evaluating policy-as-code if requested
/// - Storing results in database if requested
/// - Exporting results to various formats (JSON, CSV, HTML, XML)
pub struct ScanCommand {
    args: Args,
}

struct ScanCommandOutcome {
    exit: CommandExit,
}

impl ScanCommand {
    /// Create a new ScanCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    fn finalize_outcome(&self, exit: CommandExit) -> ScanCommandOutcome {
        ScanCommandOutcome { exit }
    }

    fn baseline_exit(&self, current: &crate::scanner::ScanResults) -> Result<CommandExit> {
        let Some(path) = self.args.output.baseline.as_deref() else {
            return Ok(CommandExit::success());
        };
        let baseline = ScanDiffCommand::read_scan(path)?;
        let diff = crate::scanner::diff::ScanDiff::compare(&baseline, current)?;
        if !self.args.output.quiet {
            println!("{}", diff.to_terminal());
        }
        if diff.has_changes() {
            Ok(CommandExit::drift_failure())
        } else {
            Ok(CommandExit::success())
        }
    }
}

#[async_trait]
impl Command for ScanCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let input = ScanWorkflowInput {
            request: self.args.to_scan_request()?,
            compliance_framework: self.args.compliance.framework.clone(),
            policy_path: self.args.compliance.policy.clone(),
            store_results: self.args.database.store_results,
            database_config_path: self.args.database.config.clone(),
        };
        let services = ScanWorkflowServices {
            scanner_port: Arc::new(DefaultScannerPort),
            compliance_framework_source: Some(Arc::new(BuiltinFrameworkSource)),
            compliance_evaluator: Some(Arc::new(DefaultComplianceEvaluator)),
            policy_source: Some(Arc::new(FilesystemPolicySource)),
            policy_evaluator: Some(Arc::new(DefaultPolicyEvaluator)),
            scan_results_store_factory: Some(Arc::new(ConfigFileScanResultsStoreFactory)),
        };
        let workflow_result = ScanWorkflow::execute(input, &services).await?;
        let presenter = ScanPresenter::new(&self.args);
        let mut exit = presenter.present(&workflow_result)?;
        let baseline_exit = self.baseline_exit(workflow_result.results())?;
        if exit.is_success()
            && self
                .args
                .output
                .fail_on
                .is_some_and(|threshold| threshold.is_met_by(workflow_result.results()))
        {
            exit = CommandExit::findings_failure();
        }
        if exit.is_success() && !baseline_exit.is_success() {
            exit = baseline_exit;
        }

        Ok(self.finalize_outcome(exit).exit)
    }

    fn name(&self) -> &'static str {
        "ScanCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    #[test]
    fn test_scan_command_name() {
        let args = Args::default();
        let cmd = ScanCommand::new(args);
        assert_eq!(cmd.name(), "ScanCommand");
    }

    #[test]
    fn baseline_exit_reports_drift() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("baseline.json");
        let baseline = crate::scanner::ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        std::fs::write(&path, baseline.to_json(false).unwrap()).unwrap();
        let command = ScanCommand::new(Args {
            output: crate::cli::OutputArgs {
                baseline: Some(path),
                quiet: true,
                ..Default::default()
            },
            ..Default::default()
        });
        let mut current = baseline;
        current
            .protocols
            .push(crate::protocols::ProtocolTestResult {
                protocol: crate::protocols::Protocol::TLS13,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            });

        assert_eq!(
            command.baseline_exit(&current).unwrap().code(),
            CommandExit::DRIFT_FAILURE
        );
    }
}
