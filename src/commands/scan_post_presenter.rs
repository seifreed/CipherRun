use super::CommandExit;
use crate::application::ScanPostView;
use crate::{Args, Result};
use std::borrow::Cow;

struct ScanPostProcessingOutcome {
    exit: CommandExit,
}

pub struct ScanPostPresenter<'a> {
    args: &'a Args,
}

impl<'a> ScanPostPresenter<'a> {
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub fn render(&self, post_view: &ScanPostView<'_>) -> Result<CommandExit> {
        if !post_view.should_render() {
            return Ok(CommandExit::success());
        }

        let outcome = self.render_outcome(post_view)?;
        if outcome.exit.code() != 0 {
            return Ok(outcome.exit);
        }

        Ok(self.exit_for_post_view(post_view))
    }

    pub fn exit_for_post_view(&self, post_view: &ScanPostView<'_>) -> CommandExit {
        let mut exit = CommandExit::success();

        if post_view.compliance_failed() {
            exit = self.merge_non_zero_exit(exit, CommandExit::failure(1));
        }

        if post_view.should_render_policy_failure_notice() {
            exit = self.merge_non_zero_exit(exit, CommandExit::failure(1));
        }

        if post_view.should_return_failure_exit() && exit.code() == 0 {
            return CommandExit::failure(1);
        }

        exit
    }

    fn render_outcome(&self, post_view: &ScanPostView<'_>) -> Result<ScanPostProcessingOutcome> {
        let mut exit = CommandExit::success();

        if let Some(section_exit) = self.render_compliance_section(post_view)? {
            exit = self.merge_non_zero_exit(exit, section_exit);
        }
        if let Some(section_exit) = self.render_policy_section(post_view)? {
            exit = self.merge_non_zero_exit(exit, section_exit);
        }

        Ok(ScanPostProcessingOutcome { exit })
    }

    fn merge_non_zero_exit(&self, current: CommandExit, candidate: CommandExit) -> CommandExit {
        if current.code() == 0 && candidate.code() != 0 {
            return candidate;
        }
        current
    }

    fn render_compliance_section(
        &self,
        post_view: &ScanPostView<'_>,
    ) -> Result<Option<CommandExit>> {
        use crate::compliance::{ComplianceStatus, Reporter};
        use colored::Colorize;

        if !post_view.should_render_compliance_section() {
            return Ok(None);
        }
        let Some(compliance_report) = post_view.compliance_report() else {
            return Ok(None);
        };
        let compliance_report = self.filtered_compliance_report(compliance_report)?;

        println!("\n{}", "Evaluating Compliance...".cyan().bold());

        match self
            .args
            .compliance
            .format
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => {
                let json =
                    Reporter::to_json(compliance_report.as_ref(), self.args.output.json_pretty)?;
                println!("{}", json);
            }
            "csv" => {
                let csv = Reporter::to_csv(compliance_report.as_ref())?;
                println!("{}", csv);
            }
            "html" => {
                let html = Reporter::to_html(compliance_report.as_ref())?;
                println!("{}", html);
            }
            "terminal" => {
                let terminal_output = Reporter::to_terminal(compliance_report.as_ref());
                println!("{}", terminal_output);
            }
            other => {
                return Err(crate::TlsError::InvalidInput {
                    message: format!(
                        "Invalid compliance format '{}'. Supported values: terminal, json, csv, html",
                        other
                    ),
                });
            }
        }

        if compliance_report.overall_status == ComplianceStatus::Fail {
            return Ok(Some(CommandExit::failure(1)));
        }

        Ok(None)
    }

    fn render_policy_section(&self, post_view: &ScanPostView<'_>) -> Result<Option<CommandExit>> {
        if !post_view.should_render_policy_section() {
            return Ok(None);
        }
        let Some(policy_result) = post_view.policy_result() else {
            return Ok(None);
        };

        println!("\nEvaluating Policy...");

        let formatted_result = policy_result.format(&self.args.compliance.policy_format)?;
        println!("{}", formatted_result);

        if post_view.should_render_policy_failure_notice() {
            println!("\nPolicy evaluation failed - command will return exit code 1");
            return Ok(Some(CommandExit::failure(1)));
        }

        Ok(None)
    }

    fn filtered_compliance_report<'b>(
        &self,
        report: &'b crate::compliance::ComplianceReport,
    ) -> Result<Cow<'b, crate::compliance::ComplianceReport>> {
        if let Some(minimum) = self.args.compliance.minimum_severity()? {
            return Ok(Cow::Owned(report.filtered_by_minimum_severity(minimum)));
        }

        Ok(Cow::Borrowed(report))
    }
}

#[cfg(test)]
mod tests {
    use crate::Args;
    use crate::application::{ScanPostProcessingView, ScanPostView};
    use crate::commands::CommandExit;
    use crate::commands::scan_post_presenter::ScanPostPresenter;
    use crate::compliance::{
        ComplianceFramework, ComplianceReport, ComplianceStatus, ComplianceSummary, Requirement,
        Severity,
    };
    use crate::policy::{
        PolicyOverallResult, PolicyResult, PolicySummary, violation::PolicyViolation,
    };
    use chrono::Utc;

    #[test]
    fn test_merge_non_zero_exit_preserves_initial_zero_only_exit() {
        let args = Args::default();
        let presenter = ScanPostPresenter::new(&args);
        let merged = presenter.merge_non_zero_exit(CommandExit::success(), CommandExit::failure(1));

        assert_eq!(merged.code(), 1);
    }

    #[test]
    fn test_merge_non_zero_exit_keeps_existing_non_zero_exit() {
        let args = Args::default();
        let presenter = ScanPostPresenter::new(&args);
        let merged =
            presenter.merge_non_zero_exit(CommandExit::failure(2), CommandExit::failure(1));

        assert_eq!(merged.code(), 2);
    }

    #[test]
    fn test_exit_for_post_view_returns_failure_for_compliance_failure() {
        let args = Args::default();
        let presenter = ScanPostPresenter::new(&args);
        let compliance_report = compliance_report(ComplianceStatus::Fail);
        let post_processing = ScanPostProcessingView {
            compliance_report: Some(&compliance_report),
            policy_result: None,
            stored_scan_id: None,
            should_fail_exit: true,
        };
        let post_view = ScanPostView {
            post_processing: &post_processing,
        };

        let exit = presenter.exit_for_post_view(&post_view);

        assert_eq!(exit.code(), 1);
    }

    #[test]
    fn test_exit_for_post_view_returns_failure_for_policy_enforcement() {
        let args = Args::default();
        let presenter = ScanPostPresenter::new(&args);
        let policy_result = policy_result(PolicyOverallResult::Fail);
        let post_processing = ScanPostProcessingView {
            compliance_report: None,
            policy_result: Some(&policy_result),
            stored_scan_id: None,
            should_fail_exit: true,
        };
        let post_view = ScanPostView {
            post_processing: &post_processing,
        };

        let exit = presenter.exit_for_post_view(&post_view);

        assert_eq!(exit.code(), 1);
    }

    fn compliance_report(status: ComplianceStatus) -> ComplianceReport {
        ComplianceReport {
            framework: ComplianceFramework {
                id: "test".to_string(),
                name: "Test".to_string(),
                version: "1.0".to_string(),
                description: "Test framework".to_string(),
                organization: "Test Org".to_string(),
                effective_date: None,
                requirements: vec![Requirement {
                    id: "REQ-1".to_string(),
                    name: "Requirement".to_string(),
                    description: "Requirement".to_string(),
                    category: "Security".to_string(),
                    severity: Severity::High,
                    remediation: "Fix it".to_string(),
                    rules: vec![],
                }],
            },
            target: "example.com:443".to_string(),
            scan_timestamp: Utc::now(),
            overall_status: status,
            requirements: vec![],
            summary: ComplianceSummary {
                total: 1,
                passed: 0,
                failed: usize::from(status == ComplianceStatus::Fail),
                warnings: usize::from(status == ComplianceStatus::Warning),
                not_applicable: 0,
            },
        }
    }

    fn policy_result(overall_result: PolicyOverallResult) -> PolicyResult {
        PolicyResult {
            policy_name: "test-policy".to_string(),
            policy_version: "1.0".to_string(),
            target: "example.com:443".to_string(),
            evaluation_time: Utc::now(),
            violations: vec![PolicyViolation::new(
                "protocols.prohibited",
                "Prohibited Protocol",
                crate::policy::PolicyAction::Fail,
                "TLS 1.0 is prohibited",
            )],
            exceptions_applied: Vec::new(),
            summary: PolicySummary {
                total_checks: 1,
                passed: 0,
                failed: u32::from(overall_result == PolicyOverallResult::Fail),
                warnings: u32::from(overall_result == PolicyOverallResult::Warning),
                info: 0,
                overall_result,
            },
        }
    }
}
