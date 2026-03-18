use super::CommandExit;
use crate::application::ScanPostView;
use crate::{Args, Result};

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
        if post_view.should_return_failure_exit() && outcome.exit.code() == 0 {
            return Ok(CommandExit::failure(1));
        }

        Ok(outcome.exit)
    }

    fn render_outcome(&self, post_view: &ScanPostView<'_>) -> Result<ScanPostProcessingOutcome> {
        if let Some(exit) = self.render_compliance_section(post_view)? {
            return Ok(ScanPostProcessingOutcome { exit });
        }
        if let Some(exit) = self.render_policy_section(post_view)? {
            return Ok(ScanPostProcessingOutcome { exit });
        }

        Ok(ScanPostProcessingOutcome {
            exit: CommandExit::success(),
        })
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

        println!("\n{}", "Evaluating Compliance...".cyan().bold());

        match self.args.compliance.format.to_lowercase().as_str() {
            "json" => {
                let json = Reporter::to_json(compliance_report, self.args.output.json_pretty)?;
                println!("{}", json);
            }
            "csv" => {
                let csv = Reporter::to_csv(compliance_report)?;
                println!("{}", csv);
            }
            "html" => {
                let html = Reporter::to_html(compliance_report)?;
                println!("{}", html);
            }
            _ => {
                let terminal_output = Reporter::to_terminal(compliance_report);
                println!("{}", terminal_output);
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
}
