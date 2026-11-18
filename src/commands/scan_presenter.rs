use super::CommandExit;
use super::scan_exporter::{ScanExportOutcome, ScanExporter};
use super::scan_notice_presenter::ScanNoticePresenter;
use super::scan_post_presenter::ScanPostPresenter;
use super::scan_results_presenter::ScanResultsPresenter;
use crate::application::{ScanCliView, ScanExecutionReport};
use crate::{Args, Result};

struct ScanArtifactsOutcome {
    export_outcome: ScanExportOutcome,
}

struct ScanPresentationOutcome {
    exit: CommandExit,
    artifacts: Option<ScanArtifactsOutcome>,
}

pub(super) struct ScanPresenter<'a> {
    args: &'a Args,
}

impl<'a> ScanPresenter<'a> {
    pub(super) fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub(super) fn present(&self, report: &'a ScanExecutionReport) -> Result<CommandExit> {
        let cli_view = report.cli_view(self.args.compliance.enforce);
        self.render_scan_results(&cli_view);
        let outcome = self.present_post_scan_sections(&cli_view)?;
        self.render_post_scan_notices(&cli_view, outcome.artifacts.as_ref());
        self.export_hello_messages(report)?;

        Ok(outcome.exit)
    }

    /// Export captured raw Client/Server Hello bytes when `--export-hello` is set,
    /// delegating the filesystem write to the dedicated exporter.
    fn export_hello_messages(&self, report: &'a ScanExecutionReport) -> Result<()> {
        ScanExporter::new(self.args).export_hellos(report.results())
    }

    fn present_post_scan_sections(
        &self,
        cli_view: &'a ScanCliView<'_>,
    ) -> Result<ScanPresentationOutcome> {
        let exit = self.render_post_processing(cli_view)?;
        if !cli_view.should_handle_artifacts() {
            return Ok(ScanPresentationOutcome {
                exit,
                artifacts: None,
            });
        }

        let artifacts = self.handle_artifacts(cli_view)?;
        Ok(ScanPresentationOutcome {
            exit,
            artifacts: Some(artifacts),
        })
    }

    fn handle_artifacts(&self, cli_view: &'a ScanCliView<'_>) -> Result<ScanArtifactsOutcome> {
        let export_outcome = self.export_results(cli_view)?;
        Ok(ScanArtifactsOutcome { export_outcome })
    }

    pub(super) fn render_scan_results(&self, cli_view: &ScanCliView<'_>) {
        if self.args.output.quiet {
            return;
        }
        if cli_view.should_render_results() {
            ScanResultsPresenter::new(self.args).render(cli_view);
        }
    }

    fn render_post_processing(&self, cli_view: &ScanCliView<'_>) -> Result<CommandExit> {
        let post_view = cli_view.post_view();

        if self.args.output.quiet {
            return Ok(ScanPostPresenter::new(self.args).exit_for_post_view(&post_view));
        }
        if !cli_view.should_render_post_processing() {
            return Ok(CommandExit::success());
        }

        ScanPostPresenter::new(self.args).render(&post_view)
    }

    fn render_post_scan_notices(
        &self,
        cli_view: &ScanCliView<'_>,
        artifacts: Option<&ScanArtifactsOutcome>,
    ) {
        if self.args.output.quiet {
            return;
        }
        if !cli_view.should_render_post_scan_notices_for(artifacts.is_some()) {
            return;
        }

        let notices = ScanNoticePresenter::new();

        if let Some(scan_id) = cli_view.stored_scan_id_for_artifact_notices() {
            notices.render_storage_notice(Some(scan_id));
        }

        if let Some(artifacts) = artifacts
            && cli_view.should_render_post_scan_export_spacing(artifacts.export_outcome.exported())
        {
            notices.render_export_spacing(true);
        }
    }

    pub(super) fn export_results(
        &self,
        cli_view: &'a ScanCliView<'_>,
    ) -> Result<ScanExportOutcome> {
        if !cli_view.should_export_artifacts() {
            return Ok(ScanExportOutcome::none());
        }

        let export_view = cli_view.export_view();
        let exporter = ScanExporter::new(self.args);
        let plan = exporter.build_plan_from_view(export_view)?;
        if !plan.has_export_targets() {
            return Ok(ScanExportOutcome::none());
        }

        exporter.export(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::ScanPresenter;
    use crate::Args;
    use crate::application::{ScanExecutionReport, ScanResults};
    use crate::protocols::{Protocol, ProtocolTestResult};

    fn report(results: ScanResults, stored_scan_id: Option<i64>) -> ScanExecutionReport {
        ScanExecutionReport::new(results, None, None, stored_scan_id)
    }

    fn protocol_results() -> ScanResults {
        ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn present_handles_a_local_scan_report_without_optional_sections() {
        let args = Args::default();
        let report = report(ScanResults::default(), None);

        let exit = ScanPresenter::new(&args).present(&report).unwrap();

        assert!(exit.is_success());
    }

    #[test]
    fn present_in_quiet_mode_skips_terminal_results_and_notices() {
        let mut args = Args::default();
        args.output.quiet = true;
        let report = report(ScanResults::default(), Some(42));

        let exit = ScanPresenter::new(&args).present(&report).unwrap();

        assert!(exit.is_success());
    }

    #[test]
    fn present_exports_results_to_the_requested_json_file() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("scan.json");
        let mut args = Args::default();
        args.output.json = Some(output_path.clone());
        let report = report(protocol_results(), None);

        let exit = ScanPresenter::new(&args).present(&report).unwrap();

        assert!(exit.is_success());
        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output_path).unwrap()).unwrap();
        assert_eq!(exported["target"], "example.com:443");
    }
}
