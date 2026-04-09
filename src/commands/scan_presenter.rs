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

pub struct ScanPresenter<'a> {
    args: &'a Args,
}

impl<'a> ScanPresenter<'a> {
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub fn present(&self, report: &'a ScanExecutionReport) -> Result<CommandExit> {
        let cli_view = report.cli_view(self.args.compliance.enforce);
        self.render_scan_results(&cli_view);
        let outcome = self.present_post_scan_sections(&cli_view)?;
        self.render_post_scan_notices(&cli_view, outcome.artifacts.as_ref());

        Ok(outcome.exit)
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

    pub fn render_scan_results(&self, cli_view: &ScanCliView<'_>) {
        if cli_view.should_render_results() {
            ScanResultsPresenter::new(self.args).render(cli_view);
        }
    }

    fn render_post_processing(&self, cli_view: &ScanCliView<'_>) -> Result<CommandExit> {
        if !cli_view.should_render_post_processing() {
            return Ok(CommandExit::success());
        }
        let post_view = cli_view.post_view();
        ScanPostPresenter::new(self.args).render(&post_view)
    }

    fn render_post_scan_notices(
        &self,
        cli_view: &ScanCliView<'_>,
        artifacts: Option<&ScanArtifactsOutcome>,
    ) {
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

    pub fn export_results(&self, cli_view: &'a ScanCliView<'_>) -> Result<ScanExportOutcome> {
        if !cli_view.should_export_artifacts() {
            return Ok(ScanExportOutcome::none());
        }

        let export_view = cli_view.export_view();
        let exporter = ScanExporter::new(self.args);
        let plan = exporter.build_plan_from_view(export_view);
        if !plan.has_export_targets() {
            return Ok(ScanExportOutcome::none());
        }

        exporter.export(plan)
    }
}
