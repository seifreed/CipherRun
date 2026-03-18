mod feature;
mod fingerprint;
mod primary;

use crate::Args;
use crate::application::ScanCliView;

pub struct ScanResultsPresenter<'a> {
    args: &'a Args,
}

impl<'a> ScanResultsPresenter<'a> {
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub fn render(&self, cli_view: &ScanCliView<'_>) {
        use crate::output::ScannerFormatter;

        let results = cli_view.results();
        let formatter = ScannerFormatter::new(self.args);

        if cli_view.should_render_results_summary_only() {
            formatter.display_results_summary(results);
            return;
        }

        self.render_tls_sections(&formatter, cli_view);
        if cli_view.should_render_results_summary() {
            formatter.display_results_summary(results);
        }
    }

    fn render_tls_sections(
        &self,
        formatter: &crate::output::ScannerFormatter<'_>,
        cli_view: &ScanCliView<'_>,
    ) {
        if cli_view.should_render_primary_tls_view() {
            let primary_view = cli_view.primary_tls_view();
            self.render_primary_tls_sections(formatter, &primary_view);
        }
        if cli_view.should_render_feature_view() {
            let feature_view = cli_view.feature_view();
            self.render_feature_sections(formatter, &feature_view);
        }
        if cli_view.should_render_fingerprint_view() {
            let fingerprint_view = cli_view.fingerprint_view();
            self.render_fingerprint_and_summary_sections(formatter, &fingerprint_view);
        }
    }
}
