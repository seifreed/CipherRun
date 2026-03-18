use super::ScanResultsPresenter;
use crate::application::ScanFingerprintView;

impl ScanResultsPresenter<'_> {
    pub(super) fn render_fingerprint_and_summary_sections(
        &self,
        formatter: &crate::output::ScannerFormatter<'_>,
        view: &ScanFingerprintView<'_>,
    ) {
        if let Some((ja3, ja3_match)) = view.ja3_results() {
            formatter.display_ja3_results(ja3, ja3_match);
        }
        if let Some((ja3s, ja3s_match)) = view.ja3s_results() {
            formatter.display_ja3s_results(ja3s, ja3s_match);
        }
        if let Some(jarm) = view.jarm_results() {
            formatter.display_jarm_results(jarm);
        }
        if let Some(alpn) = view.alpn_results() {
            formatter.display_alpn_results(alpn);
        }
        if let Some(rating) = view.rating_results() {
            formatter.display_rating_results(rating);
        }
    }
}
