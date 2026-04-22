use super::ScanResultsPresenter;
use crate::application::ScanFeatureView;

impl ScanResultsPresenter<'_> {
    pub(super) fn render_feature_sections(
        &self,
        formatter: &crate::output::ScannerFormatter<'_>,
        view: &ScanFeatureView<'_>,
    ) {
        if let Some(sims) = view.client_simulations() {
            formatter.display_client_simulation_results(sims);
        }
        if let Some(sigs) = view.signature_results() {
            formatter.display_signature_results(sigs);
        }
        if let Some(groups) = view.group_results() {
            formatter.display_group_results(groups);
        }
        if let Some(cas) = view.client_ca_results() {
            formatter.display_client_cas_results(cas);
        }
        if let Some(intolerance) = view.intolerance_results() {
            formatter.display_intolerance_results(intolerance);
        }
        if let Some(pqc) = view.pqc_readiness() {
            formatter.display_pqc_readiness_results(pqc);
        }
    }
}
