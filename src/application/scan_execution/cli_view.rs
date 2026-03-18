use crate::application::scan_execution::post_processing::{
    ScanNoticeView, ScanPostProcessingView, ScanPostView,
};
use crate::application::scan_execution::section_views::{
    ScanExportView, ScanFeatureView, ScanFingerprintView, ScanPrimaryTlsView,
};
use crate::scanner::ScanResults;

pub struct ScanCliView<'a> {
    pub(crate) results: &'a ScanResults,
    pub(crate) post_processing: ScanPostProcessingView<'a>,
}

impl<'a> ScanCliView<'a> {
    pub fn results(&self) -> &'a ScanResults {
        self.results
    }

    pub fn has_protocol_results(&self) -> bool {
        !self.results.protocols.is_empty()
    }

    pub fn has_cipher_results(&self) -> bool {
        !self.results.ciphers.is_empty()
    }

    pub fn has_certificate_results(&self) -> bool {
        self.results.certificate_chain.is_some()
    }

    pub fn has_http_header_results(&self) -> bool {
        self.results.http_headers().is_some()
    }

    pub fn has_vulnerability_results(&self) -> bool {
        !self.results.vulnerabilities.is_empty()
    }

    pub fn has_client_simulation_results(&self) -> bool {
        self.results.client_simulations().is_some()
    }

    pub fn has_signature_results(&self) -> bool {
        self.results.signature_algorithms().is_some()
    }

    pub fn has_group_results(&self) -> bool {
        self.results.key_exchange_groups().is_some()
    }

    pub fn has_client_ca_results(&self) -> bool {
        self.results.client_cas().is_some()
    }

    pub fn has_intolerance_results(&self) -> bool {
        self.results.intolerance().is_some()
    }

    pub fn has_fingerprint_results(&self) -> bool {
        self.has_ja3_results() || self.has_ja3s_results() || self.has_jarm_results()
    }

    pub fn should_render_primary_tls_sections(&self) -> bool {
        self.has_protocol_results()
            || self.has_cipher_results()
            || self.has_certificate_results()
            || self.has_http_header_results()
            || self.has_vulnerability_results()
    }

    pub fn should_render_primary_tls_view(&self) -> bool {
        self.should_render_primary_tls_sections() && self.primary_tls_view().should_render()
    }

    pub fn should_render_feature_sections(&self) -> bool {
        self.has_client_simulation_results()
            || self.has_signature_results()
            || self.has_group_results()
            || self.has_client_ca_results()
            || self.has_intolerance_results()
    }

    pub fn should_render_feature_view(&self) -> bool {
        self.should_render_feature_sections() && self.feature_view().should_render()
    }

    pub fn should_render_fingerprint_and_summary_sections(&self) -> bool {
        self.has_fingerprint_results() || self.has_alpn_results() || self.has_rating_results()
    }

    pub fn should_render_fingerprint_view(&self) -> bool {
        self.should_render_fingerprint_and_summary_sections()
            && self.fingerprint_view().should_render()
    }

    pub fn has_ja3_results(&self) -> bool {
        self.results.ja3_fingerprint().is_some()
    }

    pub fn has_ja3s_results(&self) -> bool {
        self.results.ja3s_fingerprint().is_some()
    }

    pub fn has_jarm_results(&self) -> bool {
        self.results.jarm_fingerprint().is_some()
    }

    pub fn has_alpn_results(&self) -> bool {
        self.results.alpn_result().is_some()
    }

    pub fn has_rating_results(&self) -> bool {
        self.results.ssl_rating().is_some()
    }

    pub fn has_tls_results(&self) -> bool {
        self.has_protocol_results()
            || self.has_cipher_results()
            || self.has_certificate_results()
            || self.has_http_header_results()
            || self.has_vulnerability_results()
            || self.has_client_simulation_results()
            || self.has_signature_results()
            || self.has_group_results()
            || self.has_client_ca_results()
            || self.has_intolerance_results()
            || self.has_fingerprint_results()
            || self.has_alpn_results()
            || self.has_rating_results()
    }

    pub fn should_render_tls_sections(&self) -> bool {
        self.has_tls_results()
    }

    pub fn has_multi_ip_export_data(&self) -> bool {
        self.results.multi_ip_report.is_some()
    }

    pub fn post_processing(&self) -> &ScanPostProcessingView<'a> {
        &self.post_processing
    }

    pub fn has_post_processing(&self) -> bool {
        self.post_processing.has_compliance_report()
            || self.post_processing.has_policy_result()
            || self.post_processing.has_stored_scan()
    }

    pub fn should_fail_exit(&self) -> bool {
        self.post_processing.should_fail_exit()
    }

    pub fn should_render_post_processing(&self) -> bool {
        self.post_view().should_render()
    }

    pub fn should_skip_artifacts(&self) -> bool {
        self.should_fail_exit()
    }

    pub fn should_handle_artifacts(&self) -> bool {
        !self.should_skip_artifacts()
    }

    pub fn stored_scan_id(&self) -> Option<i64> {
        self.post_processing.stored_scan_id()
    }

    pub fn should_render_storage_notice(&self) -> bool {
        self.stored_scan_id().is_some()
    }

    pub fn should_render_summary_only(&self) -> bool {
        !self.should_render_tls_sections()
    }

    pub fn should_render_detailed_results(&self) -> bool {
        !self.should_render_summary_only()
    }

    pub fn should_render_results_summary_only(&self) -> bool {
        !self.should_render_detailed_results()
    }

    pub fn should_render_results(&self) -> bool {
        self.should_render_detailed_results() || self.should_render_summary_only()
    }

    pub fn should_render_results_summary(&self) -> bool {
        self.should_render_results()
    }

    pub fn has_any_exportable_results(&self) -> bool {
        self.has_tls_results() || self.has_multi_ip_export_data()
    }

    pub fn should_export_multi_ip_json(&self) -> bool {
        self.has_multi_ip_export_data()
    }

    pub fn should_build_export_plan(&self) -> bool {
        self.has_any_exportable_results()
    }

    pub fn should_export_artifacts(&self) -> bool {
        self.should_handle_artifacts() && self.should_build_export_plan()
    }

    pub fn should_render_post_scan_notices(&self) -> bool {
        self.notice_view().should_render_any_notice()
    }

    pub fn should_render_artifact_notices(&self) -> bool {
        self.should_render_post_scan_notices()
    }

    pub fn should_render_artifact_notices_for(&self, has_artifacts: bool) -> bool {
        self.should_render_artifact_notices() && has_artifacts
    }

    pub fn should_render_post_scan_notices_for(&self, has_artifacts: bool) -> bool {
        self.should_render_post_scan_notices()
            && self.should_render_artifact_notices_for(has_artifacts)
    }

    pub fn should_render_post_scan_export_spacing_for(
        &self,
        has_artifacts: bool,
        exported: bool,
    ) -> bool {
        self.should_render_post_scan_notices_for(has_artifacts)
            && self
                .notice_view()
                .should_render_export_spacing_for(exported)
    }

    pub fn stored_scan_id_for_post_scan_notices(&self, has_artifacts: bool) -> Option<i64> {
        self.should_render_post_scan_notices_for(has_artifacts)
            .then_some(self.notice_view().stored_scan_id_for_notice())
            .flatten()
    }

    pub fn stored_scan_id_for_artifact_notices(&self) -> Option<i64> {
        self.stored_scan_id_for_post_scan_notices(true)
    }

    pub fn should_render_post_scan_export_spacing(&self, exported: bool) -> bool {
        self.should_render_post_scan_export_spacing_for(true, exported)
    }

    pub fn export_view(&self) -> ScanExportView<'_> {
        ScanExportView {
            results: self.results,
            has_any_exportable_results: self.has_any_exportable_results(),
            should_export_multi_ip_json: self.should_export_multi_ip_json(),
        }
    }

    pub fn notice_view(&self) -> ScanNoticeView {
        ScanNoticeView {
            stored_scan_id: self.stored_scan_id(),
        }
    }

    pub fn post_view(&self) -> ScanPostView<'_> {
        ScanPostView {
            post_processing: &self.post_processing,
        }
    }

    pub fn primary_tls_view(&self) -> ScanPrimaryTlsView<'_> {
        ScanPrimaryTlsView {
            results: self.results,
        }
    }

    pub fn feature_view(&self) -> ScanFeatureView<'_> {
        ScanFeatureView {
            results: self.results,
        }
    }

    pub fn fingerprint_view(&self) -> ScanFingerprintView<'_> {
        ScanFingerprintView {
            results: self.results,
        }
    }
}
