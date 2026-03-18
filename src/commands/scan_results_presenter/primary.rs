use super::ScanResultsPresenter;
use crate::application::ScanPrimaryTlsView;

impl ScanResultsPresenter<'_> {
    pub(super) fn render_primary_tls_sections(
        &self,
        formatter: &crate::output::ScannerFormatter<'_>,
        view: &ScanPrimaryTlsView<'_>,
    ) {
        if let Some(protocols) = view.protocols() {
            formatter.display_protocol_results(protocols);
        }
        if let Some(ciphers) = view.ciphers() {
            formatter.display_cipher_results(ciphers);
        }
        if let Some(cert_data) = view.certificate_results() {
            formatter.display_certificate_results(cert_data);
        }
        if let Some(headers) = view.http_header_results() {
            formatter.display_http_headers_results(headers);
        }
        if let Some(vulnerabilities) = view.vulnerabilities() {
            formatter.display_vulnerability_results(vulnerabilities);
        }
    }
}
