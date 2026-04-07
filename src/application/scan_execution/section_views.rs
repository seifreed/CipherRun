use crate::application::ScanResults;
use crate::scanner::CertificateAnalysisResult;

pub struct ScanPrimaryTlsView<'a> {
    pub(crate) results: &'a ScanResults,
}

pub struct ScanFeatureView<'a> {
    pub(crate) results: &'a ScanResults,
}

pub struct ScanFingerprintView<'a> {
    pub(crate) results: &'a ScanResults,
}

pub struct ScanExportView<'a> {
    pub(crate) results: &'a ScanResults,
    pub(crate) has_any_exportable_results: bool,
    pub(crate) should_export_multi_ip_json: bool,
}

impl<'a> ScanExportView<'a> {
    pub fn results(&self) -> &'a ScanResults {
        self.results
    }

    pub fn has_exportable_results(&self) -> bool {
        self.has_any_exportable_results
    }

    pub fn should_build_export_plan(&self) -> bool {
        self.has_exportable_results()
    }

    pub fn has_multi_ip_export_data(&self) -> bool {
        self.should_export_multi_ip_json
    }

    pub fn should_export_multi_ip_json(&self) -> bool {
        self.has_multi_ip_export_data()
    }
}

impl<'a> ScanPrimaryTlsView<'a> {
    pub fn should_render(&self) -> bool {
        self.has_protocol_results()
            || self.has_cipher_results()
            || self.has_certificate_results()
            || self.has_http_header_results()
            || self.has_vulnerability_results()
    }

    pub fn protocols(&self) -> Option<&'a [crate::protocols::ProtocolTestResult]> {
        (!self.results.protocols.is_empty()).then_some(&self.results.protocols)
    }

    pub fn ciphers(
        &self,
    ) -> Option<
        &'a std::collections::HashMap<
            crate::protocols::Protocol,
            crate::ciphers::tester::ProtocolCipherSummary,
        >,
    > {
        (!self.results.ciphers.is_empty()).then_some(&self.results.ciphers)
    }

    pub fn certificate_results(&self) -> Option<&'a CertificateAnalysisResult> {
        self.results.certificate_chain.as_ref()
    }

    pub fn http_header_results(&self) -> Option<&'a crate::http::tester::HeaderAnalysisResult> {
        self.results.http_headers()
    }

    pub fn vulnerabilities(&self) -> Option<&'a Vec<crate::vulnerabilities::VulnerabilityResult>> {
        (!self.results.vulnerabilities.is_empty()).then_some(&self.results.vulnerabilities)
    }

    fn has_protocol_results(&self) -> bool {
        !self.results.protocols.is_empty()
    }

    fn has_cipher_results(&self) -> bool {
        !self.results.ciphers.is_empty()
    }

    fn has_certificate_results(&self) -> bool {
        self.results.certificate_chain.is_some()
    }

    fn has_http_header_results(&self) -> bool {
        self.results.http_headers().is_some()
    }

    fn has_vulnerability_results(&self) -> bool {
        !self.results.vulnerabilities.is_empty()
    }
}

impl<'a> ScanFeatureView<'a> {
    pub fn should_render(&self) -> bool {
        self.client_simulations().is_some()
            || self.signature_results().is_some()
            || self.group_results().is_some()
            || self.client_ca_results().is_some()
            || self.intolerance_results().is_some()
    }

    pub fn client_simulations(
        &self,
    ) -> Option<&'a Vec<crate::client_sim::simulator::ClientSimulationResult>> {
        self.results.client_simulations()
    }

    pub fn signature_results(
        &self,
    ) -> Option<&'a crate::protocols::signatures::SignatureEnumerationResult> {
        self.results.signature_algorithms()
    }

    pub fn group_results(&self) -> Option<&'a crate::protocols::groups::GroupEnumerationResult> {
        self.results.key_exchange_groups()
    }

    pub fn client_ca_results(&self) -> Option<&'a crate::protocols::client_cas::ClientCAsResult> {
        self.results.client_cas()
    }

    pub fn intolerance_results(
        &self,
    ) -> Option<&'a crate::protocols::intolerance::IntoleranceTestResult> {
        self.results.intolerance()
    }
}

impl<'a> ScanFingerprintView<'a> {
    pub fn should_render(&self) -> bool {
        self.ja3_results().is_some()
            || self.ja3s_results().is_some()
            || self.jarm_results().is_some()
            || self.alpn_results().is_some()
            || self.rating_results().is_some()
    }

    pub fn ja3_results(
        &self,
    ) -> Option<(
        &'a crate::fingerprint::Ja3Fingerprint,
        Option<&'a crate::fingerprint::Ja3Signature>,
    )> {
        self.results
            .ja3_fingerprint()
            .map(|ja3| (ja3, self.results.ja3_match()))
    }

    pub fn ja3s_results(
        &self,
    ) -> Option<(
        &'a crate::fingerprint::Ja3sFingerprint,
        Option<&'a crate::fingerprint::Ja3sSignature>,
    )> {
        self.results
            .ja3s_fingerprint()
            .map(|ja3s| (ja3s, self.results.ja3s_match()))
    }

    pub fn jarm_results(&self) -> Option<&'a crate::fingerprint::JarmFingerprint> {
        self.results.jarm_fingerprint()
    }

    pub fn alpn_results(&self) -> Option<&'a crate::protocols::alpn::AlpnReport> {
        self.results.alpn_result()
    }

    pub fn rating_results(&self) -> Option<&'a crate::rating::RatingResult> {
        self.results.ssl_rating()
    }
}
