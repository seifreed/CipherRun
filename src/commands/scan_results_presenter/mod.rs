mod feature;
mod fingerprint;
mod primary;

use crate::Args;
use crate::application::ScanCliView;

pub struct ScanResultsPresenter<'a> {
    args: &'a Args,
}

impl<'a> ScanResultsPresenter<'a> {
    pub(super) fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub(super) fn render(&self, cli_view: &ScanCliView<'_>) {
        use crate::output::ScannerFormatter;

        let results = cli_view.results();
        let formatter = ScannerFormatter::new(self.args);
        let presentation_mode = self.args.output_presentation_mode();

        if presentation_mode.is_dns_only() {
            self.render_dns_only(results);
            return;
        }

        let summary_only = cli_view.should_render_results_summary_only();
        if summary_only {
            formatter.display_results_summary(results);
        } else {
            self.render_tls_sections(&formatter, cli_view);
        }

        if cli_view.should_render_results_summary() && !summary_only {
            formatter.display_results_summary(results);
        }
    }

    fn render_dns_only(&self, results: &crate::scanner::ScanResults) {
        let formatter = crate::output::ScannerFormatter::new(self.args);
        formatter.display_dns_only_results(results);
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

#[cfg(test)]
mod tests {
    use super::ScanResultsPresenter;
    use crate::Args;
    use crate::application::{ScanExecutionReport, ScanResults};
    use crate::pqc::{PqcLevel, PqcReadinessAssessment};
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::rating::{Grade, RatingResult};
    use crate::scanner::{AdvancedResults, RatingResults};

    #[test]
    fn render_routes_summary_only_and_dns_only_modes() {
        let results = ScanResults::default();
        let report = ScanExecutionReport::new(results, None, None, None);
        let cli_view = report.cli_view(false);

        let args = Args::default();
        assert!(cli_view.should_render_results_summary_only());
        ScanResultsPresenter::new(&args).render(&cli_view);

        let mut dns_args = Args::default();
        dns_args.cert_filters.dns_only = true;
        assert!(dns_args.output_presentation_mode().is_dns_only());
        ScanResultsPresenter::new(&dns_args).render(&cli_view);
    }

    #[test]
    fn render_routes_primary_feature_fingerprint_and_summary_sections() {
        let results = ScanResults {
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
            ciphers: std::collections::HashMap::from([(
                Protocol::TLS12,
                crate::ciphers::tester::ProtocolCipherSummary {
                    protocol: Protocol::TLS12,
                    supported_ciphers: Vec::new(),
                    server_ordered: false,
                    server_preference: Vec::new(),
                    preferred_cipher: None,
                    counts: Default::default(),
                    avg_handshake_time_ms: None,
                },
            )]),
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain: crate::certificates::parser::CertificateChain {
                    certificates: vec![crate::certificates::parser::CertificateInfo::default()],
                    chain_length: 1,
                    chain_size_bytes: 0,
                },
                validation: crate::certificates::validator::ValidationResult {
                    valid: true,
                    issues: Vec::new(),
                    trust_chain_valid: true,
                    hostname_match: true,
                    not_expired: true,
                    signature_valid: true,
                    trusted_ca: None,
                    platform_trust: None,
                },
                revocation: None,
            }),
            http: Some(crate::scanner::HttpResults {
                http_headers: Some(crate::http::tester::HeaderAnalysisResult {
                    headers: Default::default(),
                    issues: Vec::new(),
                    score: 100,
                    grade: crate::http::tester::SecurityGrade::A,
                    hsts_analysis: None,
                    hpkp_analysis: None,
                    cookie_analysis: None,
                    datetime_check: None,
                    banner_detection: None,
                    reverse_proxy_detection: None,
                    http_status_code: Some(200),
                    redirect_location: None,
                    redirect_chain: Vec::new(),
                    server_hostname: None,
                }),
            }),
            vulnerabilities: vec![crate::vulnerabilities::VulnerabilityResult {
                vuln_type: crate::vulnerabilities::VulnerabilityType::CRIME,
                vulnerable: false,
                inconclusive: false,
                details: "TLS compression is disabled".to_string(),
                cve: None,
                cwe: None,
                severity: crate::vulnerabilities::Severity::Info,
            }],
            rating: Some(RatingResults {
                ssl_rating: Some(RatingResult {
                    grade: Grade::A,
                    score: 95,
                    certificate_score: 95,
                    protocol_score: 95,
                    key_exchange_score: 95,
                    cipher_strength_score: 95,
                    warnings: Vec::new(),
                }),
            }),
            advanced: Some(AdvancedResults {
                client_simulations: Some(vec![crate::client_sim::simulator::ClientSimulationResult {
                    client_name: "test client".to_string(),
                    client_id: "test-client".to_string(),
                    success: true,
                    protocol: Some(Protocol::TLS12),
                    cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
                    error: None,
                    handshake_time_ms: Some(12),
                    alpn: None,
                    key_exchange: None,
                    forward_secrecy: true,
                    certificate_type: None,
                }]),
                signature_algorithms: Some(crate::protocols::signatures::SignatureEnumerationResult {
                    algorithms: Vec::new(),
                    inconclusive: false,
                }),
                key_exchange_groups: Some(crate::protocols::groups::GroupEnumerationResult {
                    groups: Vec::new(),
                    measured: true,
                    details: "test result".to_string(),
                }),
                client_cas: Some(crate::protocols::client_cas::ClientCAsResult {
                    cas: Vec::new(),
                    requires_client_auth: false,
                    inconclusive: false,
                }),
                intolerance: Some(crate::protocols::intolerance::IntoleranceTestResult::default()),
                pqc_readiness: Some(PqcReadinessAssessment {
                    score: 0,
                    level: PqcLevel::None,
                    pq_safe_groups: Vec::new(),
                    quantum_vulnerable_only: true,
                    hndl_risk: true,
                    recommendations: Vec::new(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ciphers_only = ScanResults {
            ciphers: results.ciphers.clone(),
            ..Default::default()
        };
        let report = ScanExecutionReport::new(results, None, None, None);
        let cli_view = report.cli_view(false);
        assert!(cli_view.should_render_primary_tls_view());
        assert!(cli_view.should_render_feature_view());
        assert!(cli_view.should_render_fingerprint_view());

        ScanResultsPresenter::new(&Args::default()).render(&cli_view);

        let report = ScanExecutionReport::new(ciphers_only, None, None, None);
        ScanResultsPresenter::new(&Args::default()).render(&report.cli_view(false));
    }

    #[test]
    fn render_feature_only_results_without_primary_tls_sections() {
        let results = ScanResults {
            advanced: Some(AdvancedResults {
                intolerance: Some(crate::protocols::intolerance::IntoleranceTestResult::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let report = ScanExecutionReport::new(results, None, None, None);
        let cli_view = report.cli_view(false);

        assert!(!cli_view.should_render_primary_tls_view());
        assert!(cli_view.should_render_feature_view());
        ScanResultsPresenter::new(&Args::default()).render(&cli_view);

        let results = ScanResults {
            advanced: Some(AdvancedResults {
                client_simulations: Some(Vec::new()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let report = ScanExecutionReport::new(results, None, None, None);
        ScanResultsPresenter::new(&Args::default()).render(&report.cli_view(false));
    }
}
