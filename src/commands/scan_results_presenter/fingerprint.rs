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
        let cdn = view.cdn_detection();
        let load_balancer = view.load_balancer_info();
        if cdn.is_some() || load_balancer.is_some() {
            formatter.display_cdn_results(cdn, load_balancer);
        }
        if let Some(alpn) = view.alpn_results() {
            formatter.display_alpn_results(alpn);
        }
        if let Some(rating) = view.rating_results() {
            formatter.display_rating_results(rating);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScanResultsPresenter;
    use crate::Args;
    use crate::application::ScanFingerprintView;
    use crate::fingerprint::{
        CdnDetection, Ja3Fingerprint, Ja3sFingerprint, JarmFingerprint, LoadBalancerInfo,
    };
    use crate::output::ScannerFormatter;
    use crate::protocols::alpn::{AlpnReport, AlpnResult};
    use crate::rating::{Grade, RatingResult};
    use crate::scanner::{AdvancedResults, FingerprintResults, RatingResults, ScanResults};

    #[test]
    fn renders_all_available_fingerprint_and_summary_sections() {
        colored::control::set_override(false);
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);
        let presenter = ScanResultsPresenter::new(&args);
        let results = ScanResults {
            fingerprints: Some(FingerprintResults {
                ja3_fingerprint: Some(Ja3Fingerprint {
                    ja3_string: "771,4865,0,,".to_string(),
                    ja3_hash: "0123456789abcdef0123456789abcdef".to_string(),
                    ssl_version: 771,
                    ciphers: vec![4865],
                    extensions: vec![0],
                    curves: Vec::new(),
                    point_formats: Vec::new(),
                }),
                ja3_match: None,
                ja3s_fingerprint: Some(Ja3sFingerprint {
                    ja3s_string: "771,4865,0".to_string(),
                    ja3s_hash: "fedcba9876543210fedcba9876543210".to_string(),
                    ssl_version: 771,
                    cipher: 4865,
                    extensions: vec![0],
                }),
                ja3s_match: None,
                jarm_fingerprint: Some(JarmFingerprint {
                    hash: "a".repeat(62),
                    raw_responses: Vec::new(),
                    signature: None,
                }),
                ..Default::default()
            }),
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
                alpn_result: Some(AlpnReport {
                    alpn_enabled: true,
                    alpn_result: AlpnResult {
                        supported_protocols: vec!["h2".to_string()],
                        http2_supported: true,
                        http3_supported: false,
                        negotiated_protocol: Some("h2".to_string()),
                        details: Vec::new(),
                        inconclusive: false,
                    },
                    spdy_supported: false,
                    recommendations: Vec::new(),
                    inconclusive: false,
                }),
                cdn_detection: Some(CdnDetection {
                    is_cdn: true,
                    cdn_provider: Some("Example CDN".to_string()),
                    confidence: 1.0,
                    indicators: vec!["test".to_string()],
                }),
                load_balancer_info: Some(LoadBalancerInfo {
                    detected: true,
                    lb_type: Some("Example LB".to_string()),
                    sticky_sessions: false,
                    indicators: vec!["test".to_string()],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let view = ScanFingerprintView { results: &results };

        presenter.render_fingerprint_and_summary_sections(&formatter, &view);
    }

    #[test]
    fn skips_fingerprint_sections_when_no_results_are_available() {
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);
        let presenter = ScanResultsPresenter::new(&args);
        let results = ScanResults::default();
        let view = ScanFingerprintView { results: &results };

        presenter.render_fingerprint_and_summary_sections(&formatter, &view);
    }
}
