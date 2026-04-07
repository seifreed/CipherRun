use crate::ciphers::tester::ProtocolCipherSummary;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::RatingResult;
use crate::scanner::inconsistency::InconsistencyDetails;
use crate::scanner::{CertificateAnalysisResult, ScanResults};
use crate::vulnerabilities::VulnerabilityResult;
use std::collections::{HashMap, HashSet};

/// Stable application-facing view for policy and compliance evaluation.
#[derive(Debug, Clone, Default)]
pub struct ScanAssessment {
    pub target: String,
    pub protocols: Vec<ProtocolTestResult>,
    pub any_supported_protocols: Vec<Protocol>,
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,
    pub certificate_chain: Option<CertificateAnalysisResult>,
    pub vulnerabilities: Vec<VulnerabilityResult>,
    pub rating: Option<RatingResult>,
}

impl ScanAssessment {
    pub fn from_scan_results(results: &ScanResults) -> Self {
        let mut any_supported_protocols: HashSet<Protocol> = results
            .protocols
            .iter()
            .filter(|protocol| protocol.supported)
            .map(|protocol| protocol.protocol)
            .collect();

        for inconsistency in results.scan_metadata.inconsistencies.iter().flatten() {
            if let InconsistencyDetails::Protocols { protocol, .. } = inconsistency.details {
                any_supported_protocols.insert(protocol);
            }
        }

        let mut any_supported_protocols: Vec<_> = any_supported_protocols.into_iter().collect();
        any_supported_protocols.sort();

        Self {
            target: results.target.clone(),
            protocols: results.protocols.clone(),
            any_supported_protocols,
            ciphers: results.ciphers.clone(),
            certificate_chain: results.certificate_chain.clone(),
            vulnerabilities: results.vulnerabilities.clone(),
            rating: results.ssl_rating().cloned(),
        }
    }

    pub fn ssl_rating(&self) -> Option<&RatingResult> {
        self.rating.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::Protocol;
    use crate::scanner::inconsistency::{Inconsistency, InconsistencyDetails, InconsistencyType};
    use crate::vulnerabilities::Severity;

    #[test]
    fn maps_target_from_scan_results() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };

        let assessment = ScanAssessment::from_scan_results(&results);
        assert_eq!(assessment.target, "example.com:443");
    }

    #[test]
    fn maps_protocols_supported_on_any_backend_from_inconsistencies() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_metadata: crate::scanner::ScanMetadata {
                inconsistencies: Some(vec![Inconsistency {
                    inconsistency_type: InconsistencyType::ProtocolSupport,
                    severity: Severity::Low,
                    description: "TLS 1.0 inconsistent".to_string(),
                    ips_affected: Vec::new(),
                    details: InconsistencyDetails::Protocols {
                        protocol: Protocol::TLS10,
                        ips_with_support: Vec::new(),
                        ips_without_support: Vec::new(),
                    },
                }]),
                ..Default::default()
            },
            ..Default::default()
        };

        let assessment = ScanAssessment::from_scan_results(&results);
        assert!(
            assessment
                .any_supported_protocols
                .contains(&Protocol::TLS10)
        );
    }
}
