// PQC Migration Roadmap Generator
//
// Produces a prioritized 4-phase migration plan from scan results.

use crate::scanner::ScanResults;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoadmapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl RoadmapSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            RoadmapSeverity::Critical => "CRITICAL",
            RoadmapSeverity::High => "HIGH",
            RoadmapSeverity::Medium => "MEDIUM",
            RoadmapSeverity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub severity: RoadmapSeverity,
    pub phase: u8,
    pub title: String,
    pub action: String,
    pub timeline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRoadmap {
    pub target: String,
    pub steps: Vec<MigrationStep>,
}

pub struct RoadmapGenerator;

impl RoadmapGenerator {
    pub fn from_scan(results: &ScanResults) -> MigrationRoadmap {
        let mut steps = Vec::new();

        // Check for legacy protocols
        let has_sslv2 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::SSLv2) && p.supported);
        let has_sslv3 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::SSLv3) && p.supported);
        let has_tls10 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS10) && p.supported);
        let has_tls11 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS11) && p.supported);
        let has_tls13 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS13) && p.supported);

        if has_sslv2 || has_sslv3 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::Critical,
                phase: 1,
                title: "Disable SSLv2/SSLv3".to_string(),
                action: "Remove SSLv2 and SSLv3 support immediately — broken protocols vulnerable to POODLE/DROWN.".to_string(),
                timeline: "Immediate".to_string(),
            });
        }

        if has_tls10 || has_tls11 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 1,
                title: "Disable TLS 1.0 / TLS 1.1".to_string(),
                action: "Remove TLS 1.0 and TLS 1.1 support (deprecated by RFC 8996).".to_string(),
                timeline: "0-30 days".to_string(),
            });
        }

        // Check for PQC group support
        let has_pqc_group = results
            .advanced
            .as_ref()
            .and_then(|a| a.key_exchange_groups.as_ref())
            .map(|g| {
                g.groups
                    .iter()
                    .any(|grp| grp.supported && !grp.quantum_vulnerable)
            })
            .unwrap_or(false);

        if !has_pqc_group {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 2,
                title: "Deploy X25519MLKEM768 hybrid key exchange".to_string(),
                action: "Configure X25519MLKEM768 (IANA 0x11EC) as preferred TLS 1.3 key share. Cloudflare/Google already deploy this by default.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        if !has_tls13 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 2,
                title: "Enable TLS 1.3".to_string(),
                action: "TLS 1.3 is required for PQC hybrid key exchange groups.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        // Certificate RSA key size
        let rsa_small = results
            .certificate_chain
            .as_ref()
            .and_then(|c| c.chain.leaf())
            .and_then(|leaf| leaf.public_key_size)
            .map(|bits| bits < 3072)
            .unwrap_or(false);

        if rsa_small {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::Medium,
                phase: 2,
                title: "Upgrade RSA certificate key to ≥ 3072 bits".to_string(),
                action: "RSA-2048 provides ~112-bit classical security (acceptable under NIST SP 800-131A Rev. 3 through 2030); upgrade to RSA-3072 for the NIST post-2030 recommendation and FIPS-PQC-3.1 classical baseline.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        steps.push(MigrationStep {
            severity: RoadmapSeverity::Medium,
            phase: 3,
            title: "Plan hybrid PQC certificate migration".to_string(),
            action: "Monitor CA/Browser Forum for hybrid certificate issuance (ML-DSA + ECDSA dual-sig). Plan internal PKI migration timeline.".to_string(),
            timeline: "6-18 months".to_string(),
        });

        steps.push(MigrationStep {
            severity: RoadmapSeverity::Low,
            phase: 4,
            title: "Full PQC certificate deployment".to_string(),
            action: "Deploy pure ML-DSA or Falcon certificates when ecosystem (browsers, CAs, load balancers) fully supports them.".to_string(),
            timeline: "18+ months".to_string(),
        });

        MigrationRoadmap {
            target: results.target.clone(),
            steps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;
    use crate::protocols::{
        Protocol, ProtocolTestResult,
        groups::{GroupEnumerationResult, GroupType, KeyExchangeGroup},
    };
    use crate::scanner::{AdvancedResults, CertificateAnalysisResult, ScanResults};

    fn protocol(protocol: Protocol, supported: bool) -> ProtocolTestResult {
        ProtocolTestResult {
            protocol,
            supported,
            inconclusive: false,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }
    }

    fn certificate_results(key_size: Option<usize>) -> CertificateAnalysisResult {
        CertificateAnalysisResult {
            chain: CertificateChain {
                certificates: vec![CertificateInfo {
                    public_key_size: key_size,
                    ..CertificateInfo::default()
                }],
                chain_length: 1,
                chain_size_bytes: 0,
            },
            validation: ValidationResult {
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
        }
    }

    #[test]
    fn test_roadmap_empty_scan_has_pqc_steps() {
        let results = ScanResults::default();
        let roadmap = RoadmapGenerator::from_scan(&results);
        assert!(!roadmap.steps.is_empty());
        assert!(
            roadmap
                .steps
                .iter()
                .any(|s| s.title.contains("X25519MLKEM768"))
        );
    }

    #[test]
    fn roadmap_severity_labels_are_stable() {
        assert_eq!(RoadmapSeverity::Critical.label(), "CRITICAL");
        assert_eq!(RoadmapSeverity::High.label(), "HIGH");
        assert_eq!(RoadmapSeverity::Medium.label(), "MEDIUM");
        assert_eq!(RoadmapSeverity::Low.label(), "LOW");
    }

    #[test]
    fn roadmap_recommends_remediation_for_legacy_protocols_and_weak_key() {
        let mut results = ScanResults {
            target: "legacy.example.com:443".to_string(),
            protocols: vec![
                protocol(Protocol::SSLv2, true),
                protocol(Protocol::SSLv3, true),
                protocol(Protocol::TLS10, true),
                protocol(Protocol::TLS11, true),
                protocol(Protocol::TLS13, false),
            ],
            certificate_chain: Some(certificate_results(Some(2048))),
            ..ScanResults::default()
        };
        results.advanced = Some(AdvancedResults {
            key_exchange_groups: Some(GroupEnumerationResult {
                groups: vec![KeyExchangeGroup {
                    name: "P-256".to_string(),
                    iana_value: 23,
                    group_type: GroupType::EllipticCurve,
                    bits: 256,
                    supported: true,
                    quantum_vulnerable: true,
                }],
                measured: true,
                details: String::new(),
            }),
            ..AdvancedResults::default()
        });

        let roadmap = RoadmapGenerator::from_scan(&results);
        assert_eq!(roadmap.target, "legacy.example.com:443");
        assert_eq!(roadmap.steps.len(), 7);
        assert!(matches!(
            roadmap.steps[0].severity,
            RoadmapSeverity::Critical
        ));
        assert_eq!(roadmap.steps[0].phase, 1);
        assert_eq!(roadmap.steps[0].timeline, "Immediate");
        assert_eq!(roadmap.steps[1].title, "Disable TLS 1.0 / TLS 1.1");
        assert!(
            roadmap
                .steps
                .iter()
                .any(|step| { step.title.contains("X25519MLKEM768") && step.phase == 2 })
        );
        assert!(
            roadmap
                .steps
                .iter()
                .any(|step| step.title == "Enable TLS 1.3")
        );
        assert!(roadmap.steps.iter().any(|step| {
            step.title.contains("RSA certificate key") && step.severity.label() == "MEDIUM"
        }));
        assert_eq!(roadmap.steps[5].phase, 3);
        assert_eq!(roadmap.steps[6].phase, 4);
    }

    #[test]
    fn roadmap_skips_recommendations_for_supported_pqc_and_large_rsa_key() {
        let results = ScanResults {
            protocols: vec![
                protocol(Protocol::SSLv2, false),
                protocol(Protocol::SSLv3, false),
                protocol(Protocol::TLS10, false),
                protocol(Protocol::TLS11, false),
                protocol(Protocol::TLS13, true),
            ],
            certificate_chain: Some(certificate_results(Some(3072))),
            advanced: Some(AdvancedResults {
                key_exchange_groups: Some(GroupEnumerationResult {
                    groups: vec![KeyExchangeGroup {
                        name: "X25519MLKEM768".to_string(),
                        iana_value: 0x11ec,
                        group_type: GroupType::PostQuantum,
                        bits: 768,
                        supported: true,
                        quantum_vulnerable: false,
                    }],
                    measured: true,
                    details: String::new(),
                }),
                ..AdvancedResults::default()
            }),
            ..ScanResults::default()
        };

        let roadmap = RoadmapGenerator::from_scan(&results);
        assert_eq!(roadmap.steps.len(), 2);
        assert_eq!(roadmap.steps[0].phase, 3);
        assert_eq!(roadmap.steps[1].phase, 4);
    }
}
