use crate::scanner::ScanResults;
use crate::{Result, TlsError};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingChange {
    pub finding_id: String,
    pub previous_status: Option<String>,
    pub current_status: Option<String>,
    pub previous_severity: Option<String>,
    pub current_severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RatingSnapshot {
    pub grade: String,
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanDiff {
    pub target: String,
    pub protocols: SetDiff,
    pub ciphers: SetDiff,
    pub findings: Vec<FindingChange>,
    pub previous_certificate_fingerprint: Option<String>,
    pub current_certificate_fingerprint: Option<String>,
    pub previous_rating: Option<RatingSnapshot>,
    pub current_rating: Option<RatingSnapshot>,
}

impl ScanDiff {
    pub fn compare(previous: &ScanResults, current: &ScanResults) -> Result<Self> {
        if previous.target != current.target {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Cannot compare different targets: '{}' and '{}'",
                    previous.target, current.target
                ),
            });
        }

        Ok(Self {
            target: current.target.clone(),
            protocols: set_diff(protocols(previous), protocols(current)),
            ciphers: set_diff(ciphers(previous), ciphers(current)),
            findings: finding_changes(previous, current),
            previous_certificate_fingerprint: certificate_fingerprint(previous),
            current_certificate_fingerprint: certificate_fingerprint(current),
            previous_rating: rating(previous),
            current_rating: rating(current),
        })
    }

    pub fn has_changes(&self) -> bool {
        !self.protocols.added.is_empty()
            || !self.protocols.removed.is_empty()
            || !self.ciphers.added.is_empty()
            || !self.ciphers.removed.is_empty()
            || !self.findings.is_empty()
            || self.previous_certificate_fingerprint != self.current_certificate_fingerprint
            || self.previous_rating != self.current_rating
    }

    pub fn to_terminal(&self) -> String {
        if !self.has_changes() {
            return format!("No scan drift detected for {}", self.target);
        }

        let mut lines = vec![format!("Scan drift detected for {}", self.target)];
        push_set(&mut lines, "Protocols added", &self.protocols.added);
        push_set(&mut lines, "Protocols removed", &self.protocols.removed);
        push_set(&mut lines, "Ciphers added", &self.ciphers.added);
        push_set(&mut lines, "Ciphers removed", &self.ciphers.removed);
        for finding in &self.findings {
            lines.push(format!(
                "Finding {}: {} -> {}",
                finding.finding_id,
                finding.previous_status.as_deref().unwrap_or("missing"),
                finding.current_status.as_deref().unwrap_or("missing")
            ));
        }
        if self.previous_certificate_fingerprint != self.current_certificate_fingerprint {
            lines.push("Certificate fingerprint changed".to_string());
        }
        if self.previous_rating != self.current_rating {
            lines.push(format!(
                "Rating: {} -> {}",
                rating_label(self.previous_rating.as_ref()),
                rating_label(self.current_rating.as_ref())
            ));
        }
        lines.join("\n")
    }
}

fn protocols(results: &ScanResults) -> BTreeSet<String> {
    results
        .protocols
        .iter()
        .filter(|result| result.supported)
        .map(|result| format!("{:?}", result.protocol))
        .collect()
}

fn ciphers(results: &ScanResults) -> BTreeSet<String> {
    results
        .ciphers
        .iter()
        .flat_map(|(protocol, summary)| {
            summary
                .supported_ciphers
                .iter()
                .map(move |cipher| format!("{:?}:{}", protocol, cipher.iana_name))
        })
        .collect()
}

fn finding_changes(previous: &ScanResults, current: &ScanResults) -> Vec<FindingChange> {
    let snapshot = |results: &ScanResults| {
        results
            .vulnerabilities
            .iter()
            .map(|finding| {
                (
                    finding.finding_id().to_string(),
                    (
                        finding.status().as_str().to_string(),
                        format!("{:?}", finding.severity).to_ascii_lowercase(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let previous = snapshot(previous);
    let current = snapshot(current);
    previous
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|finding_id| {
            let before = previous.get(finding_id);
            let after = current.get(finding_id);
            (before != after).then(|| FindingChange {
                finding_id: finding_id.clone(),
                previous_status: before.map(|value| value.0.clone()),
                current_status: after.map(|value| value.0.clone()),
                previous_severity: before.map(|value| value.1.clone()),
                current_severity: after.map(|value| value.1.clone()),
            })
        })
        .collect()
}

fn certificate_fingerprint(results: &ScanResults) -> Option<String> {
    results
        .certificate_chain
        .as_ref()
        .and_then(|certificate| certificate.chain.leaf())
        .and_then(|leaf| leaf.fingerprint_sha256.clone())
}

fn rating(results: &ScanResults) -> Option<RatingSnapshot> {
    results.ssl_rating().map(|rating| RatingSnapshot {
        grade: rating.grade.to_string(),
        score: rating.score,
    })
}

fn set_diff(previous: BTreeSet<String>, current: BTreeSet<String>) -> SetDiff {
    SetDiff {
        added: current.difference(&previous).cloned().collect(),
        removed: previous.difference(&current).cloned().collect(),
    }
}

fn push_set(lines: &mut Vec<String>, label: &str, values: &[String]) {
    if !values.is_empty() {
        lines.push(format!("{label}: {}", values.join(", ")));
    }
}

fn rating_label(rating: Option<&RatingSnapshot>) -> String {
    rating
        .map(|rating| format!("{} ({})", rating.grade, rating.score))
        .unwrap_or_else(|| "missing".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::{CipherCounts, ProtocolCipherSummary};
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::rating::grader::Grade;
    use crate::rating::scoring::RatingResult;
    use crate::scanner::{CertificateAnalysisResult, RatingResults};
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};
    use std::collections::HashMap;

    fn test_protocol(protocol: Protocol, supported: bool) -> ProtocolTestResult {
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

    fn test_cipher(name: &str) -> CipherSuite {
        CipherSuite {
            hexcode: "002f".to_string(),
            openssl_name: name.to_string(),
            iana_name: name.to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "RSA".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES-128-CBC".to_string(),
            mac: "SHA256".to_string(),
            bits: 128,
            export: false,
        }
    }

    fn test_rating(grade: Grade, score: u8) -> RatingResults {
        RatingResults {
            ssl_rating: Some(RatingResult {
                grade,
                score,
                certificate_score: score,
                protocol_score: score,
                key_exchange_score: score,
                cipher_strength_score: score,
                warnings: Vec::new(),
            }),
        }
    }

    fn test_certificate(fingerprint: &str) -> CertificateAnalysisResult {
        CertificateAnalysisResult {
            chain: CertificateChain {
                certificates: vec![CertificateInfo {
                    fingerprint_sha256: Some(fingerprint.to_string()),
                    ..Default::default()
                }],
                chain_length: 1,
                chain_size_bytes: 1,
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
    fn compare_ignores_runtime_but_reports_security_drift() {
        let previous = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 10,
            protocols: vec![test_protocol(Protocol::TLS12, true)],
            ..Default::default()
        };
        let current = ScanResults {
            target: previous.target.clone(),
            scan_time_ms: 99,
            protocols: vec![
                test_protocol(Protocol::TLS12, true),
                test_protocol(Protocol::TLS13, true),
            ],
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Critical,
            }],
            ..Default::default()
        };

        let diff = ScanDiff::compare(&previous, &current).unwrap();
        assert_eq!(diff.protocols.added, ["TLS13"]);
        assert_eq!(
            diff.findings[0].current_status.as_deref(),
            Some("confirmed_vulnerable")
        );
        assert!(diff.has_changes());

        let unchanged = ScanDiff::compare(
            &previous,
            &ScanResults {
                scan_time_ms: 20,
                ..previous.clone()
            },
        )
        .unwrap();
        assert!(!unchanged.has_changes());
        assert_eq!(
            unchanged.to_terminal(),
            "No scan drift detected for example.com:443"
        );
    }

    #[test]
    fn compare_reports_cipher_finding_certificate_and_rating_changes() {
        let mut previous_ciphers = HashMap::new();
        previous_ciphers.insert(
            Protocol::TLS12,
            ProtocolCipherSummary {
                protocol: Protocol::TLS12,
                supported_ciphers: vec![test_cipher("AES128-SHA")],
                server_ordered: false,
                server_preference: Vec::new(),
                preferred_cipher: None,
                counts: CipherCounts::default(),
                avg_handshake_time_ms: None,
            },
        );
        let mut current_ciphers = HashMap::new();
        current_ciphers.insert(
            Protocol::TLS13,
            ProtocolCipherSummary {
                protocol: Protocol::TLS13,
                supported_ciphers: vec![test_cipher("TLS_AES_128_GCM_SHA256")],
                server_ordered: false,
                server_preference: Vec::new(),
                preferred_cipher: None,
                counts: CipherCounts::default(),
                avg_handshake_time_ms: None,
            },
        );

        let previous = ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![
                test_protocol(Protocol::TLS12, true),
                test_protocol(Protocol::TLS10, false),
            ],
            ciphers: previous_ciphers,
            certificate_chain: Some(test_certificate("old-fingerprint")),
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::High,
            }],
            rating: Some(test_rating(Grade::A, 95)),
            ..Default::default()
        };
        let current = ScanResults {
            target: previous.target.clone(),
            protocols: vec![test_protocol(Protocol::TLS13, true)],
            ciphers: current_ciphers,
            certificate_chain: Some(test_certificate("new-fingerprint")),
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: false,
                inconclusive: true,
                details: "inconclusive".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Medium,
            }],
            rating: Some(test_rating(Grade::B, 75)),
            ..Default::default()
        };

        let diff = ScanDiff::compare(&previous, &current).unwrap();
        assert_eq!(diff.protocols.added, ["TLS13"]);
        assert_eq!(diff.protocols.removed, ["TLS12"]);
        assert_eq!(diff.ciphers.added, ["TLS13:TLS_AES_128_GCM_SHA256"]);
        assert_eq!(diff.ciphers.removed, ["TLS12:AES128-SHA"]);
        assert_eq!(diff.findings.len(), 1);
        assert_eq!(
            diff.findings[0].previous_status.as_deref(),
            Some("confirmed_vulnerable")
        );
        assert_eq!(
            diff.findings[0].current_status.as_deref(),
            Some("inconclusive")
        );
        assert_eq!(diff.findings[0].previous_severity.as_deref(), Some("high"));
        assert_eq!(diff.findings[0].current_severity.as_deref(), Some("medium"));
        assert_eq!(
            diff.previous_certificate_fingerprint.as_deref(),
            Some("old-fingerprint")
        );
        assert_eq!(
            diff.current_certificate_fingerprint.as_deref(),
            Some("new-fingerprint")
        );
        assert_eq!(diff.previous_rating.as_ref().unwrap().grade, "A");
        assert_eq!(diff.current_rating.as_ref().unwrap().score, 75);

        let rendered = diff.to_terminal();
        assert!(rendered.contains("Protocols added: TLS13"));
        assert!(rendered.contains("Ciphers removed: TLS12:AES128-SHA"));
        assert!(rendered.contains("Finding CR-TLS-HEARTBLEED-001:"));
        assert!(rendered.contains("Certificate fingerprint changed"));
        assert!(rendered.contains("Rating: A (95) -> B (75)"));
    }

    #[test]
    fn compare_reports_added_and_removed_findings() {
        let previous = ScanResults {
            target: "example.com:443".to_string(),
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::Critical,
            }],
            ..Default::default()
        };
        let current = ScanResults {
            target: previous.target.clone(),
            rating: Some(test_rating(Grade::B, 75)),
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Ticketbleed,
                vulnerable: true,
                inconclusive: false,
                details: "confirmed".to_string(),
                cve: None,
                cwe: None,
                severity: Severity::High,
            }],
            ..Default::default()
        };

        let diff = ScanDiff::compare(&previous, &current).unwrap();

        assert_eq!(diff.findings.len(), 2);
        let added = diff
            .findings
            .iter()
            .find(|finding| finding.finding_id == "CR-TLS-TICKETBLEED-001")
            .unwrap();
        assert_eq!(added.previous_status, None);
        assert_eq!(
            added.current_status.as_deref(),
            Some("confirmed_vulnerable")
        );
        let removed = diff
            .findings
            .iter()
            .find(|finding| finding.finding_id == "CR-TLS-HEARTBLEED-001")
            .unwrap();
        assert_eq!(
            removed.previous_status.as_deref(),
            Some("confirmed_vulnerable")
        );
        assert_eq!(removed.current_status, None);

        let rendered = diff.to_terminal();
        assert!(
            rendered.contains("Finding CR-TLS-TICKETBLEED-001: missing -> confirmed_vulnerable")
        );
        assert!(
            rendered.contains("Finding CR-TLS-HEARTBLEED-001: confirmed_vulnerable -> missing")
        );
        assert!(rendered.contains("Rating: missing -> B (75)"));
    }

    #[test]
    fn compare_rejects_different_targets() {
        let previous = ScanResults {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        let current = ScanResults {
            target: "other.example:443".to_string(),
            ..Default::default()
        };

        let error = ScanDiff::compare(&previous, &current)
            .expect_err("scan drift cannot compare different targets");
        assert!(
            error
                .to_string()
                .contains("Cannot compare different targets")
        );
    }
}
