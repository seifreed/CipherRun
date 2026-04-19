// Compliance checkers - Rule evaluation logic

use crate::Result;
use crate::application::ScanAssessment;
use crate::certificates::validator::parse_cert_date;
use crate::compliance::{Rule, Severity, Violation};
use chrono::Utc;

/// Compliance checker for evaluating rules against scan results
pub struct ComplianceChecker;

impl ComplianceChecker {
    /// Check protocol version compliance
    pub fn check_protocols(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        for protocol_result in &results.protocols {
            if !protocol_result.supported {
                continue;
            }

            let protocol_name = protocol_result.protocol.to_string();

            // Check if protocol is in denied list
            if rule.is_denied(&protocol_name) {
                violations.push(Violation {
                    violation_type: "Prohibited Protocol".to_string(),
                    description: format!(
                        "{} is prohibited by this compliance framework",
                        protocol_name
                    ),
                    evidence: format!("Server accepts {} connections", protocol_name),
                    severity: Severity::Critical,
                });
            }
            // Check if protocol is NOT in allowed list (when allow list is specified)
            else if !rule.allowed.is_empty() && !rule.is_allowed(&protocol_name) {
                violations.push(Violation {
                    violation_type: "Non-Compliant Protocol".to_string(),
                    description: format!("{} is not in the allowed protocol list", protocol_name),
                    evidence: format!("Server accepts {} connections", protocol_name),
                    severity: Severity::High,
                });
            }
        }

        // Check that at least one allowed protocol is supported.
        // If none of the allowed protocols are available, flag a violation.
        if !rule.allowed.is_empty() {
            let any_allowed_supported = rule.allowed.iter().any(|allowed_protocol| {
                results
                    .protocols
                    .iter()
                    .any(|p| p.supported && p.protocol.to_string() == *allowed_protocol)
            });

            if !any_allowed_supported {
                violations.push(Violation {
                    violation_type: "Missing Required Protocol".to_string(),
                    description: format!(
                        "None of the required protocols are supported: {}",
                        rule.allowed.join(", ")
                    ),
                    evidence: "No allowed protocol found in scan results".to_string(),
                    severity: Severity::High,
                });
            }
        }

        Ok(violations)
    }

    /// Check cipher suite compliance
    pub fn check_ciphers(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        for (protocol, cipher_summary) in &results.ciphers {
            for cipher in &cipher_summary.supported_ciphers {
                let cipher_name = &cipher.iana_name;
                let openssl_name = &cipher.openssl_name;

                // Check denied patterns
                if rule.matches_denied_pattern(cipher_name)
                    || rule.matches_denied_pattern(openssl_name)
                {
                    violations.push(Violation {
                        violation_type: "Prohibited Cipher Suite".to_string(),
                        description: format!(
                            "Weak or prohibited cipher suite detected for {}",
                            protocol
                        ),
                        evidence: format!("{} ({})", cipher_name, openssl_name),
                        severity: Severity::Critical,
                    });
                } else if rule.is_denied(cipher_name) || rule.is_denied(openssl_name) {
                    // Check if cipher is explicitly denied (only if not already caught by pattern)
                    violations.push(Violation {
                        violation_type: "Prohibited Cipher Suite".to_string(),
                        description: format!("Explicitly prohibited cipher for {}", protocol),
                        evidence: format!("{} ({})", cipher_name, openssl_name),
                        severity: Severity::Critical,
                    });
                } else {
                    let fails_allowed_list = !rule.allowed.is_empty()
                        && !rule.allowed.contains(cipher_name)
                        && !rule.allowed.contains(openssl_name);
                    let fails_allowed_patterns = !rule.allowed_patterns.is_empty()
                        && !rule.matches_allowed_pattern(cipher_name)
                        && !rule.matches_allowed_pattern(openssl_name);

                    // Emit one violation only when the cipher is rejected by every configured list.
                    // A cipher accepted by either allowed or allowed_patterns is compliant.
                    let should_violate = match (fails_allowed_list, fails_allowed_patterns) {
                        (true, true) => true,
                        (true, false) if rule.allowed_patterns.is_empty() => true,
                        (false, true) if rule.allowed.is_empty() => true,
                        _ => false,
                    };

                    if should_violate {
                        violations.push(Violation {
                            violation_type: "Non-Compliant Cipher Suite".to_string(),
                            description: format!(
                                "Cipher not in allowed list or patterns for {}",
                                protocol
                            ),
                            evidence: format!("{} ({})", cipher_name, openssl_name),
                            severity: Severity::High,
                        });
                    }
                }
            }
        }

        Ok(violations)
    }

    /// Check certificate key size compliance
    pub fn check_key_size(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(cert_analysis) = &results.certificate_chain
            && let Some(leaf_cert) = cert_analysis.chain.leaf()
            && let Some(key_size) = leaf_cert.public_key_size
        {
            let key_algo = leaf_cert.public_key_algorithm.to_lowercase();

            // Check RSA key size
            if key_algo.contains("rsa")
                && let Some(min_rsa_bits) = rule.min_rsa_bits
                && (key_size as u32) < min_rsa_bits
            {
                violations.push(Violation {
                    violation_type: "Insufficient Key Size".to_string(),
                    description: format!(
                        "RSA key size {} bits is below minimum required {} bits",
                        key_size, min_rsa_bits
                    ),
                    evidence: format!("Certificate uses {}-bit RSA key", key_size),
                    severity: Severity::High,
                });
            }

            // Check ECC key size
            if (key_algo.starts_with("ec") || key_algo.contains("ecdsa"))
                && let Some(min_ecc_bits) = rule.min_ecc_bits
                && (key_size as u32) < min_ecc_bits
            {
                violations.push(Violation {
                    violation_type: "Insufficient Key Size".to_string(),
                    description: format!(
                        "ECC key size {} bits is below minimum required {} bits",
                        key_size, min_ecc_bits
                    ),
                    evidence: format!("Certificate uses {}-bit ECC key", key_size),
                    severity: Severity::High,
                });
            }
        }

        Ok(violations)
    }

    /// Check signature algorithm compliance
    pub fn check_signature(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(cert_analysis) = &results.certificate_chain
            && let Some(leaf_cert) = cert_analysis.chain.leaf()
        {
            let sig_algo = leaf_cert.signature_algorithm.to_lowercase();

            // Check if signature algorithm is denied (exact match, sig_algo already lowercased)
            if rule.denied.iter().any(|d| sig_algo == d.to_lowercase()) {
                violations.push(Violation {
                    violation_type: "Prohibited Signature Algorithm".to_string(),
                    description: format!(
                        "Certificate uses prohibited signature algorithm: {}",
                        leaf_cert.signature_algorithm
                    ),
                    evidence: format!("Signature algorithm: {}", leaf_cert.signature_algorithm),
                    severity: Severity::High,
                });
            }

            // If already denied, skip the allowed-list check to avoid double-counting
            if !violations.is_empty() {
                return Ok(violations);
            }

            // Check if signature algorithm is in allowed list
            if !rule.allowed.is_empty() {
                let mut is_allowed = false;
                for allowed in &rule.allowed {
                    if sig_algo == allowed.to_lowercase() {
                        is_allowed = true;
                        break;
                    }
                }

                if !is_allowed {
                    violations.push(Violation {
                        violation_type: "Non-Compliant Signature Algorithm".to_string(),
                        description: format!(
                            "Certificate signature algorithm not in allowed list: {}",
                            leaf_cert.signature_algorithm
                        ),
                        evidence: format!("Signature algorithm: {}", leaf_cert.signature_algorithm),
                        severity: Severity::Medium,
                    });
                }
            }
        }

        Ok(violations)
    }

    /// Check forward secrecy compliance
    pub fn check_forward_secrecy(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        let required = rule.required.unwrap_or(false);
        if !required {
            return Ok(violations);
        }

        for (protocol, cipher_summary) in &results.ciphers {
            // Collect all ciphers without forward secrecy for this protocol
            let non_fs_ciphers: Vec<_> = cipher_summary
                .supported_ciphers
                .iter()
                .filter(|cipher| {
                    // TLS 1.3 ciphers (e.g. TLS_AES_128_GCM_SHA256) inherently
                    // require forward secrecy by protocol design — no key-exchange
                    // algorithm appears in the name.
                    let is_tls13_cipher = cipher.protocol.contains("TLS13")
                        || cipher.protocol.contains("TLSv1.3")
                        || cipher.protocol.contains("TLS 1.3")
                        || cipher.iana_name.starts_with("TLS_AES_")
                        || cipher.iana_name.starts_with("TLS_CHACHA20_");
                    let has_fs = is_tls13_cipher
                        || cipher.iana_name.contains("_ECDHE_")
                        || cipher.iana_name.contains("_DHE_")
                        || cipher.openssl_name.starts_with("ECDHE-")
                        || cipher.openssl_name.starts_with("DHE-");
                    !has_fs
                })
                .collect();

            // Only create one violation per protocol, listing all non-FS ciphers
            if !non_fs_ciphers.is_empty() {
                let cipher_list: Vec<String> =
                    non_fs_ciphers.iter().map(|c| c.iana_name.clone()).collect();

                violations.push(Violation {
                    violation_type: "Missing Forward Secrecy".to_string(),
                    description: format!(
                        "{} cipher suite(s) without forward secrecy enabled for {}",
                        non_fs_ciphers.len(),
                        protocol
                    ),
                    evidence: format!("Non-FS ciphers: {}", cipher_list.join(", ")),
                    severity: Severity::High,
                });
            }
        }

        Ok(violations)
    }

    /// Check certificate validation compliance
    pub fn check_cert_validation(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(cert_analysis) = &results.certificate_chain {
            let validation = &cert_analysis.validation;

            // Check if valid chain is required
            if rule.require_valid_chain.unwrap_or(false) && !validation.trust_chain_valid {
                violations.push(Violation {
                    violation_type: "Invalid Certificate Chain".to_string(),
                    description: "Certificate chain validation failed".to_string(),
                    evidence: "Trust chain is not valid".to_string(),
                    severity: Severity::Critical,
                });
            }

            // Check if unexpired certificate is required
            if rule.require_unexpired.unwrap_or(false) && !validation.not_expired {
                violations.push(Violation {
                    violation_type: "Expired Certificate".to_string(),
                    description: "Certificate has expired".to_string(),
                    evidence: "Certificate is past its expiration date".to_string(),
                    severity: Severity::Critical,
                });
            }

            // Check if hostname match is required
            if rule.require_hostname_match.unwrap_or(false) && !validation.hostname_match {
                violations.push(Violation {
                    violation_type: "Hostname Mismatch".to_string(),
                    description: "Certificate hostname does not match".to_string(),
                    evidence: "Certificate subject/SAN does not match target hostname".to_string(),
                    severity: Severity::High,
                });
            }
        } else {
            // No certificate analysis available
            if rule.require_valid_chain.unwrap_or(false) {
                violations.push(Violation {
                    violation_type: "Missing Certificate".to_string(),
                    description: "No certificate information available".to_string(),
                    evidence: "Certificate analysis was not performed".to_string(),
                    severity: Severity::High,
                });
            }
        }

        Ok(violations)
    }

    /// Check certificate expiration (early warning)
    pub fn check_cert_expiration(rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(max_days) = rule.max_days_until_expiration
            && let Some(cert_analysis) = &results.certificate_chain
            && let Some(leaf_cert) = cert_analysis.chain.leaf()
        {
            // Parse expiration date and calculate days remaining
            // This is a simplified check - in production, parse the actual date
            if let Some(not_after) = parse_cert_date(&leaf_cert.not_after) {
                let now = Utc::now();
                let days_until_expiry = (not_after - now).num_days();

                // Only warn about expiring-soon certs; already-expired certs are handled
                // by check_cert_validation (require_unexpired) to avoid duplicate Critical violations.
                if days_until_expiry >= 0 && days_until_expiry <= max_days {
                    violations.push(Violation {
                        violation_type: "Certificate Expiring Soon".to_string(),
                        description: format!(
                            "Certificate expires in {} days (threshold: {} days)",
                            days_until_expiry, max_days
                        ),
                        evidence: format!("Certificate expires: {}", leaf_cert.not_after),
                        severity: Severity::Medium,
                    });
                }
            }
        }

        Ok(violations)
    }

    /// Check for known vulnerabilities
    pub fn check_vulnerabilities(_rule: &Rule, results: &ScanAssessment) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        for vuln in &results.vulnerabilities {
            if vuln.vulnerable {
                let severity = match vuln.severity {
                    crate::vulnerabilities::Severity::Critical => Severity::Critical,
                    crate::vulnerabilities::Severity::High => Severity::High,
                    crate::vulnerabilities::Severity::Medium => Severity::Medium,
                    crate::vulnerabilities::Severity::Low => Severity::Low,
                    crate::vulnerabilities::Severity::Info => Severity::Info,
                };

                violations.push(Violation {
                    violation_type: format!("Vulnerability: {:?}", vuln.vuln_type),
                    description: vuln.details.clone(),
                    evidence: vuln
                        .cve
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", vuln.vuln_type)),
                    severity,
                });
            }
        }

        Ok(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ScanAssessment;
    use crate::compliance::Rule;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::vulnerabilities::{
        Severity as VulnSeverity, VulnerabilityResult, VulnerabilityType,
    };
    use std::collections::HashMap;

    #[test]
    fn test_check_protocols_denied() {
        let rule = Rule {
            rule_type: "ProtocolVersion".to_string(),
            allowed: vec![],
            denied: vec!["SSLv2".to_string(), "SSLv3".to_string()],
            allowed_patterns: vec![],
            denied_patterns: vec![],
            preferred_patterns: vec![],
            min_rsa_bits: None,
            min_ecc_bits: None,
            required: None,
            require_valid_chain: None,
            require_unexpired: None,
            require_hostname_match: None,
            max_days_until_expiration: None,
            custom_params: HashMap::new(),
        };

        let results = ScanAssessment {
            protocols: vec![
                ProtocolTestResult {
                    protocol: Protocol::SSLv2,
                    supported: true,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
                ProtocolTestResult {
                    protocol: Protocol::TLS12,
                    supported: true,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
            ],
            ..Default::default()
        };

        let violations = ComplianceChecker::check_protocols(&rule, &results)
            .expect("test assertion should succeed");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "Prohibited Protocol");
    }

    #[test]
    fn test_check_protocols_allowed() {
        let rule = Rule {
            rule_type: "ProtocolVersion".to_string(),
            allowed: vec!["TLS 1.2".to_string(), "TLS 1.3".to_string()],
            denied: vec![],
            allowed_patterns: vec![],
            denied_patterns: vec![],
            preferred_patterns: vec![],
            min_rsa_bits: None,
            min_ecc_bits: None,
            required: None,
            require_valid_chain: None,
            require_unexpired: None,
            require_hostname_match: None,
            max_days_until_expiration: None,
            custom_params: HashMap::new(),
        };

        let results = ScanAssessment {
            protocols: vec![
                ProtocolTestResult {
                    protocol: Protocol::TLS10,
                    supported: true,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
                ProtocolTestResult {
                    protocol: Protocol::TLS12,
                    supported: true,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
            ],
            ..Default::default()
        };

        let violations = ComplianceChecker::check_protocols(&rule, &results)
            .expect("test assertion should succeed");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "Non-Compliant Protocol");
    }

    #[test]
    fn test_check_vulnerabilities_maps_severity_and_evidence() {
        let rule = Rule {
            rule_type: "Vulnerability".to_string(),
            allowed: vec![],
            denied: vec![],
            allowed_patterns: vec![],
            denied_patterns: vec![],
            preferred_patterns: vec![],
            min_rsa_bits: None,
            min_ecc_bits: None,
            required: None,
            require_valid_chain: None,
            require_unexpired: None,
            require_hostname_match: None,
            max_days_until_expiration: None,
            custom_params: HashMap::new(),
        };

        let results = ScanAssessment {
            vulnerabilities: vec![
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::Heartbleed,
                    vulnerable: true,
                    inconclusive: false,
                    details: "bad".to_string(),
                    cve: None,
                    cwe: None,
                    severity: VulnSeverity::High,
                },
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::BEAST,
                    vulnerable: false,
                    inconclusive: false,
                    details: "ok".to_string(),
                    cve: Some("CVE-2011-3389".to_string()),
                    cwe: None,
                    severity: VulnSeverity::Medium,
                },
            ],
            ..Default::default()
        };

        let violations = ComplianceChecker::check_vulnerabilities(&rule, &results)
            .expect("test assertion should succeed");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].violation_type.contains("Heartbleed"));
        assert_eq!(violations[0].severity, Severity::High);
    }
}
