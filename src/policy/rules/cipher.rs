// Cipher policy rules

use crate::Result;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::policy::CipherPolicy;
use crate::policy::violation::PolicyViolation;
use crate::protocols::Protocol;
use regex::Regex;
use std::collections::HashMap;

pub struct CipherRule<'a> {
    policy: &'a CipherPolicy,
    results: &'a HashMap<Protocol, ProtocolCipherSummary>,
}

impl<'a> CipherRule<'a> {
    pub fn new(
        policy: &'a CipherPolicy,
        results: &'a HashMap<Protocol, ProtocolCipherSummary>,
    ) -> Self {
        Self { policy, results }
    }

    pub fn evaluate(&self, _target: &str) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // Check minimum cipher strength
        if let Some(ref min_strength) = self.policy.min_strength {
            for (protocol, summary) in self.results {
                let weak_ciphers = match min_strength.as_str() {
                    "HIGH" => summary.counts.low_strength + summary.counts.medium_strength,
                    "MEDIUM" => summary.counts.low_strength,
                    "LOW" => 0,
                    _ => 0,
                };

                if weak_ciphers > 0 {
                    violations.push(
                        PolicyViolation::new(
                            "ciphers.min_strength",
                            "Minimum Cipher Strength Check",
                            self.policy.action,
                            format!(
                                "{} has {} cipher(s) below {} strength",
                                protocol, weak_ciphers, min_strength
                            ),
                        )
                        .with_evidence(format!(
                            "Protocol: {}, Weak ciphers: {}",
                            protocol, weak_ciphers
                        ))
                        .with_remediation(format!(
                            "Remove weak cipher suites from {} configuration",
                            protocol
                        )),
                    );
                }
            }
        }

        // Check forward secrecy requirement
        if let Some(true) = self.policy.require_forward_secrecy {
            for (protocol, summary) in self.results {
                let non_fs_count = summary.counts.total - summary.counts.forward_secrecy;
                if non_fs_count > 0 {
                    violations.push(
                        PolicyViolation::new(
                            "ciphers.require_forward_secrecy",
                            "Forward Secrecy Requirement",
                            self.policy.action,
                            format!(
                                "{} has {} cipher(s) without forward secrecy",
                                protocol, non_fs_count
                            ),
                        )
                        .with_evidence(format!(
                            "Protocol: {}, Non-FS ciphers: {}/{}",
                            protocol, non_fs_count, summary.counts.total
                        ))
                        .with_remediation(format!(
                            "Configure {} to prefer ECDHE/DHE cipher suites",
                            protocol
                        )),
                    );
                }
            }
        }

        // Check AEAD requirement
        if let Some(true) = self.policy.require_aead {
            for (protocol, summary) in self.results {
                let non_aead_count = summary.counts.total - summary.counts.aead;
                if non_aead_count > 0 {
                    violations.push(
                        PolicyViolation::new(
                            "ciphers.require_aead",
                            "AEAD Cipher Requirement",
                            self.policy.action,
                            format!(
                                "{} has {} cipher(s) without AEAD",
                                protocol, non_aead_count
                            ),
                        )
                        .with_evidence(format!(
                            "Protocol: {}, Non-AEAD ciphers: {}/{}",
                            protocol, non_aead_count, summary.counts.total
                        ))
                        .with_remediation(format!(
                            "Configure {} to use only AEAD cipher suites (GCM, CCM, ChaCha20-Poly1305)",
                            protocol
                        )),
                    );
                }
            }
        }

        // Check prohibited cipher patterns
        if let Some(ref patterns) = self.policy.prohibited_patterns {
            for (protocol, summary) in self.results {
                for cipher in &summary.supported_ciphers {
                    for pattern in patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            // Check both OpenSSL and IANA names
                            if re.is_match(&cipher.openssl_name) || re.is_match(&cipher.iana_name) {
                                violations.push(
                                    PolicyViolation::new(
                                        "ciphers.prohibited_patterns",
                                        "Prohibited Cipher Pattern",
                                        self.policy.action,
                                        format!(
                                            "Prohibited cipher detected: {}",
                                            cipher.openssl_name
                                        ),
                                    )
                                    .with_evidence(format!(
                                        "Protocol: {}, Cipher: {} (matches pattern: {})",
                                        protocol, cipher.openssl_name, pattern
                                    ))
                                    .with_remediation(format!(
                                        "Remove {} from server configuration",
                                        cipher.openssl_name
                                    )),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check required cipher patterns
        if let Some(ref patterns) = self.policy.required_patterns {
            for (protocol, summary) in self.results {
                for pattern in patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        let has_matching_cipher = summary.supported_ciphers.iter().any(|cipher| {
                            re.is_match(&cipher.openssl_name) || re.is_match(&cipher.iana_name)
                        });

                        if !has_matching_cipher {
                            violations.push(
                                PolicyViolation::new(
                                    "ciphers.required_patterns",
                                    "Required Cipher Pattern",
                                    self.policy.action,
                                    format!(
                                        "{} does not have cipher matching pattern: {}",
                                        protocol, pattern
                                    ),
                                )
                                .with_evidence(format!(
                                    "Protocol: {}, Missing cipher pattern: {}",
                                    protocol, pattern
                                ))
                                .with_remediation(format!(
                                    "Add cipher suites matching '{}' to {} configuration",
                                    pattern, protocol
                                )),
                            );
                        }
                    }
                }
            }
        }

        Ok(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::CipherCounts;
    use crate::policy::PolicyAction;

    fn create_test_cipher(name: &str) -> CipherSuite {
        CipherSuite {
            hexcode: "0000".to_string(),
            openssl_name: name.to_string(),
            iana_name: name.to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "RSA".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES".to_string(),
            mac: "SHA".to_string(),
            bits: 128,
            export: false,
        }
    }

    #[test]
    fn test_prohibited_cipher_pattern() {
        let policy = CipherPolicy {
            min_strength: None,
            require_forward_secrecy: None,
            require_aead: None,
            prohibited_patterns: Some(vec![".*_RC4_.*".to_string()]),
            required_patterns: None,
            action: PolicyAction::Fail,
        };

        let mut results = HashMap::new();
        results.insert(
            Protocol::TLS12,
            ProtocolCipherSummary {
                protocol: Protocol::TLS12,
                supported_ciphers: vec![create_test_cipher("TLS_RSA_WITH_RC4_128_SHA")],
                counts: CipherCounts::default(),
                server_ordered: true,
                server_preference: vec![],
                preferred_cipher: None,
                avg_handshake_time_ms: None,
            },
        );

        let rule = CipherRule::new(&policy, &results);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "ciphers.prohibited_patterns");
    }

    #[test]
    fn test_minimum_strength() {
        let policy = CipherPolicy {
            min_strength: Some("HIGH".to_string()),
            require_forward_secrecy: None,
            require_aead: None,
            prohibited_patterns: None,
            required_patterns: None,
            action: PolicyAction::Fail,
        };

        let mut results = HashMap::new();
        results.insert(
            Protocol::TLS12,
            ProtocolCipherSummary {
                protocol: Protocol::TLS12,
                supported_ciphers: vec![],
                counts: CipherCounts {
                    total: 10,
                    high_strength: 5,
                    medium_strength: 3,
                    low_strength: 2,
                    null_ciphers: 0,
                    export_ciphers: 0,
                    forward_secrecy: 8,
                    aead: 5,
                },
                server_ordered: true,
                server_preference: vec![],
                preferred_cipher: None,
                avg_handshake_time_ms: None,
            },
        );

        let rule = CipherRule::new(&policy, &results);
        let violations = rule
            .evaluate("example.com:443")
            .expect("test assertion should succeed");

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "ciphers.min_strength");
    }
}
