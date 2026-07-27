// Certificate policy rules

use crate::Result;
use crate::certificates::revocation::RevocationStatus;
use crate::certificates::signature_algorithm::normalize_signature_algorithm_name;
use crate::certificates::validator::parse_cert_date;
use crate::policy::violation::PolicyViolation;
use crate::policy::{CertificatePolicy, PolicyAction};
use crate::scanner::CertificateAnalysisResult;
use chrono::Utc;

pub struct CertificateRule<'a> {
    policy: &'a CertificatePolicy,
    cert_result: Option<&'a CertificateAnalysisResult>,
}

impl<'a> CertificateRule<'a> {
    pub fn new(
        policy: &'a CertificatePolicy,
        cert_result: Option<&'a CertificateAnalysisResult>,
    ) -> Self {
        Self {
            policy,
            cert_result,
        }
    }

    fn missing_certificate_violation() -> PolicyViolation {
        PolicyViolation::new(
            "certificates.missing",
            "Certificate Missing",
            PolicyAction::Fail,
            "No certificate information available",
        )
        .with_evidence("Certificate chain could not be retrieved")
        .with_remediation("Ensure the server presents a valid certificate")
    }

    pub fn evaluate(&self, target: &str) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        let cert_result = match self.cert_result {
            Some(result) => result,
            None => {
                violations.push(Self::missing_certificate_violation());
                return Ok(violations);
            }
        };

        let Some(leaf_cert) = cert_result.chain.leaf() else {
            violations.push(Self::missing_certificate_violation());
            return Ok(violations);
        };

        // Check minimum key size
        if let Some(min_key_size) = self.policy.min_key_size
            && let Some(key_size) = leaf_cert.public_key_size
            && key_size_below_minimum(key_size, min_key_size)
        {
            violations.push(
                PolicyViolation::new(
                    "certificates.min_key_size",
                    "Minimum Key Size Check",
                    self.policy.action,
                    format!(
                        "Certificate key size {} is below minimum {}",
                        key_size, min_key_size
                    ),
                )
                .with_evidence(format!(
                    "Certificate has {}-bit {} key",
                    key_size, leaf_cert.public_key_algorithm
                ))
                .with_remediation(format!(
                    "Replace certificate with at least {}-bit key",
                    min_key_size
                )),
            );
        }

        // Check days until expiry
        if let Some(max_days) = self.policy.max_days_until_expiry {
            // Parse not_after date using the shared certificate date parser,
            // which supports OpenSSL format ("Jan 01 00:00:00 2024 GMT")
            // and ISO format ("2024-01-01 00:00:00 +00:00").
            match parse_cert_date(&leaf_cert.not_after) {
                Some(not_after) => {
                    let now = Utc::now();

                    if now > not_after {
                        let days_expired = (now - not_after).num_days();
                        violations.push(
                            PolicyViolation::new(
                                "certificates.max_days_until_expiry",
                                "Certificate Expiry Check",
                                self.policy.action,
                                format!("Certificate expired {} days ago", days_expired),
                            )
                            .with_evidence(format!("Valid until: {}", leaf_cert.not_after))
                            .with_remediation(
                                "Renew certificate immediately - it has already expired",
                            ),
                        );
                    } else {
                        let days_remaining = (not_after - now).num_days();
                        if days_remaining < max_days {
                            violations.push(
                                PolicyViolation::new(
                                    "certificates.max_days_until_expiry",
                                    "Certificate Expiry Check",
                                    self.policy.action,
                                    format!(
                                        "Certificate expires in {} days (threshold: {} days)",
                                        days_remaining, max_days
                                    ),
                                )
                                .with_evidence(format!("Valid until: {}", leaf_cert.not_after))
                                .with_remediation("Renew certificate before expiration"),
                            );
                        }
                    }
                }
                None => violations.push(
                    PolicyViolation::new(
                        "certificates.max_days_until_expiry",
                        "Certificate Expiry Check",
                        self.policy.action,
                        "Certificate expiry date could not be parsed",
                    )
                    .with_evidence(format!("Valid until: {}", leaf_cert.not_after))
                    .with_remediation(
                        "Replace or re-scan the certificate so expiry can be verified",
                    ),
                ),
            }
        }

        // Check prohibited signature algorithms
        if let Some(ref prohibited_sigs) = self.policy.prohibited_signature_algorithms {
            for prohibited in prohibited_sigs {
                let prohibited = prohibited.trim();
                if prohibited.is_empty() {
                    continue;
                }

                if signature_algorithm_matches(&leaf_cert.signature_algorithm, prohibited) {
                    violations.push(
                        PolicyViolation::new(
                            "certificates.prohibited_signature_algorithms",
                            "Prohibited Signature Algorithm",
                            self.policy.action,
                            format!(
                                "Certificate uses prohibited signature algorithm: {}",
                                leaf_cert.signature_algorithm
                            ),
                        )
                        .with_evidence(format!(
                            "Signature algorithm: {}",
                            leaf_cert.signature_algorithm
                        ))
                        .with_remediation(format!(
                            "Replace certificate with signature algorithm other than {}",
                            prohibited
                        )),
                    );
                }
            }
        }

        // Check valid trust chain
        if let Some(true) = self.policy.require_valid_trust_chain
            && !cert_result.validation.trust_chain_valid
        {
            violations.push(
                PolicyViolation::new(
                    "certificates.require_valid_trust_chain",
                    "Trust Chain Validation",
                    self.policy.action,
                    "Certificate trust chain is invalid",
                )
                .with_evidence("Trust chain validation failed")
                .with_remediation("Install valid certificate chain from trusted CA"),
            );
        }

        // Check revocation status
        if let Some(true) = self.policy.require_revocation_check {
            match cert_result.revocation.as_ref() {
                Some(revocation) if revocation.status == RevocationStatus::Good => {}
                Some(revocation) => {
                    violations.push(
                        PolicyViolation::new(
                            "certificates.require_revocation_check",
                            "Revocation Check",
                            self.policy.action,
                            "Certificate revocation check failed",
                        )
                        .with_evidence(revocation.summary())
                        .with_remediation(
                            "Revoke or replace the certificate and re-run revocation checks",
                        ),
                    );
                }
                None => {
                    violations.push(
                        PolicyViolation::new(
                            "certificates.require_revocation_check",
                            "Revocation Check",
                            self.policy.action,
                            "Certificate revocation status is unavailable",
                        )
                        .with_evidence("Revocation check was not performed")
                        .with_remediation(
                            "Enable revocation checking or provide a fresh scan with revocation data",
                        ),
                    );
                }
            }
        }

        // Check SAN requirement
        if let Some(true) = self.policy.require_san
            && leaf_cert.san.is_empty()
        {
            violations.push(
                PolicyViolation::new(
                    "certificates.require_san",
                    "Subject Alternative Name Check",
                    self.policy.action,
                    "Certificate missing Subject Alternative Names (SAN)",
                )
                .with_evidence("No SAN extension found in certificate")
                .with_remediation("Replace certificate with SAN extension"),
            );
        }

        // Check hostname match
        if let Some(true) = self.policy.require_hostname_match
            && !cert_result.validation.hostname_match
        {
            violations.push(
                PolicyViolation::new(
                    "certificates.require_hostname_match",
                    "Hostname Match Check",
                    self.policy.action,
                    "Certificate hostname does not match target",
                )
                .with_evidence(format!("Certificate does not match hostname: {}", target))
                .with_remediation("Replace certificate with correct hostname in CN or SAN"),
            );
        }

        Ok(violations)
    }
}

fn key_size_below_minimum(key_size: usize, min_key_size: u32) -> bool {
    usize::try_from(min_key_size).map_or(true, |min_key_size| key_size < min_key_size)
}

fn signature_algorithm_aliases(value: &str) -> Vec<String> {
    let mut aliases = vec![normalize_signature_algorithm_name(value)];
    let parts: Vec<String> = value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(normalize_signature_algorithm_name)
        .collect();
    aliases.extend(parts.iter().cloned());
    aliases.extend(parts.windows(2).map(|pair| pair.concat()));
    aliases
}

fn signature_algorithm_matches(signature_algorithm: &str, prohibited: &str) -> bool {
    let prohibited = normalize_signature_algorithm_name(prohibited);
    if prohibited.is_empty() {
        return false;
    }

    signature_algorithm_aliases(signature_algorithm)
        .iter()
        .any(|alias| alias == &prohibited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
    use crate::certificates::validator::ValidationResult;

    fn create_test_cert_result() -> CertificateAnalysisResult {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "123456".to_string(),
            not_before: "2024-01-01 00:00:00 UTC".to_string(),
            not_after: "2025-01-01 00:00:00 UTC".to_string(),
            signature_algorithm: "SHA256-RSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(2048),
            san: vec!["example.com".to_string()],
            certificate_transparency: Some("Yes (certificate)".to_string()),
            ..Default::default()
        };

        CertificateAnalysisResult {
            chain: CertificateChain {
                certificates: vec![cert],
                chain_length: 1,
                chain_size_bytes: 1000,
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

    fn create_revocation_result(status: RevocationStatus) -> RevocationResult {
        RevocationResult {
            status,
            method: RevocationMethod::OCSP,
            details: "test revocation result".to_string(),
            ocsp_stapling: false,
            ocsp_stapling_details: None,
            must_staple: false,
        }
    }

    fn base_policy() -> CertificatePolicy {
        CertificatePolicy {
            min_key_size: None,
            max_days_until_expiry: None,
            prohibited_signature_algorithms: None,
            require_valid_trust_chain: None,
            require_san: None,
            require_hostname_match: None,
            require_revocation_check: None,
            action: PolicyAction::Fail,
        }
    }

    fn violations(
        policy: &CertificatePolicy,
        cert_result: Option<&CertificateAnalysisResult>,
    ) -> Vec<PolicyViolation> {
        CertificateRule::new(policy, cert_result)
            .evaluate("example.com:443")
            .expect("test assertion should succeed")
    }

    fn prohibited_signature_violations(
        prohibited: &str,
        signature_algorithm: &str,
    ) -> Vec<PolicyViolation> {
        let policy = CertificatePolicy {
            prohibited_signature_algorithms: Some(vec![prohibited.to_string()]),
            ..base_policy()
        };
        let mut cert_result = create_test_cert_result();
        cert_result.chain.certificates[0].signature_algorithm = signature_algorithm.to_string();
        violations(&policy, Some(&cert_result))
    }

    #[test]
    fn test_min_key_size_violation() {
        let policy = CertificatePolicy {
            min_key_size: Some(4096),
            ..base_policy()
        };

        let cert_result = create_test_cert_result();
        let violations = violations(&policy, Some(&cert_result));

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "certificates.min_key_size");
    }

    #[test]
    fn test_missing_certificate_result() {
        let policy = base_policy();

        let violations = violations(&policy, None);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "certificates.missing");
    }

    #[test]
    fn test_empty_certificate_chain_is_missing_certificate_violation() {
        let policy = CertificatePolicy {
            min_key_size: Some(2048),
            max_days_until_expiry: Some(30),
            prohibited_signature_algorithms: Some(vec!["SHA1".to_string()]),
            require_valid_trust_chain: Some(true),
            require_san: Some(true),
            require_hostname_match: Some(true),
            require_revocation_check: None,
            action: PolicyAction::Fail,
        };

        let mut cert_result = create_test_cert_result();
        cert_result.chain.certificates.clear();
        cert_result.chain.chain_length = 0;

        let violations = violations(&policy, Some(&cert_result));

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_path, "certificates.missing");
    }

    #[test]
    fn test_san_requirement() {
        let policy = CertificatePolicy {
            require_san: Some(true),
            ..base_policy()
        };

        let mut cert_result = create_test_cert_result();
        cert_result.chain.certificates[0].san.clear();

        let violations = violations(&policy, Some(&cert_result));

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "certificates.require_san");
    }

    #[test]
    fn test_invalid_expiry_dates_fail_expiry_policy() {
        let policy = CertificatePolicy {
            max_days_until_expiry: Some(30),
            ..base_policy()
        };

        for (case, not_after, expected_description) in [
            (
                "expired",
                (Utc::now() - chrono::Duration::hours(1))
                    .format("%Y-%m-%d %H:%M:%S %z")
                    .to_string(),
                Some("expired"),
            ),
            ("unparseable", "not a date".to_string(), None),
        ] {
            let mut cert_result = create_test_cert_result();
            cert_result.chain.certificates[0].not_after = not_after;

            let violations = violations(&policy, Some(&cert_result));

            assert_eq!(violations.len(), 1, "{case}");
            assert_eq!(
                violations[0].rule_path, "certificates.max_days_until_expiry",
                "{case}"
            );
            if let Some(expected) = expected_description {
                assert!(violations[0].description.contains(expected), "{case}");
            }
        }
    }

    #[test]
    fn test_prohibited_signature_algorithm_matches_policy_values() {
        for (prohibited, signature_algorithm) in [
            ("SHA1", "SHA1-RSA"),
            (" sha1 ", "SHA1-RSA"),
            ("SHA1", "SHA-1-RSA"),
        ] {
            let violations = prohibited_signature_violations(prohibited, signature_algorithm);

            assert_eq!(violations.len(), 1);
            assert_eq!(
                violations[0].rule_path,
                "certificates.prohibited_signature_algorithms"
            );
        }
    }

    #[test]
    fn test_prohibited_signature_algorithm_rejects_partial_match() {
        let violations = prohibited_signature_violations("HA1", "SHA-1-RSA");

        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn test_require_valid_trust_chain_violation() {
        let policy = CertificatePolicy {
            require_valid_trust_chain: Some(true),
            ..base_policy()
        };

        let mut cert_result = create_test_cert_result();
        cert_result.validation.trust_chain_valid = false;

        let violations = violations(&policy, Some(&cert_result));

        assert_eq!(
            violations[0].rule_path,
            "certificates.require_valid_trust_chain"
        );
    }

    #[test]
    fn test_require_revocation_check_violation_for_revoked_certificate() {
        let policy = CertificatePolicy {
            require_revocation_check: Some(true),
            ..base_policy()
        };

        let mut cert_result = create_test_cert_result();
        cert_result.revocation = Some(create_revocation_result(RevocationStatus::Revoked));

        let violations = violations(&policy, Some(&cert_result));

        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].rule_path,
            "certificates.require_revocation_check"
        );
    }
}
