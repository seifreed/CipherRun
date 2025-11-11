// Certificate policy rules

use crate::Result;
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

    pub fn evaluate(&self, target: &str) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        let cert_result = match self.cert_result {
            Some(result) => result,
            None => {
                violations.push(
                    PolicyViolation::new(
                        "certificates.missing",
                        "Certificate Missing",
                        PolicyAction::Fail,
                        "No certificate information available",
                    )
                    .with_evidence("Certificate chain could not be retrieved")
                    .with_remediation("Ensure the server presents a valid certificate"),
                );
                return Ok(violations);
            }
        };

        let leaf_cert = cert_result.chain.leaf();

        // Check minimum key size
        if let Some(min_key_size) = self.policy.min_key_size
            && let Some(cert) = leaf_cert
            && let Some(key_size) = cert.public_key_size
            && (key_size as u32) < min_key_size
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
                    key_size, cert.public_key_algorithm
                ))
                .with_remediation(format!(
                    "Replace certificate with at least {}-bit key",
                    min_key_size
                )),
            );
        }

        // Check days until expiry
        if let Some(max_days) = self.policy.max_days_until_expiry
            && let Some(cert) = leaf_cert
        {
            // Parse not_after date and calculate days remaining
            if let Ok(not_after) =
                chrono::NaiveDateTime::parse_from_str(&cert.not_after, "%Y-%m-%d %H:%M:%S %Z")
            {
                let now = Utc::now().naive_utc();
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
                        .with_evidence(format!("Valid until: {}", cert.not_after))
                        .with_remediation("Renew certificate before expiration"),
                    );
                }
            }
        }

        // Check prohibited signature algorithms
        if let Some(ref prohibited_sigs) = self.policy.prohibited_signature_algorithms
            && let Some(cert) = leaf_cert
        {
            for prohibited in prohibited_sigs {
                if cert
                    .signature_algorithm
                    .to_uppercase()
                    .contains(&prohibited.to_uppercase())
                {
                    violations.push(
                        PolicyViolation::new(
                            "certificates.prohibited_signature_algorithms",
                            "Prohibited Signature Algorithm",
                            self.policy.action,
                            format!(
                                "Certificate uses prohibited signature algorithm: {}",
                                cert.signature_algorithm
                            ),
                        )
                        .with_evidence(format!("Signature algorithm: {}", cert.signature_algorithm))
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

        // Check SAN requirement
        if let Some(true) = self.policy.require_san
            && let Some(cert) = leaf_cert
            && cert.san.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;

    fn create_test_cert_result() -> CertificateAnalysisResult {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "123456".to_string(),
            not_before: "2024-01-01 00:00:00 UTC".to_string(),
            not_after: "2025-01-01 00:00:00 UTC".to_string(),
            expiry_countdown: None,
            signature_algorithm: "SHA256-RSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["example.com".to_string()],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: Some("Yes (certificate)".to_string()),
            der_bytes: vec![],
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

    #[test]
    fn test_min_key_size_violation() {
        let policy = CertificatePolicy {
            min_key_size: Some(4096),
            max_days_until_expiry: None,
            prohibited_signature_algorithms: None,
            require_valid_trust_chain: None,
            require_san: None,
            require_hostname_match: None,
            action: PolicyAction::Fail,
        };

        let cert_result = create_test_cert_result();
        let rule = CertificateRule::new(&policy, Some(&cert_result));
        let violations = rule.evaluate("example.com:443").unwrap();

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "certificates.min_key_size");
    }

    #[test]
    fn test_san_requirement() {
        let policy = CertificatePolicy {
            min_key_size: None,
            max_days_until_expiry: None,
            prohibited_signature_algorithms: None,
            require_valid_trust_chain: None,
            require_san: Some(true),
            require_hostname_match: None,
            action: PolicyAction::Fail,
        };

        let mut cert_result = create_test_cert_result();
        cert_result.chain.certificates[0].san.clear();

        let rule = CertificateRule::new(&policy, Some(&cert_result));
        let violations = rule.evaluate("example.com:443").unwrap();

        assert!(!violations.is_empty());
        assert_eq!(violations[0].rule_path, "certificates.require_san");
    }
}
