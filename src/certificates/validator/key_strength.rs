use super::*;

impl CertificateValidator {
    /// Check key strength
    pub(crate) fn check_key_strength(
        &self,
        cert: &CertificateInfo,
        issues: &mut Vec<ValidationIssue>,
    ) {
        // Skip warnings if requested
        if self.skip_warnings {
            return;
        }

        if let Some(key_size) = cert.public_key_size {
            let alg = cert.public_key_algorithm.to_lowercase();
            let is_ec = alg.contains("ec") || alg.contains("ecdsa");

            if is_ec {
                // EC keys: 224 bits is the minimum acceptable; 256+ is recommended
                if key_size < 224 {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::High,
                        issue_type: IssueType::ShortKeyLength,
                        description: format!(
                            "Weak EC public key: {} bits (minimum recommended: 224)",
                            key_size
                        ),
                    });
                } else if key_size < 256 {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Low,
                        issue_type: IssueType::ShortKeyLength,
                        description: format!(
                            "EC key size {} bits is acceptable but 256+ recommended",
                            key_size
                        ),
                    });
                }
            } else {
                // RSA/DSA keys: 2048 bits minimum; 3072+ recommended
                if key_size < 2048 {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::High,
                        issue_type: IssueType::ShortKeyLength,
                        description: format!(
                            "Weak public key: {} bits (minimum recommended: 2048)",
                            key_size
                        ),
                    });
                } else if key_size < 3072 {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Low,
                        issue_type: IssueType::ShortKeyLength,
                        description: format!(
                            "Public key size {} bits is acceptable but 3072+ recommended",
                            key_size
                        ),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cert(not_before: String, not_after: String) -> CertificateInfo {
        CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before,
            not_after,
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
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
            certificate_transparency: None,
            der_bytes: vec![],
        }
    }

    #[test]
    fn test_weak_key_detection() {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: Some("expires in 1 year".to_string()),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(1024), // Weak!
            rsa_exponent: Some("e 65537".to_string()),
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
            certificate_transparency: None,
            der_bytes: vec![],
        };

        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        validator.check_key_strength(&cert, &mut issues);

        assert!(!issues.is_empty());
        assert!(matches!(issues[0].issue_type, IssueType::ShortKeyLength));
    }

    #[test]
    fn test_key_strength_skip_warnings() {
        let validator = CertificateValidator::with_skip_warnings("example.com".to_string(), true);
        let mut issues = Vec::new();

        let mut cert = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        cert.public_key_size = Some(1024);

        validator.check_key_strength(&cert, &mut issues);
        assert!(issues.is_empty());
    }
}
