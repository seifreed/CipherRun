use super::*;

impl CertificateValidator {
    /// Check signature algorithm
    pub(crate) fn check_signature_algorithm(
        &self,
        cert: &CertificateInfo,
        issues: &mut Vec<ValidationIssue>,
    ) {
        let sig_alg = normalize_signature_algorithm_name(&cert.signature_algorithm);

        // Check for weak algorithms
        if sig_alg.contains("MD2") || sig_alg.contains("MD4") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::WeakSignature,
                description: "Certificate uses MD2/MD4 signature (broken)".to_string(),
            });
        } else if sig_alg.contains("MD5") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::WeakSignature,
                description: "Certificate uses MD5 signature (broken)".to_string(),
            });
        } else if sig_alg.contains("SHA1") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::WeakSignature,
                description: "Certificate uses SHA-1 signature (deprecated)".to_string(),
            });
        }
    }
}

fn normalize_signature_algorithm_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
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
    fn test_signature_algorithm_md5_and_sha1() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let mut cert = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        cert.signature_algorithm = "md5WithRSAEncryption".to_string();
        validator.check_signature_algorithm(&cert, &mut issues);
        assert!(issues.iter().any(|i| {
            matches!(i.issue_type, IssueType::WeakSignature)
                && matches!(i.severity, IssueSeverity::Critical)
        }));

        let mut issues = Vec::new();
        cert.signature_algorithm = "sha1WithRSAEncryption".to_string();
        validator.check_signature_algorithm(&cert, &mut issues);
        assert!(issues.iter().any(|i| {
            matches!(i.issue_type, IssueType::WeakSignature)
                && matches!(i.severity, IssueSeverity::High)
        }));
    }

    #[test]
    fn test_signature_algorithm_detects_hyphenated_sha1_alias() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();
        let mut cert = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        cert.signature_algorithm = "sha-1WithRSAEncryption".to_string();

        validator.check_signature_algorithm(&cert, &mut issues);

        assert!(issues.iter().any(|i| {
            matches!(i.issue_type, IssueType::WeakSignature)
                && matches!(i.severity, IssueSeverity::High)
        }));
    }
}
