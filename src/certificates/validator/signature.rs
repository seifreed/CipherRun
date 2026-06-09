use super::*;

impl CertificateValidator {
    /// Check the leaf certificate's signature algorithm.
    pub(crate) fn check_signature_algorithm(
        &self,
        cert: &CertificateInfo,
        issues: &mut Vec<ValidationIssue>,
    ) {
        self.check_signature_algorithm_labeled(cert, "Certificate", issues);
    }

    /// Check the signature algorithm of every chain certificate that is
    /// cryptographically verified during path building — i.e. the leaf and
    /// any intermediates. A self-signed root is skipped: its signature is not
    /// verified (trust is established by identity, not signature), so a SHA-1
    /// self-signature on a root is not a weakness.
    ///
    /// Without this, a SHA-1-signed intermediate (a real, browser-distrusted
    /// weakness) was missed because only the leaf was inspected.
    pub(crate) fn check_chain_signature_algorithms(
        &self,
        chain: &CertificateChain,
        issues: &mut Vec<ValidationIssue>,
    ) {
        for cert in chain.certificates.iter().skip(1) {
            if cert.subject == cert.issuer {
                continue;
            }
            self.check_signature_algorithm_labeled(cert, "Intermediate CA certificate", issues);
        }
    }

    fn check_signature_algorithm_labeled(
        &self,
        cert: &CertificateInfo,
        label: &str,
        issues: &mut Vec<ValidationIssue>,
    ) {
        let sig_alg = normalize_signature_algorithm_name(&cert.signature_algorithm);

        // Check for weak algorithms
        if sig_alg.contains("MD2") || sig_alg.contains("MD4") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::WeakSignature,
                description: format!("{label} uses MD2/MD4 signature (broken)"),
            });
        } else if sig_alg.contains("MD5") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::WeakSignature,
                description: format!("{label} uses MD5 signature (broken)"),
            });
        } else if sig_alg.contains("SHA1") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::WeakSignature,
                description: format!("{label} uses SHA-1 signature (deprecated)"),
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
    fn test_chain_signature_flags_sha1_intermediate_but_not_self_signed_root() {
        use crate::certificates::parser::CertificateChain;

        let validator = CertificateValidator::new("example.com".to_string());

        // Leaf: modern SHA-256 (must not be flagged).
        let leaf = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );

        // Intermediate: SHA-1 signed (a real weakness — must be flagged).
        let mut intermediate = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        intermediate.subject = "CN=Intermediate CA".to_string();
        intermediate.issuer = "CN=Root CA".to_string();
        intermediate.signature_algorithm = "sha1WithRSAEncryption".to_string();

        // Root: self-signed with SHA-1 (acceptable — its signature is not
        // verified during path building, so it must NOT be flagged).
        let mut root = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        root.subject = "CN=Root CA".to_string();
        root.issuer = "CN=Root CA".to_string();
        root.signature_algorithm = "sha1WithRSAEncryption".to_string();

        let chain = CertificateChain {
            certificates: vec![leaf, intermediate, root],
            chain_length: 3,
            chain_size_bytes: 0,
        };

        let mut issues = Vec::new();
        validator.check_chain_signature_algorithms(&chain, &mut issues);

        let weak: Vec<_> = issues
            .iter()
            .filter(|i| matches!(i.issue_type, IssueType::WeakSignature))
            .collect();
        assert_eq!(
            weak.len(),
            1,
            "exactly the SHA-1 intermediate should be flagged, not the self-signed root"
        );
        assert!(weak[0].description.contains("Intermediate"));
        assert!(matches!(weak[0].severity, IssueSeverity::High));
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
