use super::*;

impl CertificateValidator {
    /// Check hostname match
    pub(crate) fn check_hostname(
        &self,
        cert: &CertificateInfo,
        issues: &mut Vec<ValidationIssue>,
    ) -> bool {
        // Check CN and SAN
        // Normalize hostname: convert to lowercase and remove trailing dot (FQDN format)
        // Per RFC 1034, a trailing dot represents the DNS root and should be stripped
        // for comparison with certificate SANs which don't include the root dot.
        let hostname_lower = self.hostname.to_lowercase();
        let hostname_lower = hostname_lower.strip_suffix('.').unwrap_or(&hostname_lower);
        let hostname_lower = hostname_lower.to_string();

        // Check Subject Alternative Names
        for san in &cert.san {
            // Also normalize SANs by removing trailing dots for comparison
            let san_normalized = san.to_lowercase();
            let san_normalized = san_normalized.strip_suffix('.').unwrap_or(&san_normalized);

            if san_normalized == hostname_lower {
                return true;
            }

            // Check wildcard match
            // Wildcard certificates like "*.example.com" should match "www.example.com"
            // but NOT "sub.www.example.com" (only one level)
            // and NOT "example.com" (bare domain - wildcard does NOT match bare domain)
            if let Some(san_domain) = san_normalized.strip_prefix("*.") {
                // Wildcard domain must be non-empty and contain at least one dot
                // (e.g., "example.com" from "*.example.com", not "" from "*." or "com" from "*.com")
                if san_domain.is_empty() || !san_domain.contains('.') {
                    continue;
                }
                // Check if hostname ends with the domain part (e.g., ".example.com")
                let domain_suffix = format!(".{}", san_domain);
                if hostname_lower.ends_with(&domain_suffix) {
                    // Extract the label before the domain suffix
                    // e.g., for "www.example.com" and ".example.com", we get "www"
                    let prefix = &hostname_lower[..hostname_lower.len() - domain_suffix.len()];
                    // Wildcard matches exactly one label (no dots in prefix)
                    if !prefix.is_empty() && !prefix.contains('.') {
                        return true;
                    }
                }
                // NOTE: Wildcard certificates do NOT match the bare domain.
                // If the cert has "*.example.com", it does NOT match "example.com".
                // The bare domain must be explicitly listed in SANs if needed.
            }
        }

        // Check Common Name in subject (exact match with DN boundary)
        let subject_lower = cert.subject.to_lowercase();
        let cn_prefix = format!("cn={}", hostname_lower);
        if let Some(pos) = subject_lower.find(&cn_prefix) {
            // Verify CN= is preceded by a DN boundary (start of string, comma, slash, or space)
            let before_ok = pos == 0
                || subject_lower[..pos].ends_with(", ")
                || subject_lower[..pos].ends_with(',')
                || subject_lower[..pos].ends_with('/')
                || subject_lower[..pos].ends_with(' ');
            // Verify the CN value ends at a DN boundary (comma, end of string, or slash)
            let after = pos + cn_prefix.len();
            let after_ok = after == subject_lower.len()
                || subject_lower[after..].starts_with(',')
                || subject_lower[after..].starts_with('/');
            if before_ok && after_ok {
                return true;
            }
        }

        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::HostnameMismatch,
            description: format!(
                "Certificate hostname mismatch. Expected: {}, Got SANs: {:?}",
                self.hostname, cert.san
            ),
        });

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_hostname_match() {
        let cert = CertificateInfo {
            subject: "CN=unused".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01 00:00:00 +0000".to_string(),
            not_after: "2025-01-01 00:00:00 +0000".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["*.example.com".to_string()],
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

        // Wildcard should match subdomain
        let validator = CertificateValidator::new("api.example.com".to_string());
        let mut issues = Vec::new();
        assert!(validator.check_hostname(&cert, &mut issues));

        // Wildcard should NOT match sub-subdomain (multiple levels)
        let validator = CertificateValidator::new("a.b.example.com".to_string());
        let mut issues = Vec::new();
        assert!(!validator.check_hostname(&cert, &mut issues));
        assert!(!issues.is_empty());

        // Wildcard should NOT match bare domain (this is the key fix)
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();
        assert!(!validator.check_hostname(&cert, &mut issues));
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_wildcard_with_bare_domain_sans() {
        // Test cert with both wildcard and bare domain in SANs
        let cert = CertificateInfo {
            subject: "CN=unused".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01 00:00:00 +0000".to_string(),
            not_after: "2025-01-01 00:00:00 +0000".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["*.example.com".to_string(), "example.com".to_string()],
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

        // Both subdomain and bare domain should match
        let validator = CertificateValidator::new("api.example.com".to_string());
        let mut issues = Vec::new();
        assert!(validator.check_hostname(&cert, &mut issues));

        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();
        assert!(validator.check_hostname(&cert, &mut issues));
    }

    #[test]
    fn test_hostname_matching() {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["example.com".to_string(), "www.example.com".to_string()],
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

        assert!(validator.check_hostname(&cert, &mut issues));
        assert!(issues.is_empty());
    }
}
