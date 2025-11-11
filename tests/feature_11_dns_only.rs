/// Tests for Feature 11: DNS-Only Output Mode
///
/// This test file verifies the DNS-only output mode functionality,
/// which extracts unique domain names from certificates.
#[cfg(test)]
mod dns_only_tests {
    use cipherrun::certificates::parser::CertificateInfo;
    use cipherrun::output::dns_only::DnsOnlyMode;

    /// Helper to create a test certificate
    fn create_test_cert(subject: &str, san: Vec<String>) -> CertificateInfo {
        CertificateInfo {
            subject: subject.to_string(),
            issuer: "CN=Test CA,O=Test".to_string(),
            serial_number: "123456".to_string(),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: Some("e 65537".to_string()),
            san,
            is_ca: false,
            key_usage: vec!["digitalSignature".to_string()],
            extended_key_usage: vec!["serverAuth".to_string()],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            der_bytes: vec![],
        }
    }

    #[test]
    fn test_extract_single_domain_from_cn() {
        let cert = create_test_cert("CN=example.com,O=Test", vec![]);
        let domains = DnsOnlyMode::extract_domains(&cert);

        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "example.com");
    }

    #[test]
    fn test_extract_with_san_entries() {
        let cert = create_test_cert(
            "CN=example.com,O=Test",
            vec!["www.example.com".to_string(), "api.example.com".to_string()],
        );
        let domains = DnsOnlyMode::extract_domains(&cert);

        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"www.example.com".to_string()));
        assert!(domains.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn test_wildcard_removal() {
        let cert = create_test_cert("CN=*.example.com,O=Test", vec!["*.example.com".to_string()]);
        let domains = DnsOnlyMode::extract_domains(&cert);

        // Wildcards should be removed
        assert!(domains.contains(&"example.com".to_string()));
        // Should not contain wildcard
        assert!(!domains.iter().any(|d| d.contains("*")));
    }

    #[test]
    fn test_deduplication() {
        let cert = create_test_cert(
            "CN=example.com,O=Test",
            vec![
                "example.com".to_string(),
                "example.com".to_string(),
                "www.example.com".to_string(),
            ],
        );
        let domains = DnsOnlyMode::extract_domains(&cert);

        // Should only have 2 unique domains (example.com and www.example.com)
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn test_case_insensitivity() {
        let cert = create_test_cert("CN=EXAMPLE.COM,O=Test", vec!["WWW.EXAMPLE.COM".to_string()]);
        let domains = DnsOnlyMode::extract_domains(&cert);

        // All domains should be lowercase
        assert!(domains.iter().all(|d| d == &d.to_lowercase()));
        assert_eq!(domains[0], "example.com");
        assert_eq!(domains[1], "www.example.com");
    }

    #[test]
    fn test_format_output() {
        let cert = create_test_cert("CN=example.com,O=Test", vec!["www.example.com".to_string()]);
        let output = DnsOnlyMode::format_output(&cert);

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "example.com");
        assert_eq!(lines[1], "www.example.com");
    }

    #[test]
    fn test_empty_san() {
        let cert = create_test_cert("CN=example.com,O=Test", vec![]);
        let domains = DnsOnlyMode::extract_domains(&cert);

        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "example.com");
    }

    #[test]
    fn test_no_cn() {
        let cert = create_test_cert("O=Test Org,C=US", vec!["example.com".to_string()]);
        let domains = DnsOnlyMode::extract_domains(&cert);

        // Should only have the SAN entry
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "example.com");
    }

    #[test]
    fn test_sorting() {
        let cert = create_test_cert(
            "CN=zebra.example.com,O=Test",
            vec![
                "apple.example.com".to_string(),
                "middle.example.com".to_string(),
            ],
        );
        let domains = DnsOnlyMode::extract_domains(&cert);

        // Domains should be sorted alphabetically
        assert_eq!(domains[0], "apple.example.com");
        assert_eq!(domains[1], "middle.example.com");
        assert_eq!(domains[2], "zebra.example.com");
    }
}
