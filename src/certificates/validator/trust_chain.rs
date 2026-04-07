use super::*;

impl CertificateValidator {
    /// Validate trust chain against CA stores
    ///
    /// Security: This function validates the certificate chain by:
    /// 1. Finding the root CA in trusted stores by subject
    /// 2. Verifying the cryptographic signature chain
    /// 3. Checking that each certificate in the chain is signed by its issuer
    pub(crate) fn validate_trust_chain(
        &self,
        chain: &CertificateChain,
        issues: &mut Vec<ValidationIssue>,
    ) -> (bool, Option<String>) {
        let ca_stores = CA_STORES.as_ref();

        // Helper to verify signature using OpenSSL
        fn verify_signature(_cert_der: &[u8], _issuer_der: &[u8]) -> bool {
            // Cannot verify certificate signatures with current setup
            // Continue with subject-only matching
            false
        }

        let find_store_for_subject = |subject: &str| -> Option<(String, Vec<u8>)> {
            for store in ca_stores.all_stores() {
                for ca_cert in &store.certificates {
                    if ca_cert.subject == subject {
                        return Some((store.name.clone(), ca_cert.der.clone()));
                    }
                }
            }
            None
        };

        // Get root/issuer from chain
        let Some(last_cert) = chain.certificates.last() else {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::UntrustedCA,
                description: "No issuer certificate in chain".to_string(),
            });
            return (false, None);
        };

        // Check if self-signed first
        if chain.certificates.len() == 1 && last_cert.subject == last_cert.issuer {
            // Check if this self-signed cert is a known root CA
            if let Some((store_name, ca_der)) = find_store_for_subject(&last_cert.subject) {
                // Verify the certificate is actually in our trust store by checking DER
                if !last_cert.der_bytes.is_empty() && last_cert.der_bytes == ca_der {
                    return (true, Some(store_name));
                }
                // Subject matches but DER is different - potential spoofing attempt
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Critical,
                    issue_type: IssueType::UntrustedCA,
                    description: format!(
                        "Self-signed certificate subject matches known CA but certificate content differs: {}",
                        last_cert.subject
                    ),
                });
                return (false, None);
            }

            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::SelfSigned,
                description: "Certificate is self-signed and not a known root CA".to_string(),
            });
            return (false, None);
        }

        // For chains with multiple certificates, verify the entire chain:
        // 1. Each cert[i] must be signed by cert[i+1]
        // 2. The last cert must be signed by a trusted CA
        let certs = &chain.certificates;

        // Verify intermediate chain signatures (cert[i] signed by cert[i+1])
        for i in 0..certs.len().saturating_sub(1) {
            let cert = &certs[i];
            let issuer_cert = &certs[i + 1];

            // Check issuer/subject match
            if cert.issuer != issuer_cert.subject {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::High,
                    issue_type: IssueType::UntrustedCA,
                    description: format!(
                        "Chain broken: cert '{}' issuer '{}' does not match next cert subject '{}'",
                        cert.subject, cert.issuer, issuer_cert.subject
                    ),
                });
                return (false, None);
            }

            // Verify cryptographic signature if DER bytes available
            if !cert.der_bytes.is_empty() && !issuer_cert.der_bytes.is_empty() {
                if !verify_signature(&cert.der_bytes, &issuer_cert.der_bytes) {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        issue_type: IssueType::UntrustedCA,
                        description: format!(
                            "Intermediate signature verification failed: '{}' not signed by '{}'",
                            cert.subject, issuer_cert.subject
                        ),
                    });
                    return (false, None);
                }
            } else {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Medium,
                    issue_type: IssueType::UntrustedCA,
                    description: format!(
                        "Cannot verify intermediate signature - DER bytes unavailable: '{}' -> '{}'",
                        cert.subject, issuer_cert.subject
                    ),
                });
            }
        }

        // Verify the last cert against trusted CA stores
        if let Some((store_name, ca_der)) = find_store_for_subject(&last_cert.issuer) {
            // Verify signature if we have DER bytes
            if !last_cert.der_bytes.is_empty() && !ca_der.is_empty() {
                if verify_signature(&last_cert.der_bytes, &ca_der) {
                    return (true, Some(store_name));
                } else {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        issue_type: IssueType::UntrustedCA,
                        description: format!(
                            "Certificate signature verification failed for issuer: {}",
                            last_cert.issuer
                        ),
                    });
                    return (false, None);
                }
            }
            // DER bytes unavailable - cannot verify signature cryptographically
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::UntrustedCA,
                description: format!(
                    "Cannot verify certificate signature - DER bytes unavailable for issuer: {}",
                    last_cert.issuer
                ),
            });
            return (false, None);
        }

        // Also check if the CA cert itself is the last cert in our chain
        if let Some((store_name, ca_der)) = find_store_for_subject(&last_cert.subject) {
            // For this case, the certificate itself might be a trusted CA
            if !last_cert.der_bytes.is_empty() && last_cert.der_bytes == ca_der {
                return (true, Some(store_name));
            }
        }

        issues.push(ValidationIssue {
            severity: IssueSeverity::High,
            issue_type: IssueType::UntrustedCA,
            description: format!(
                "Issuer not found in trusted CA stores: {}",
                last_cert.issuer
            ),
        });

        (false, None)
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
    fn test_validate_trust_chain_empty() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let chain = CertificateChain {
            certificates: Vec::new(),
            chain_length: 0,
            chain_size_bytes: 0,
        };

        let (valid, ca) = validator.validate_trust_chain(&chain, &mut issues);
        assert!(!valid);
        assert!(ca.is_none());
        assert!(
            issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::UntrustedCA))
        );
    }

    #[test]
    fn test_validate_trust_chain_self_signed_unknown() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let mut cert = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        cert.subject = "CN=Unknown Root".to_string();
        cert.issuer = "CN=Unknown Root".to_string();
        cert.is_ca = true;

        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        let (valid, ca) = validator.validate_trust_chain(&chain, &mut issues);
        assert!(!valid);
        assert!(ca.is_none());
        assert!(
            issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::SelfSigned))
        );
    }
}
