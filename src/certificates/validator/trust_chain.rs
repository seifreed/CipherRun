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
        fn verify_signature(cert_der: &[u8], issuer_der: &[u8]) -> bool {
            use openssl::x509::X509;

            // Parse the certificate from DER bytes
            let cert = match X509::from_der(cert_der) {
                Ok(c) => c,
                Err(_) => {
                    tracing::debug!("Failed to parse certificate DER bytes");
                    return false;
                }
            };

            // Parse the issuer certificate from DER bytes
            let issuer = match X509::from_der(issuer_der) {
                Ok(c) => c,
                Err(_) => {
                    tracing::debug!("Failed to parse issuer certificate DER bytes");
                    return false;
                }
            };

            // Get issuer's public key
            let issuer_pkey = match issuer.public_key() {
                Ok(pk) => pk,
                Err(_) => {
                    tracing::debug!("Failed to extract issuer public key");
                    return false;
                }
            };

            // Verify the certificate's signature using issuer's public key
            cert.verify(&issuer_pkey).unwrap_or(false)
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
                // DER bytes unavailable for a known CA subject - add warning but try to verify
                if last_cert.der_bytes.is_empty() {
                    // Can't cryptographically verify, but subject matches a known CA
                    // This is a medium-severity issue, not critical
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Medium,
                        issue_type: IssueType::UntrustedCA,
                        description: format!(
                            "Self-signed certificate subject matches known CA '{}' but DER bytes unavailable for cryptographic verification. \
                             Manual verification recommended.",
                            last_cert.subject
                        ),
                    });
                    return (false, None);
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
                // DER bytes unavailable - this is a security concern
                // SECURITY: Default to strict mode for certificate validation
                // Use CIPHERUN_ALLOW_WEAK_CERT_VALIDATION=true to allow non-strict validation
                // (not recommended for production use)
                let strict_mode = !std::env::var("CIPHERUN_ALLOW_WEAK_CERT_VALIDATION")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false);

                if strict_mode {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Critical,
                        issue_type: IssueType::UntrustedCA,
                        description: format!(
                            "Cannot verify signature without DER bytes (strict mode): '{}' -> '{}'",
                            cert.subject, issuer_cert.subject
                        ),
                    });
                    return (false, None);
                } else {
                    tracing::warn!(
                        "SECURITY: Weak certificate validation enabled - signature verification skipped for '{}' -> '{}'. \
                         This reduces security. Remove CIPHERUN_ALLOW_WEAK_CERT_VALIDATION to restore strict validation.",
                        cert.subject,
                        issuer_cert.subject
                    );
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
            // SECURITY: In strict mode (default), this is a failure
            // Use CIPHERUN_ALLOW_WEAK_CERT_VALIDATION=true to allow non-strict validation
            let strict_mode = !std::env::var("CIPHERUN_ALLOW_WEAK_CERT_VALIDATION")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);

            if strict_mode {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Critical,
                    issue_type: IssueType::UntrustedCA,
                    description: format!(
                        "Cannot verify certificate signature without DER bytes (strict mode) for issuer: {}",
                        last_cert.issuer
                    ),
                });
                return (false, None);
            } else {
                tracing::warn!(
                    "SECURITY: Weak certificate validation enabled - signature verification skipped for root CA '{}'. \
                     This reduces security. Remove CIPHERUN_ALLOW_WEAK_CERT_VALIDATION to restore strict validation.",
                    last_cert.issuer
                );
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
        }

        // Note: We do NOT check if the last cert's subject matches a trusted CA here.
        // The chain validation requires that the issuer of the last cert be a trusted CA,
        // not that the last cert itself is a trusted CA. A chain where an intermediate
        // CA's subject matches a trusted CA name but is not signed by that CA is invalid.

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

    #[test]
    fn test_validate_trust_chain_self_signed_with_missing_der_fails_strict_mode() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let stores = CA_STORES.as_ref();
        let all_stores = stores.all_stores();
        let Some(first_store) = all_stores.first() else {
            panic!("Expected at least one CA store to be available");
        };

        let Some(known_ca) = first_store.certificates.first() else {
            panic!("Expected CA store to contain at least one certificate");
        };

        let cert = CertificateInfo {
            subject: known_ca.subject.clone(),
            issuer: known_ca.subject.clone(),
            is_ca: true,
            ..base_cert(
                "2024-01-01 00:00:00 +0000".to_string(),
                "2025-01-01 00:00:00 +0000".to_string(),
            )
        };

        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        let (valid, ca) = validator.validate_trust_chain(&chain, &mut issues);

        assert!(!valid);
        assert!(ca.is_none());
        assert!(
            issues.iter().any(|i| {
                i.issue_type == IssueType::UntrustedCA
                    && i.description.contains("DER bytes unavailable")
            }),
            "Expected strict-mode DER unavailable issue"
        );
    }

    #[test]
    fn test_validate_trust_chain_intermediate_missing_der_fails() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let stores = CA_STORES.as_ref();
        let all_stores = stores.all_stores();
        let Some(first_store) = all_stores.first() else {
            panic!("Expected at least one CA store to be available");
        };

        let Some(intermediate_ca) = first_store.certificates.first() else {
            panic!("Expected CA store to contain at least one certificate");
        };

        let mut leaf = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        leaf.subject = "CN=leaf.example.com".to_string();
        leaf.issuer = intermediate_ca.subject.clone();
        leaf.der_bytes = Vec::new();

        let mut issuer = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2025-01-01 00:00:00 +0000".to_string(),
        );
        issuer.subject = intermediate_ca.subject.clone();
        issuer.issuer = intermediate_ca.subject.clone();
        issuer.der_bytes = intermediate_ca.der.clone();
        issuer.is_ca = true;

        let chain = CertificateChain {
            certificates: vec![leaf, issuer],
            chain_length: 2,
            chain_size_bytes: 0,
        };

        let (valid, ca) = validator.validate_trust_chain(&chain, &mut issues);

        assert!(!valid);
        assert!(ca.is_none());
        assert!(
            issues.iter().any(|i| {
                i.issue_type == IssueType::UntrustedCA
                    && i.description
                        .contains("Cannot verify signature without DER bytes")
            }),
            "Expected missing-DER signature validation issue"
        );
    }
}
