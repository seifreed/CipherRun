use super::*;

impl CertificateValidator {
    /// Check the validity period of every intermediate certificate in the chain.
    ///
    /// The leaf is checked separately by [`Self::check_expiration`]. A self-signed
    /// root is skipped: its validity is governed by trust-store membership, not by
    /// the presented chain (mirroring how chain signature checks skip the root).
    ///
    /// Browsers reject a path that contains an expired or not-yet-valid
    /// intermediate, so without this a chain anchored by an expired intermediate
    /// CA (a recurring real-world incident, e.g. Sectigo AddTrust 2020) would be
    /// reported valid. Returns `false` if any intermediate is outside its
    /// validity window or carries an unparseable date (fail-closed).
    pub(crate) fn check_chain_expiration(
        &self,
        chain: &CertificateChain,
        issues: &mut Vec<ValidationIssue>,
    ) -> bool {
        let now = Utc::now();
        let mut all_valid = true;

        for cert in chain.certificates.iter().skip(1) {
            if cert.subject == cert.issuer {
                continue;
            }

            let (Some(not_before), Some(not_after)) = (
                parse_cert_date(&cert.not_before),
                parse_cert_date(&cert.not_after),
            ) else {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::High,
                    issue_type: IssueType::InvalidDate,
                    description: format!(
                        "Intermediate CA certificate '{}' has an unparseable validity date \
                         (not_before: '{}', not_after: '{}') — treating as invalid.",
                        cert.subject, cert.not_before, cert.not_after
                    ),
                });
                all_valid = false;
                continue;
            };

            if now < not_before {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Critical,
                    issue_type: IssueType::NotYetValid,
                    description: format!(
                        "Intermediate CA certificate '{}' is not yet valid (valid from: {})",
                        cert.subject, cert.not_before
                    ),
                });
                all_valid = false;
            } else if now > not_after {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Critical,
                    issue_type: IssueType::Expired,
                    description: format!(
                        "Intermediate CA certificate '{}' has expired (valid until: {})",
                        cert.subject, cert.not_after
                    ),
                });
                all_valid = false;
            }
        }

        all_valid
    }

    /// Check certificate expiration
    pub(crate) fn check_expiration(
        &self,
        cert: &CertificateInfo,
        issues: &mut Vec<ValidationIssue>,
    ) -> bool {
        let now = Utc::now();

        // Parse not_before date using the helper function
        // Fail-closed: unparseable dates are treated as invalid to prevent
        // bypassing expiration checks with malformed date formats.
        let Some(not_before) = parse_cert_date(&cert.not_before) else {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::InvalidDate,
                description: format!(
                    "Certificate date format could not be parsed (not_before: '{}'). \
                     Treating as invalid — unparseable dates cannot be trusted.",
                    cert.not_before
                ),
            });
            return false;
        };

        // Parse not_after date using the helper function
        let Some(not_after) = parse_cert_date(&cert.not_after) else {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::InvalidDate,
                description: format!(
                    "Certificate date format could not be parsed (not_after: '{}'). \
                     Treating as invalid — unparseable dates cannot be trusted.",
                    cert.not_after
                ),
            });
            return false;
        };

        // Check if certificate is not yet valid
        if now < not_before {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::NotYetValid,
                description: format!(
                    "Certificate not yet valid (valid from: {})",
                    cert.not_before
                ),
            });
            return false;
        }

        // Check if certificate has expired
        if now > not_after {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: format!("Certificate expired (valid until: {})", cert.not_after),
            });
            return false;
        }

        // Check if certificate expires soon (within 30 days)
        let days_until_expiry = (not_after - now).num_days();
        if days_until_expiry <= 30 && !self.skip_warnings {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::ExpiringSoon,
                description: format!(
                    "Certificate expires soon ({} days remaining)",
                    days_until_expiry
                ),
            });
        }

        true
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
    fn test_expiration_checks() {
        let validator = CertificateValidator::new("example.com".to_string());

        // Certificate not yet valid (not_before in the future)
        let mut issues = Vec::new();
        let future_start = (Utc::now() + chrono::Duration::days(10))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();
        let future_end = (Utc::now() + chrono::Duration::days(375))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();
        let cert = base_cert(future_start, future_end);
        assert!(!validator.check_expiration(&cert, &mut issues));
        assert!(
            issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::NotYetValid))
        );

        // Expired certificate (not_after in the past)
        let mut issues = Vec::new();
        let past_start = (Utc::now() - chrono::Duration::days(375))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();
        let past_end = (Utc::now() - chrono::Duration::days(10))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();
        let cert = base_cert(past_start, past_end);
        assert!(!validator.check_expiration(&cert, &mut issues));
        assert!(
            issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::Expired))
        );
    }

    #[test]
    fn test_chain_expiration_flags_expired_intermediate_but_not_self_signed_root() {
        use crate::certificates::parser::CertificateChain;

        let validator = CertificateValidator::new("example.com".to_string());

        // Leaf (index 0) is checked by check_expiration, not here.
        let leaf = base_cert(
            "2024-01-01 00:00:00 +0000".to_string(),
            "2099-01-01 00:00:00 +0000".to_string(),
        );

        // Intermediate: expired (not_after in the past) — must be flagged.
        let mut intermediate = base_cert(
            "2020-01-01 00:00:00 +0000".to_string(),
            "2021-01-01 00:00:00 +0000".to_string(),
        );
        intermediate.subject = "CN=Intermediate CA".to_string();
        intermediate.issuer = "CN=Root CA".to_string();

        // Root: self-signed and also expired — must NOT be flagged (trust is by
        // store membership, mirroring the chain signature-algorithm check).
        let mut root = base_cert(
            "2020-01-01 00:00:00 +0000".to_string(),
            "2021-01-01 00:00:00 +0000".to_string(),
        );
        root.subject = "CN=Root CA".to_string();
        root.issuer = "CN=Root CA".to_string();

        let chain = CertificateChain {
            certificates: vec![leaf, intermediate, root],
            chain_length: 3,
            chain_size_bytes: 0,
        };

        let mut issues = Vec::new();
        let ok = validator.check_chain_expiration(&chain, &mut issues);

        assert!(!ok, "an expired intermediate must invalidate the chain");
        let expired: Vec<_> = issues
            .iter()
            .filter(|i| matches!(i.issue_type, IssueType::Expired))
            .collect();
        assert_eq!(
            expired.len(),
            1,
            "exactly the expired intermediate should be flagged, not the self-signed root"
        );
        assert!(expired[0].description.contains("Intermediate"));
    }

    #[test]
    fn test_expiration_with_invalid_dates_returns_false() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let cert = base_cert("invalid".to_string(), "also invalid".to_string());
        // Fail-closed: unparseable dates should return false (invalid)
        assert!(!validator.check_expiration(&cert, &mut issues));
        // Should have high-severity issues about unparseable dates
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::InvalidDate)
                    && i.description.contains("could not be parsed"))
        );
    }
}
