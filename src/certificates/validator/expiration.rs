use super::*;

impl CertificateValidator {
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
                issue_type: IssueType::NotYetValid,
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
                issue_type: IssueType::Expired,
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
        if days_until_expiry < 30 && !self.skip_warnings {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::Expired,
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
        let mut issues = Vec::new();

        let future = (Utc::now() + chrono::Duration::days(10))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();
        let past = (Utc::now() - chrono::Duration::days(10))
            .format("%Y-%m-%d %H:%M:%S +0000")
            .to_string();

        let cert = base_cert(future.clone(), future.clone());
        assert!(!validator.check_expiration(&cert, &mut issues));

        let mut issues = Vec::new();
        let cert = base_cert(past.clone(), past.clone());
        assert!(!validator.check_expiration(&cert, &mut issues));
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_expiration_with_invalid_dates_returns_true() {
        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        let cert = base_cert("invalid".to_string(), "also invalid".to_string());
        // Fail-closed: unparseable dates should return false (invalid)
        assert!(!validator.check_expiration(&cert, &mut issues));
        // Should have high-severity issues about unparseable dates
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| matches!(
            i.issue_type,
            IssueType::NotYetValid | IssueType::Expired
        ) && i.description.contains("could not be parsed")));
    }
}
