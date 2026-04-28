// Certificate Status - Detect certificate validation status for filtering

use super::parser::CertificateInfo;
use super::revocation::{RevocationResult, RevocationStatus};
use super::validator::{IssueType, ValidationResult, parse_cert_date};
use crate::application::CertificateFilters;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Certificate validation status for filtering
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateStatus {
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub is_mismatched: bool,
    pub is_revoked: bool,
    pub is_untrusted: bool,
}

impl CertificateStatus {
    /// Create CertificateStatus from validation result
    ///
    /// Analyzes the validation result to determine the certificate status
    /// for each filter category.
    ///
    /// # Arguments
    /// * `validation` - Certificate validation result
    /// * `hostname` - Expected hostname for mismatch detection
    /// * `cert` - Certificate information
    /// * `revocation` - Optional revocation check result
    ///
    /// # Returns
    /// CertificateStatus with all status flags set
    pub fn from_validation_result(
        validation: &ValidationResult,
        hostname: &str,
        cert: &CertificateInfo,
        revocation: Option<&RevocationResult>,
    ) -> Self {
        // Check if expired
        let is_expired = Self::detect_expired(validation, cert);

        // Check if self-signed
        let is_self_signed = Self::detect_self_signed(validation, cert);

        // Check if hostname mismatched
        let is_mismatched = Self::detect_mismatched(validation, hostname, cert);

        // Check if revoked
        let is_revoked = Self::detect_revoked(revocation);

        // Check if untrusted
        let is_untrusted = Self::detect_untrusted(validation);

        Self {
            is_expired,
            is_self_signed,
            is_mismatched,
            is_revoked,
            is_untrusted,
        }
    }

    /// Check if this certificate matches the active filters
    ///
    /// Returns true only if:
    /// - No filters are active (show all), OR
    /// - At least one active filter matches this certificate's status
    ///
    /// This implements OR logic: if any filter matches, the cert is shown.
    ///
    /// # Arguments
    /// * `filters` - certificate filter configuration
    ///
    /// # Returns
    /// true if certificate should be displayed, false if it should be filtered out
    pub fn matches_filter(&self, filters: &CertificateFilters) -> bool {
        // If no filters are active, show everything
        if !filters.has_filters() {
            return true;
        }

        (filters.expired && self.is_expired)
            || (filters.self_signed && self.is_self_signed)
            || (filters.mismatched && self.is_mismatched)
            || (filters.revoked && self.is_revoked)
            || (filters.untrusted && self.is_untrusted)
    }

    /// Detect if certificate is expired
    fn detect_expired(validation: &ValidationResult, cert: &CertificateInfo) -> bool {
        // Check validation issues first
        if validation.issues.iter().any(|issue| {
            matches!(
                issue.issue_type,
                IssueType::Expired | IssueType::InvalidDate
            )
        }) {
            return true;
        }

        // Also check the not_expired flag
        if !validation.not_expired {
            return true;
        }

        // Fallback: parse certificate dates directly
        if let Some(not_after) = parse_cert_date(&cert.not_after)
            && Utc::now() > not_after
        {
            return true;
        }

        false
    }

    /// Detect if certificate is self-signed
    fn detect_self_signed(validation: &ValidationResult, cert: &CertificateInfo) -> bool {
        // Check validation issues first
        if validation
            .issues
            .iter()
            .any(|issue| matches!(issue.issue_type, IssueType::SelfSigned))
        {
            return true;
        }

        // Check if subject equals issuer (self-signed)
        cert.subject == cert.issuer
    }

    /// Detect if certificate has hostname mismatch
    fn detect_mismatched(
        validation: &ValidationResult,
        hostname: &str,
        cert: &CertificateInfo,
    ) -> bool {
        // Check validation issues first
        if validation
            .issues
            .iter()
            .any(|issue| matches!(issue.issue_type, IssueType::HostnameMismatch))
        {
            return true;
        }

        // Also check the hostname_match flag
        if !validation.hostname_match {
            return true;
        }

        // Fallback: check hostname against SANs manually
        let hostname_lower = hostname.to_lowercase();

        // Check Subject Alternative Names
        for san in &cert.san {
            if san.to_lowercase() == hostname_lower {
                return false; // Match found, not mismatched
            }

            // Check wildcard match (only matches exactly one subdomain level)
            if let Some(san_domain) = san.strip_prefix("*.")
                && !san_domain.is_empty()
                && san_domain.contains('.')
            {
                let domain_suffix = format!(".{}", san_domain.to_lowercase());
                if hostname_lower.ends_with(&domain_suffix) {
                    let prefix = &hostname_lower[..hostname_lower.len() - domain_suffix.len()];
                    if !prefix.is_empty() && !prefix.contains('.') {
                        return false; // Wildcard match found
                    }
                }
            }
        }

        // Check Common Name in subject (exact match with DN boundary)
        let subject_lower = cert.subject.to_lowercase();
        let cn_prefix = format!("cn={}", hostname_lower);
        if let Some(pos) = subject_lower.find(&cn_prefix) {
            let before_ok = pos == 0
                || subject_lower[..pos].ends_with(", ")
                || subject_lower[..pos].ends_with(',')
                || subject_lower[..pos].ends_with('/')
                || subject_lower[..pos].ends_with(' ');
            let after = pos + cn_prefix.len();
            let after_ok = after == subject_lower.len()
                || subject_lower[after..].starts_with(',')
                || subject_lower[after..].starts_with('/');
            if before_ok && after_ok {
                return false; // CN match found
            }
        }

        // No matches found - it's mismatched
        true
    }

    /// Detect if certificate is revoked
    fn detect_revoked(revocation: Option<&RevocationResult>) -> bool {
        if let Some(rev) = revocation {
            matches!(rev.status, RevocationStatus::Revoked)
        } else {
            false
        }
    }

    /// Detect if certificate is untrusted
    fn detect_untrusted(validation: &ValidationResult) -> bool {
        // Check validation issues first
        if validation
            .issues
            .iter()
            .any(|issue| matches!(issue.issue_type, IssueType::UntrustedCA))
        {
            return true;
        }

        // Check if trust chain is invalid
        if !validation.trust_chain_valid {
            return true;
        }

        // Check platform trust if available
        if let Some(ref platform_trust) = validation.platform_trust {
            // If overall trust is false, consider it untrusted
            if !platform_trust.overall_trusted {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::CertificateFilters;
    use crate::certificates::validator::{IssueSeverity, ValidationIssue};

    #[test]
    fn test_detect_expired() {
        let validation = ValidationResult {
            valid: false,
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: "Certificate expired".to_string(),
            }],
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: false,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };

        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            not_after: "2020-01-01 00:00:00 UTC".to_string(),
            ..Default::default()
        };

        assert!(
            CertificateStatus::detect_expired(&validation, &cert),
            "Should detect expired certificate"
        );
    }

    #[test]
    fn test_detect_expired_fallback_parses_numeric_timezone_offsets() {
        let validation = ValidationResult {
            valid: true,
            issues: vec![],
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            not_after: (Utc::now() - chrono::Duration::minutes(5))
                .format("%Y-%m-%d %H:%M:%S +0000")
                .to_string(),
            ..Default::default()
        };

        assert!(
            CertificateStatus::detect_expired(&validation, &cert),
            "fallback should detect expired certificates with numeric timezone offsets"
        );
    }

    #[test]
    fn test_detect_self_signed() {
        let validation = ValidationResult {
            valid: false,
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::SelfSigned,
                description: "Self-signed certificate".to_string(),
            }],
            trust_chain_valid: false,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };

        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(), // Same as subject
            ..Default::default()
        };

        assert!(
            CertificateStatus::detect_self_signed(&validation, &cert),
            "Should detect self-signed certificate"
        );
    }

    #[test]
    fn test_detect_mismatched() {
        let validation = ValidationResult {
            valid: false,
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::HostnameMismatch,
                description: "Hostname mismatch".to_string(),
            }],
            trust_chain_valid: true,
            hostname_match: false,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };

        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            san: vec!["example.com".to_string()],
            ..Default::default()
        };

        assert!(
            CertificateStatus::detect_mismatched(&validation, "different.com", &cert),
            "Should detect hostname mismatch"
        );
    }

    #[test]
    fn test_matches_filter_no_filters_active() {
        let status = CertificateStatus {
            is_expired: true,
            is_self_signed: true,
            is_mismatched: false,
            is_revoked: false,
            is_untrusted: false,
        };

        let filters = CertificateFilters::default();

        assert!(
            status.matches_filter(&filters),
            "Should match when no filters are active"
        );
    }

    #[test]
    fn test_detect_revoked_none() {
        assert!(!CertificateStatus::detect_revoked(None));
    }

    #[test]
    fn test_matches_filter_expired_filter() {
        let status = CertificateStatus {
            is_expired: true,
            is_self_signed: false,
            is_mismatched: false,
            is_revoked: false,
            is_untrusted: false,
        };

        let filters = CertificateFilters {
            expired: true,
            ..Default::default()
        };

        assert!(
            status.matches_filter(&filters),
            "Expired certificate should match expired filter"
        );

        // Test non-matching certificate
        let status_not_expired = CertificateStatus {
            is_expired: false,
            ..status
        };

        assert!(
            !status_not_expired.matches_filter(&filters),
            "Non-expired certificate should not match expired filter"
        );
    }

    #[test]
    fn test_matches_filter_multiple_filters() {
        let status = CertificateStatus {
            is_expired: false,
            is_self_signed: true,
            is_mismatched: false,
            is_revoked: false,
            is_untrusted: false,
        };

        let filters = CertificateFilters {
            expired: true,
            self_signed: true,
            ..Default::default()
        };

        assert!(
            status.matches_filter(&filters),
            "Self-signed certificate should match when self-signed filter is active"
        );
    }

    #[test]
    fn test_parse_certificate_date() {
        // Test various date formats
        assert!(parse_cert_date("2025-01-01 00:00:00 UTC").is_some());
        assert!(parse_cert_date("2025-01-01T00:00:00Z").is_some());
        assert!(parse_cert_date("Jan 01 00:00:00 2025 GMT").is_some());
        assert!(parse_cert_date("2025-01-01 00:00:00 +0000").is_some());
    }
}
