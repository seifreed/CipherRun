// Certificate Status - Detect certificate validation status for filtering

use super::parser::CertificateInfo;
use super::revocation::{RevocationResult, RevocationStatus};
use super::validator::{IssueType, ValidationResult};
use crate::cli::Args;
use chrono::{DateTime, Utc};
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
    /// * `args` - CLI arguments containing filter flags
    ///
    /// # Returns
    /// true if certificate should be displayed, false if it should be filtered out
    pub fn matches_filter(&self, args: &Args) -> bool {
        // If no filters are active, show everything
        if !args.has_certificate_filters() {
            return true;
        }

        // Check each active filter - if ANY match, show the certificate
        let mut matches = false;

        if args.filter_expired && self.is_expired {
            matches = true;
        }
        if args.filter_self_signed && self.is_self_signed {
            matches = true;
        }
        if args.filter_mismatched && self.is_mismatched {
            matches = true;
        }
        if args.filter_revoked && self.is_revoked {
            matches = true;
        }
        if args.filter_untrusted && self.is_untrusted {
            matches = true;
        }

        matches
    }

    /// Detect if certificate is expired
    fn detect_expired(validation: &ValidationResult, cert: &CertificateInfo) -> bool {
        // Check validation issues first
        if validation
            .issues
            .iter()
            .any(|issue| matches!(issue.issue_type, IssueType::Expired))
        {
            return true;
        }

        // Also check the not_expired flag
        if !validation.not_expired {
            return true;
        }

        // Fallback: parse certificate dates directly
        if let Ok(not_after) = parse_certificate_date(&cert.not_after) {
            if Utc::now() > not_after {
                return true;
            }
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

            // Check wildcard match
            if let Some(san_domain) = san.strip_prefix("*.")
                && hostname_lower.ends_with(san_domain)
            {
                return false; // Wildcard match found
            }
        }

        // Check Common Name in subject
        if cert
            .subject
            .to_lowercase()
            .contains(&format!("cn={}", hostname_lower))
        {
            return false; // CN match found
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

/// Parse certificate date string to DateTime<Utc>
///
/// Handles multiple date formats used in X.509 certificates
fn parse_certificate_date(date_str: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    use chrono::NaiveDateTime;

    // Try RFC3339 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try "YYYY-MM-DD HH:MM:SS UTC" format
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S UTC") {
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    // Try cleaned format without timezone suffix
    let cleaned = date_str.replace(" UTC", "").replace(" GMT", "");
    if let Ok(dt) = NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S") {
        return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    // Try "MMM DD HH:MM:SS YYYY GMT" format (common in OpenSSL output)
    // Note: chrono's %Z is unreliable for parsing timezone abbreviations, so we strip it
    if date_str.ends_with(" GMT") || date_str.ends_with(" UTC") {
        let without_tz = date_str.replace(" GMT", "").replace(" UTC", "");
        if let Ok(dt) = NaiveDateTime::parse_from_str(&without_tz, "%b %d %H:%M:%S %Y") {
            return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
    }

    // If all parsing attempts fail, return error by attempting to parse invalid data
    // This will return an appropriate ParseError
    NaiveDateTime::parse_from_str("invalid", "%Y-%m-%d %H:%M:%S")
        .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::validator::{IssueSeverity, ValidationIssue};

    #[test]
    fn test_detect_expired() {
        let mut validation = ValidationResult {
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

        let args = Args::default();

        assert!(
            status.matches_filter(&args),
            "Should match when no filters are active"
        );
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

        let mut args = Args::default();
        args.filter_expired = true;

        assert!(
            status.matches_filter(&args),
            "Expired certificate should match expired filter"
        );

        // Test non-matching certificate
        let status_not_expired = CertificateStatus {
            is_expired: false,
            ..status
        };

        assert!(
            !status_not_expired.matches_filter(&args),
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

        let mut args = Args::default();
        args.filter_expired = true;
        args.filter_self_signed = true;

        assert!(
            status.matches_filter(&args),
            "Self-signed certificate should match when self-signed filter is active"
        );
    }

    #[test]
    fn test_parse_certificate_date() {
        // Test various date formats
        assert!(parse_certificate_date("2025-01-01 00:00:00 UTC").is_ok());
        assert!(parse_certificate_date("2025-01-01T00:00:00Z").is_ok());
        assert!(parse_certificate_date("Jan 01 00:00:00 2025 GMT").is_ok());
    }
}
