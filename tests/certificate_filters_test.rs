// Integration tests for certificate validation filters

#![allow(clippy::field_reassign_with_default)]

use cipherrun::certificates::parser::{CertificateChain, CertificateInfo};
use cipherrun::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
use cipherrun::certificates::status::CertificateStatus;
use cipherrun::certificates::validator::{
    IssueSeverity, IssueType, ValidationIssue, ValidationResult,
};
use cipherrun::cli::Args;
use cipherrun::scanner::mass::MassScanner;
use cipherrun::scanner::{CertificateAnalysisResult, ScanResults};

/// Create a mock certificate for testing
fn create_mock_certificate(
    subject: &str,
    issuer: &str,
    not_after: &str,
    san: Vec<String>,
) -> CertificateInfo {
    CertificateInfo {
        subject: subject.to_string(),
        issuer: issuer.to_string(),
        serial_number: "123456".to_string(),
        not_before: "2024-01-01 00:00:00 UTC".to_string(),
        not_after: not_after.to_string(),
        expiry_countdown: None,
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key_algorithm: "rsaEncryption".to_string(),
        public_key_size: Some(2048),
        rsa_exponent: Some("e 65537".to_string()),
        san,
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

/// Create a mock validation result
fn create_mock_validation(
    valid: bool,
    issues: Vec<ValidationIssue>,
    not_expired: bool,
    hostname_match: bool,
    trust_chain_valid: bool,
) -> ValidationResult {
    ValidationResult {
        valid,
        issues,
        trust_chain_valid,
        hostname_match,
        not_expired,
        signature_valid: true,
        trusted_ca: Some("Mock CA".to_string()),
        platform_trust: None,
    }
}

/// Create a mock scan result for testing
fn create_mock_scan_result(
    target: &str,
    cert: CertificateInfo,
    validation: ValidationResult,
    revocation: Option<RevocationResult>,
) -> ScanResults {
    let chain = CertificateChain {
        certificates: vec![cert],
        chain_length: 1,
        chain_size_bytes: 1024,
    };

    let cert_analysis = CertificateAnalysisResult {
        chain,
        validation,
        revocation,
    };

    ScanResults {
        target: target.to_string(),
        certificate_chain: Some(cert_analysis),
        ..Default::default()
    }
}

#[test]
fn test_filter_expired_certificates() {
    // Create expired certificate
    let cert = create_mock_certificate(
        "CN=expired.com",
        "CN=CA",
        "2020-01-01 00:00:00 UTC", // Expired
        vec!["expired.com".to_string()],
    );

    let validation = create_mock_validation(
        false,
        vec![ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::Expired,
            description: "Certificate expired".to_string(),
        }],
        false, // not_expired = false
        true,
        true,
    );

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "expired.com", &cert, None);

    assert!(
        cert_status.is_expired,
        "Certificate should be detected as expired"
    );

    // Test filter matching
    let mut args = Args::default();
    args.cert_filters.filter_expired = true;

    assert!(
        cert_status.matches_filter(&args),
        "Expired certificate should match expired filter"
    );
}

#[test]
fn test_filter_self_signed_certificates() {
    // Create self-signed certificate (subject == issuer)
    let cert = create_mock_certificate(
        "CN=selfsigned.com",
        "CN=selfsigned.com", // Same as subject
        "2035-01-01 00:00:00 UTC",
        vec!["selfsigned.com".to_string()],
    );

    let validation = create_mock_validation(
        false,
        vec![ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::SelfSigned,
            description: "Self-signed certificate".to_string(),
        }],
        true,
        true,
        false,
    );

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "selfsigned.com", &cert, None);

    assert!(
        cert_status.is_self_signed,
        "Certificate should be detected as self-signed"
    );

    // Test filter matching
    let mut args = Args::default();
    args.cert_filters.filter_self_signed = true;

    assert!(
        cert_status.matches_filter(&args),
        "Self-signed certificate should match self-signed filter"
    );
}

#[test]
fn test_filter_mismatched_certificates() {
    // Create certificate with hostname mismatch
    let cert = create_mock_certificate(
        "CN=example.com",
        "CN=CA",
        "2035-01-01 00:00:00 UTC",
        vec!["example.com".to_string()],
    );

    let validation = create_mock_validation(
        false,
        vec![ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::HostnameMismatch,
            description: "Hostname mismatch".to_string(),
        }],
        true,
        false, // hostname_match = false
        true,
    );

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "different.com", &cert, None);

    assert!(
        cert_status.is_mismatched,
        "Certificate should be detected as mismatched"
    );

    // Test filter matching
    let mut args = Args::default();
    args.cert_filters.filter_mismatched = true;

    assert!(
        cert_status.matches_filter(&args),
        "Mismatched certificate should match mismatched filter"
    );
}

#[test]
fn test_filter_revoked_certificates() {
    let cert = create_mock_certificate(
        "CN=revoked.com",
        "CN=CA",
        "2035-01-01 00:00:00 UTC",
        vec!["revoked.com".to_string()],
    );

    let validation = create_mock_validation(true, vec![], true, true, true);

    let revocation = RevocationResult {
        status: RevocationStatus::Revoked,
        method: RevocationMethod::OCSP,
        details: "Certificate revoked".to_string(),
        ocsp_stapling: false,
        must_staple: false,
    };

    let cert_status = CertificateStatus::from_validation_result(
        &validation,
        "revoked.com",
        &cert,
        Some(&revocation),
    );

    assert!(
        cert_status.is_revoked,
        "Certificate should be detected as revoked"
    );

    // Test filter matching
    let mut args = Args::default();
    args.cert_filters.filter_revoked = true;

    assert!(
        cert_status.matches_filter(&args),
        "Revoked certificate should match revoked filter"
    );
}

#[test]
fn test_filter_untrusted_certificates() {
    let cert = create_mock_certificate(
        "CN=untrusted.com",
        "CN=Unknown CA",
        "2035-01-01 00:00:00 UTC",
        vec!["untrusted.com".to_string()],
    );

    let validation = create_mock_validation(
        false,
        vec![ValidationIssue {
            severity: IssueSeverity::High,
            issue_type: IssueType::UntrustedCA,
            description: "Untrusted CA".to_string(),
        }],
        true,
        true,
        false, // trust_chain_valid = false
    );

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "untrusted.com", &cert, None);

    assert!(
        cert_status.is_untrusted,
        "Certificate should be detected as untrusted"
    );

    // Test filter matching
    let mut args = Args::default();
    args.cert_filters.filter_untrusted = true;

    assert!(
        cert_status.matches_filter(&args),
        "Untrusted certificate should match untrusted filter"
    );
}

#[test]
fn test_multiple_filters_or_logic() {
    // Create a certificate that is both expired AND self-signed
    let cert = create_mock_certificate(
        "CN=bad.com",
        "CN=bad.com",              // Self-signed
        "2020-01-01 00:00:00 UTC", // Expired
        vec!["bad.com".to_string()],
    );

    let validation = create_mock_validation(
        false,
        vec![
            ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: "Expired".to_string(),
            },
            ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::SelfSigned,
                description: "Self-signed".to_string(),
            },
        ],
        false,
        true,
        false,
    );

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "bad.com", &cert, None);

    // Test with only expired filter
    let mut args = Args::default();
    args.cert_filters.filter_expired = true;
    assert!(
        cert_status.matches_filter(&args),
        "Should match with expired filter"
    );

    // Test with only self-signed filter
    args = Args::default();
    args.cert_filters.filter_self_signed = true;
    assert!(
        cert_status.matches_filter(&args),
        "Should match with self-signed filter"
    );

    // Test with both filters (OR logic)
    args = Args::default();
    args.cert_filters.filter_expired = true;
    args.cert_filters.filter_self_signed = true;
    assert!(
        cert_status.matches_filter(&args),
        "Should match with either filter"
    );
}

#[test]
fn test_no_filters_active_shows_all() {
    let cert = create_mock_certificate(
        "CN=example.com",
        "CN=CA",
        "2035-01-01 00:00:00 UTC",
        vec!["example.com".to_string()],
    );

    let validation = create_mock_validation(true, vec![], true, true, true);

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "example.com", &cert, None);

    let args = Args::default(); // No filters active

    assert!(
        cert_status.matches_filter(&args),
        "Should match when no filters are active"
    );
}

#[test]
fn test_valid_certificate_filtered_out_when_filters_active() {
    // Create a valid certificate
    let cert = create_mock_certificate(
        "CN=valid.com",
        "CN=Trusted CA",
        "2035-12-31 00:00:00 UTC",
        vec!["valid.com".to_string()],
    );

    let validation = create_mock_validation(true, vec![], true, true, true);

    let cert_status =
        CertificateStatus::from_validation_result(&validation, "valid.com", &cert, None);

    // When expired filter is active, valid cert should NOT match
    let mut args = Args::default();
    args.cert_filters.filter_expired = true;

    assert!(
        !cert_status.matches_filter(&args),
        "Valid certificate should not match expired filter"
    );
}

#[test]
fn test_mass_scanner_filtering() {
    // Create test scan results with different certificate issues
    let expired_cert = create_mock_certificate(
        "CN=expired.com",
        "CN=CA",
        "2020-01-01 00:00:00 UTC",
        vec!["expired.com".to_string()],
    );
    let expired_validation = create_mock_validation(
        false,
        vec![ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::Expired,
            description: "Expired".to_string(),
        }],
        false,
        true,
        true,
    );
    let expired_result =
        create_mock_scan_result("expired.com:443", expired_cert, expired_validation, None);

    let valid_cert = create_mock_certificate(
        "CN=valid.com",
        "CN=CA",
        "2035-12-31 00:00:00 UTC",
        vec!["valid.com".to_string()],
    );
    let valid_validation = create_mock_validation(true, vec![], true, true, true);
    let valid_result = create_mock_scan_result("valid.com:443", valid_cert, valid_validation, None);

    // Test filtering with expired filter
    let mut args = Args::default();
    args.cert_filters.filter_expired = true;

    let results_with_filter = vec![
        ("expired.com:443".to_string(), Ok(expired_result.clone())),
        ("valid.com:443".to_string(), Ok(valid_result.clone())),
    ];

    let filtered = MassScanner::filter_results(&args, results_with_filter);

    assert_eq!(filtered.len(), 1, "Should only return expired certificate");
    assert_eq!(filtered[0].0, "expired.com:443");

    // Test with no filters (should return all)
    let args_no_filter = Args::default();
    let results_no_filter = vec![
        ("expired.com:443".to_string(), Ok(expired_result)),
        ("valid.com:443".to_string(), Ok(valid_result)),
    ];
    let unfiltered = MassScanner::filter_results(&args_no_filter, results_no_filter);

    assert_eq!(
        unfiltered.len(),
        2,
        "Should return all results when no filters active"
    );
}

#[test]
fn test_has_certificate_filters() {
    let mut args = Args::default();
    assert!(
        !args.has_certificate_filters(),
        "Default args should have no filters"
    );

    args.cert_filters.filter_expired = true;
    assert!(
        args.has_certificate_filters(),
        "Should detect expired filter"
    );

    args = Args::default();
    args.cert_filters.filter_self_signed = true;
    assert!(
        args.has_certificate_filters(),
        "Should detect self-signed filter"
    );

    args = Args::default();
    args.cert_filters.filter_mismatched = true;
    assert!(
        args.has_certificate_filters(),
        "Should detect mismatched filter"
    );

    args = Args::default();
    args.cert_filters.filter_revoked = true;
    assert!(
        args.has_certificate_filters(),
        "Should detect revoked filter"
    );

    args = Args::default();
    args.cert_filters.filter_untrusted = true;
    assert!(
        args.has_certificate_filters(),
        "Should detect untrusted filter"
    );
}
