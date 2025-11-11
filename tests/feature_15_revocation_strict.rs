/// Tests for Feature 15: Hard Fail on Revocation Errors
///
/// This test file verifies the strict revocation checking functionality,
/// which can hard-fail when revocation checks encounter errors.
#[cfg(test)]
mod revocation_strict_tests {
    use cipherrun::certificates::revocation::{
        RevocationMethod, RevocationResult, RevocationStatus,
    };
    use cipherrun::certificates::revocation_strict::{
        StrictRevocationChecker, StrictRevocationCheckerBuilder, StrictRevocationResult,
    };

    #[test]
    fn test_builder_defaults() {
        let checker = StrictRevocationCheckerBuilder::new().build();
        assert!(!checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_builder_with_hard_fail() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(true)
            .build();
        assert!(checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_builder_with_phone_out() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_phone_out(true)
            .build();
        assert!(checker.is_phone_out_enabled());
    }

    #[test]
    fn test_builder_fluent_api() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_phone_out(true)
            .with_hard_fail(true)
            .build();

        assert!(checker.is_hard_fail_enabled());
        assert!(checker.is_phone_out_enabled());
    }

    #[test]
    fn test_strict_result_status_good() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: RevocationMethod::OCSP,
                details: "Certificate is good".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(result.is_good());
        assert!(!result.is_revoked());
        assert!(!result.is_unknown());
        assert!(!result.is_error());
    }

    #[test]
    fn test_strict_result_status_revoked() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Revoked,
                method: RevocationMethod::OCSP,
                details: "Certificate is revoked".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(!result.is_good());
        assert!(result.is_revoked());
        assert!(!result.is_unknown());
        assert!(!result.is_error());
    }

    #[test]
    fn test_strict_result_status_unknown() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Unknown,
                method: RevocationMethod::None,
                details: "Revocation status unknown".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(!result.is_good());
        assert!(!result.is_revoked());
        assert!(result.is_unknown());
        assert!(!result.is_error());
    }

    #[test]
    fn test_strict_result_status_error() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Error,
                method: RevocationMethod::None,
                details: "Revocation check failed".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: Some("OCSP responder timeout".to_string()),
        };

        assert!(!result.is_good());
        assert!(!result.is_revoked());
        assert!(!result.is_unknown());
        assert!(result.is_error());
    }

    #[test]
    fn test_strict_result_getters() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: RevocationMethod::OCSP,
                details: "Test details".to_string(),
                ocsp_stapling: true,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert_eq!(result.status(), RevocationStatus::Good);
        assert_eq!(result.method(), RevocationMethod::OCSP);
        assert_eq!(result.details(), "Test details");
    }

    #[test]
    fn test_hard_fail_disabled_by_default() {
        let checker = StrictRevocationChecker::new(false, false);
        assert!(!checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_phone_out_disabled_by_default() {
        let checker = StrictRevocationChecker::new(false, false);
        // This property should return false when disabled
        assert!(!checker.is_phone_out_enabled());
    }

    #[test]
    fn test_builder_default_instance() {
        let builder = StrictRevocationCheckerBuilder::default();
        let checker = builder.build();

        assert!(!checker.is_hard_fail_enabled());
        assert!(!checker.is_phone_out_enabled());
    }

    #[test]
    fn test_strict_result_with_error_details() {
        let error_details = "OCSP responder returned invalid response".to_string();
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Unknown,
                method: RevocationMethod::None,
                details: "Check failed".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: Some(error_details.clone()),
        };

        assert_eq!(result.error_details, Some(error_details));
    }

    #[test]
    fn test_strict_result_crl_method() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: RevocationMethod::CRL,
                details: "Verified via CRL".to_string(),
                ocsp_stapling: false,
                must_staple: false,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(result.is_good());
        assert_eq!(result.method(), RevocationMethod::CRL);
    }

    #[test]
    fn test_strict_result_ocsp_stapling_method() {
        let result = StrictRevocationResult {
            base_result: RevocationResult {
                status: RevocationStatus::Good,
                method: RevocationMethod::OCSPStapling,
                details: "OCSP stapling response verified".to_string(),
                ocsp_stapling: true,
                must_staple: true,
            },
            hard_fail_applied: false,
            error_details: None,
        };

        assert!(result.is_good());
        assert_eq!(result.method(), RevocationMethod::OCSPStapling);
    }

    #[test]
    fn test_hard_fail_mode_creation() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(true)
            .with_phone_out(true)
            .build();

        assert!(checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_soft_fail_mode_creation() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(false)
            .with_phone_out(true)
            .build();

        assert!(!checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_revocation_disabled_mode() {
        let checker = StrictRevocationCheckerBuilder::new()
            .with_phone_out(false)
            .with_hard_fail(false)
            .build();

        assert!(!checker.is_phone_out_enabled());
        assert!(!checker.is_hard_fail_enabled());
    }

    #[test]
    fn test_multiple_builder_instances() {
        let checker1 = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(true)
            .build();

        let checker2 = StrictRevocationCheckerBuilder::new()
            .with_hard_fail(false)
            .build();

        assert!(checker1.is_hard_fail_enabled());
        assert!(!checker2.is_hard_fail_enabled());
    }
}
