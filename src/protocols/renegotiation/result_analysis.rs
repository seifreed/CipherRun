use super::{InsecureRenegotiationResult, RenegotiationSupport, RenegotiationTestResult};

pub(super) fn failed_secure_extension_probe(
    insecure_result: InsecureRenegotiationResult,
) -> RenegotiationTestResult {
    if matches!(insecure_result, InsecureRenegotiationResult::Detected) {
        return RenegotiationTestResult {
            support: RenegotiationSupport::InsecureRenegotiation,
            secure_extension: false,
            vulnerable: true,
            needs_verification: false,
            inconclusive: false,
            details: vulnerable_details(),
        };
    }

    RenegotiationTestResult {
        support: RenegotiationSupport::Inconclusive,
        secure_extension: false,
        vulnerable: false,
        needs_verification: true,
        inconclusive: true,
        details: "Renegotiation support unclear - secure extension probe did not complete"
            .to_string(),
    }
}

pub(super) fn support_without_secure_extension(
    insecure_result: InsecureRenegotiationResult,
    fallback_support: RenegotiationSupport,
) -> RenegotiationSupport {
    if matches!(insecure_result, InsecureRenegotiationResult::Detected) {
        return RenegotiationSupport::InsecureRenegotiation;
    }

    match fallback_support {
        RenegotiationSupport::SecureRenegotiation => RenegotiationSupport::NotSupported,
        other => other,
    }
}

pub(super) fn final_result(
    support: RenegotiationSupport,
    secure_extension: bool,
    insecure_result: InsecureRenegotiationResult,
) -> RenegotiationTestResult {
    let needs_verification = matches!(insecure_result, InsecureRenegotiationResult::Inconclusive)
        || matches!(support, RenegotiationSupport::Inconclusive);
    let vulnerable = matches!(support, RenegotiationSupport::InsecureRenegotiation);

    RenegotiationTestResult {
        support,
        secure_extension,
        vulnerable,
        needs_verification,
        inconclusive: needs_verification,
        details: details_for(support, needs_verification),
    }
}

fn details_for(support: RenegotiationSupport, needs_verification: bool) -> String {
    match support {
        RenegotiationSupport::SecureRenegotiation => {
            "Secure renegotiation supported (RFC 5746)".to_string()
        }
        RenegotiationSupport::InsecureRenegotiation => vulnerable_details(),
        RenegotiationSupport::ClientInitiatedDisabled => {
            "Client-initiated renegotiation disabled (secure configuration)".to_string()
        }
        RenegotiationSupport::NotSupported => {
            if needs_verification {
                "Renegotiation support unclear - server responded without renegotiation_info extension. \
                 Manual verification recommended for CVE-2009-3555."
                    .to_string()
            } else {
                "Renegotiation not supported".to_string()
            }
        }
        RenegotiationSupport::Inconclusive => {
            "Renegotiation support inconclusive - transport or handshake failures prevented a reliable result"
                .to_string()
        }
    }
}

fn vulnerable_details() -> String {
    "VULNERABLE: Insecure renegotiation enabled (CVE-2009-3555)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_secure_fallback_when_extension_is_missing() {
        assert_eq!(
            support_without_secure_extension(
                InsecureRenegotiationResult::NotDetected,
                RenegotiationSupport::SecureRenegotiation,
            ),
            RenegotiationSupport::NotSupported
        );
    }

    #[test]
    fn detected_insecure_renegotiation_wins_over_failed_extension_probe() {
        let result = failed_secure_extension_probe(InsecureRenegotiationResult::Detected);

        assert_eq!(result.support, RenegotiationSupport::InsecureRenegotiation);
        assert!(result.vulnerable);
        assert!(!result.needs_verification);
    }

    #[test]
    fn final_result_marks_inconclusive_as_needing_verification() {
        let result = final_result(
            RenegotiationSupport::NotSupported,
            false,
            InsecureRenegotiationResult::Inconclusive,
        );

        assert!(result.needs_verification);
        assert!(result.inconclusive);
        assert!(!result.vulnerable);
    }
}
