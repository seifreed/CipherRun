use super::CbcCipherSupportStatus;

/// Lucky13 test result.
#[derive(Debug, Clone)]
pub struct Lucky13TestResult {
    pub vulnerable: bool,
    pub partially_vulnerable: bool,
    pub cbc_supported: bool,
    pub inconclusive: bool,
    pub details: String,
}

impl Lucky13TestResult {
    pub(super) fn from_cbc_status(cbc_status: CbcCipherSupportStatus) -> Self {
        match cbc_status {
            CbcCipherSupportStatus::Inconclusive => Self {
                vulnerable: false,
                partially_vulnerable: false,
                cbc_supported: false,
                inconclusive: true,
                details: "Lucky13 assessment inconclusive - unable to determine CBC cipher support"
                    .to_string(),
            },
            CbcCipherSupportStatus::Supported => Self {
                vulnerable: false,
                partially_vulnerable: true,
                cbc_supported: true,
                inconclusive: false,
                details:
                    "Server supports CBC cipher suites, which are in the class susceptible to the \
                     Lucky13 timing attack (CVE-2013-0169). Whether the TLS implementation includes \
                     the constant-time MAC mitigation cannot be confirmed by remote timing (the \
                     difference is below network-jitter resolution). Recommendation: prefer AEAD \
                     cipher suites (AES-GCM, ChaCha20-Poly1305) and disable CBC."
                        .to_string(),
            },
            CbcCipherSupportStatus::NotSupported => Self {
                vulnerable: false,
                partially_vulnerable: false,
                cbc_supported: false,
                inconclusive: false,
                details: "Not vulnerable - server does not support CBC cipher suites".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_cbc_marks_partial_vulnerability() {
        let result = Lucky13TestResult::from_cbc_status(CbcCipherSupportStatus::Supported);

        assert!(!result.vulnerable);
        assert!(result.partially_vulnerable);
        assert!(result.cbc_supported);
    }

    #[test]
    fn inconclusive_cbc_marks_result_inconclusive() {
        let result = Lucky13TestResult::from_cbc_status(CbcCipherSupportStatus::Inconclusive);

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(!result.cbc_supported);
    }
}
