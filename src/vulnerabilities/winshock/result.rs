use super::{MalformedHandshakeStatus, SchannelDetectionStatus};

/// Winshock test result.
#[derive(Debug, Clone)]
pub struct WinshockTestResult {
    pub vulnerable: bool,
    pub schannel_detected: bool,
    pub inconclusive: bool,
    pub details: String,
}

impl WinshockTestResult {
    pub(super) fn inconclusive_schannel_probe() -> Self {
        Self {
            vulnerable: false,
            schannel_detected: false,
            inconclusive: true,
            details: "Winshock test inconclusive - unable to connect to target to detect Schannel"
                .to_string(),
        }
    }

    pub(super) fn from_probe_status(
        schannel_status: SchannelDetectionStatus,
        malformed_status: Option<MalformedHandshakeStatus>,
    ) -> Self {
        let schannel_detected = schannel_status == SchannelDetectionStatus::Detected;

        match (schannel_status, malformed_status) {
            (SchannelDetectionStatus::Detected, Some(MalformedHandshakeStatus::Handled)) => Self {
                vulnerable: false,
                schannel_detected: true,
                inconclusive: false,
                details:
                    "Schannel detected but Winshock test passed - Likely patched or protected"
                        .to_string(),
            },
            (SchannelDetectionStatus::Detected, Some(MalformedHandshakeStatus::Inconclusive)) => {
                Self {
                    vulnerable: false,
                    schannel_detected: true,
                    inconclusive: true,
                    details: "Winshock test inconclusive - Schannel was detected, but malformed handshake probe did not produce conclusive evidence".to_string(),
                }
            }
            _ => Self {
                vulnerable: false,
                schannel_detected,
                inconclusive: false,
                details: "Not vulnerable - Schannel not detected".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_schannel_probe_marks_result_inconclusive() {
        let result = WinshockTestResult::inconclusive_schannel_probe();

        assert!(!result.vulnerable);
        assert!(!result.schannel_detected);
        assert!(result.inconclusive);
    }

    #[test]
    fn detected_inconclusive_malformed_probe_preserves_schannel_signal() {
        let result = WinshockTestResult::from_probe_status(
            SchannelDetectionStatus::Detected,
            Some(MalformedHandshakeStatus::Inconclusive),
        );

        assert!(!result.vulnerable);
        assert!(result.schannel_detected);
        assert!(result.inconclusive);
    }
}
