use super::{EarlyDataSizeInfo, EarlyDataSupportStatus, ReplayTestResult};

pub(super) fn classify_pair(
    first: EarlyDataSupportStatus,
    second: EarlyDataSupportStatus,
) -> ReplayTestResult {
    match (first, second) {
        (EarlyDataSupportStatus::Supported, EarlyDataSupportStatus::Supported) => {
            ReplayTestResult {
                tested: true,
                vulnerable: true,
                inconclusive: false,
                details: "Server accepted the same 0-RTT request on two resumed connections"
                    .to_string(),
            }
        }
        (EarlyDataSupportStatus::Supported, EarlyDataSupportStatus::NotSupported) => {
            ReplayTestResult {
                tested: true,
                vulnerable: false,
                inconclusive: false,
                details: "Server accepted initial 0-RTT data but rejected replayed early data"
                    .to_string(),
            }
        }
        (EarlyDataSupportStatus::NotSupported, _) => ReplayTestResult {
            tested: true,
            vulnerable: false,
            inconclusive: false,
            details: "Server did not accept resumed 0-RTT data during replay probe".to_string(),
        },
        _ => ReplayTestResult {
            tested: false,
            vulnerable: false,
            inconclusive: true,
            details: "Early Data replay test inconclusive - no probe result".to_string(),
        },
    }
}

pub(super) fn inconclusive_with_size(info: &EarlyDataSizeInfo) -> ReplayTestResult {
    ReplayTestResult {
        tested: false,
        vulnerable: false,
        inconclusive: true,
        details: format!(
            "Early Data replay test inconclusive (max: {} bytes, estimated: {})",
            info.max_early_data_size
                .map(|size| size.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            info.is_estimated
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_replayed_early_data_as_vulnerable() {
        let result = classify_pair(
            EarlyDataSupportStatus::Supported,
            EarlyDataSupportStatus::Supported,
        );
        assert!(result.tested);
        assert!(result.vulnerable);
        assert!(!result.inconclusive);
    }

    #[test]
    fn classifies_rejected_replay_as_not_vulnerable() {
        let result = classify_pair(
            EarlyDataSupportStatus::Supported,
            EarlyDataSupportStatus::NotSupported,
        );
        assert!(result.tested);
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
    }

    #[test]
    fn includes_size_context_for_inconclusive_results() {
        let info = EarlyDataSizeInfo {
            tls13_supported: true,
            early_data_supported: true,
            max_early_data_size: Some(16384),
            is_estimated: true,
            inconclusive: false,
        };

        let result = inconclusive_with_size(&info);
        assert!(result.inconclusive);
        assert!(result.details.contains("16384"));
    }
}
