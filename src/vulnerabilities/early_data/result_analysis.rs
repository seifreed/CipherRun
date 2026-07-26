use super::{EarlyDataSizeInfo, EarlyDataTestResult, ReplayTestResult};

pub(super) fn early_data_support_inconclusive() -> EarlyDataTestResult {
    EarlyDataTestResult {
        vulnerable: false,
        supports_early_data: false,
        accepts_replayed_data: false,
        max_early_data_size: None,
        issues: vec![
            "Early Data test inconclusive - unable to determine TLS 1.3 early_data support"
                .to_string(),
        ],
        details: "Early Data test inconclusive - target did not provide a usable TLS response"
            .to_string(),
        inconclusive: true,
    }
}

pub(super) fn early_data_not_supported() -> EarlyDataTestResult {
    EarlyDataTestResult {
        vulnerable: false,
        supports_early_data: false,
        accepts_replayed_data: false,
        max_early_data_size: None,
        issues: vec!["Server does not support TLS 1.3 early_data extension".to_string()],
        details: "Not vulnerable - Server does not support 0-RTT / early data".to_string(),
        inconclusive: false,
    }
}

pub(super) fn supported_early_data_result(
    early_data_info: &EarlyDataSizeInfo,
    replay_result: &ReplayTestResult,
) -> EarlyDataTestResult {
    let mut issues = vec!["Server supports TLS 1.3 early_data extension (0x002a)".to_string()];
    add_size_issue(&mut issues, early_data_info);
    add_replay_issue(&mut issues, replay_result);

    EarlyDataTestResult {
        vulnerable: replay_result.vulnerable,
        supports_early_data: true,
        accepts_replayed_data: replay_result.vulnerable,
        max_early_data_size: early_data_info.max_early_data_size,
        issues,
        details: details(early_data_info, replay_result),
        inconclusive: replay_result.inconclusive,
    }
}

fn add_size_issue(issues: &mut Vec<String>, early_data_info: &EarlyDataSizeInfo) {
    let Some(size) = early_data_info.max_early_data_size.filter(|size| *size > 0) else {
        return;
    };

    if early_data_info.is_estimated {
        issues.push(format!(
            "Server likely accepts up to {} bytes of early data (estimated, actual value requires session ticket parsing)",
            size
        ));
    } else {
        issues.push(format!("Server accepts up to {} bytes of early data", size));
    }
}

fn add_replay_issue(issues: &mut Vec<String>, replay_result: &ReplayTestResult) {
    if replay_result.inconclusive {
        issues
            .push("⚠️ 0-RTT replay test is inconclusive - manual testing recommended".to_string());
        issues.push(replay_result.details.clone());
    } else if replay_result.vulnerable {
        issues.push(
            "⚠️ Server accepts replayed 0-RTT data without proper anti-replay protection"
                .to_string(),
        );
        issues.push("This can allow replay attacks on sensitive operations".to_string());
    } else if replay_result.tested {
        issues.push("✓ Server appears to have anti-replay mechanisms in place".to_string());
    }
}

fn details(early_data_info: &EarlyDataSizeInfo, replay_result: &ReplayTestResult) -> String {
    let max_size = early_data_info
        .max_early_data_size
        .map(|size| size.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if replay_result.vulnerable {
        return format!(
            "Vulnerable to 0-RTT replay attacks - Server supports early_data and accepts replayed requests. \
            max_early_data_size: {}. Server should implement anti-replay mechanisms (single-use tickets, \
            time-based checks, or nonce tracking).",
            max_size
        );
    }

    if replay_result.inconclusive {
        return format!(
            "Inconclusive 0-RTT replay test - Server supports TLS 1.3 with early_data (max: {}). \
            Full replay testing was not performed. Potential vulnerability exists if server \
            lacks anti-replay mechanisms (single-use tickets, time-based checks, nonce tracking).",
            max_size
        );
    }

    "Server supports 0-RTT but appears to have anti-replay protection enabled".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn early_data_info() -> EarlyDataSizeInfo {
        EarlyDataSizeInfo {
            tls13_supported: true,
            early_data_supported: true,
            max_early_data_size: Some(16_384),
            is_estimated: true,
            inconclusive: false,
        }
    }

    #[test]
    fn unsupported_result_is_not_vulnerable() {
        let result = early_data_not_supported();

        assert!(!result.vulnerable);
        assert!(!result.supports_early_data);
        assert!(!result.inconclusive);
    }

    #[test]
    fn vulnerable_replay_sets_vulnerable_result() {
        let replay = ReplayTestResult {
            tested: true,
            vulnerable: true,
            inconclusive: false,
            details: "replayed".to_string(),
        };

        let result = supported_early_data_result(&early_data_info(), &replay);

        assert!(result.vulnerable);
        assert!(result.accepts_replayed_data);
        assert!(result.details.contains("Vulnerable to 0-RTT"));
    }

    #[test]
    fn inconclusive_replay_keeps_manual_testing_issue() {
        let replay = ReplayTestResult {
            tested: false,
            vulnerable: false,
            inconclusive: true,
            details: "could not replay".to_string(),
        };

        let result = supported_early_data_result(&early_data_info(), &replay);

        assert!(result.inconclusive);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("manual testing"))
        );
    }
}
