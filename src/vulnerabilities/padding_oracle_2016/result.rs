use super::{CbcSupportStatus, PaddingOracleTimingResult};

/// Padding Oracle 2016 test result.
#[derive(Debug, Clone)]
pub struct PaddingOracle2016Result {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub cbc_supported: bool,
    pub timing_oracle_detected: bool,
    pub details: String,
    pub average_valid_timing_ms: f64,
    pub average_invalid_timing_ms: f64,
}

impl PaddingOracle2016Result {
    pub(super) fn from_cbc_status(cbc_status: CbcSupportStatus) -> Self {
        match cbc_status {
            CbcSupportStatus::Inconclusive => Self {
                vulnerable: false,
                inconclusive: true,
                cbc_supported: false,
                timing_oracle_detected: false,
                details:
                    "INCONCLUSIVE: unable to determine AES-CBC cipher support for CVE-2016-2107"
                        .to_string(),
                average_valid_timing_ms: 0.0,
                average_invalid_timing_ms: 0.0,
            },
            CbcSupportStatus::NotSupported => Self {
                vulnerable: false,
                inconclusive: false,
                cbc_supported: false,
                timing_oracle_detected: false,
                details: "Server does not support AES-CBC cipher suites (only GCM/other AEAD)"
                    .to_string(),
                average_valid_timing_ms: 0.0,
                average_invalid_timing_ms: 0.0,
            },
            CbcSupportStatus::Supported => {
                unreachable!("supported CBC status requires timing data")
            }
        }
    }

    pub(super) fn from_timing_result(timing_result: PaddingOracleTimingResult) -> Self {
        Self {
            vulnerable: timing_result.oracle_detected,
            inconclusive: timing_result.inconclusive,
            cbc_supported: true,
            timing_oracle_detected: timing_result.oracle_detected,
            details: timing_details(&timing_result),
            average_valid_timing_ms: timing_result.valid_avg_ms,
            average_invalid_timing_ms: timing_result.invalid_avg_ms,
        }
    }
}

fn timing_details(timing_result: &PaddingOracleTimingResult) -> String {
    if timing_result.inconclusive {
        format!(
            "INCONCLUSIVE: AES-CBC supported but timing analysis uncertain. {}. \
             Manual testing recommended as padding oracle may exist.",
            timing_result.details
        )
    } else if timing_result.oracle_detected {
        format!(
            "VULNERABLE to CVE-2016-2107 Padding Oracle - Timing difference detected: valid={:.2}ms, invalid={:.2}ms. {}",
            timing_result.valid_avg_ms, timing_result.invalid_avg_ms, timing_result.details
        )
    } else {
        format!(
            "AES-CBC supported but no clear timing oracle detected - valid={:.2}ms, invalid={:.2}ms. {}",
            timing_result.valid_avg_ms, timing_result.invalid_avg_ms, timing_result.details
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_cbc_status_marks_result_inconclusive() {
        let result = PaddingOracle2016Result::from_cbc_status(CbcSupportStatus::Inconclusive);

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(!result.cbc_supported);
    }

    #[test]
    fn detected_timing_oracle_marks_result_vulnerable() {
        let result = PaddingOracle2016Result::from_timing_result(PaddingOracleTimingResult {
            valid_avg_ms: 15.5,
            invalid_avg_ms: 5.2,
            oracle_detected: true,
            inconclusive: false,
            details: "timing delta".to_string(),
        });

        assert!(result.vulnerable);
        assert!(result.cbc_supported);
        assert!(result.timing_oracle_detected);
        assert!(result.details.contains("15.50ms"));
    }
}
