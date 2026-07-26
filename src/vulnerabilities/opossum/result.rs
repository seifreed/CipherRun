#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpossumStatus {
    Vulnerable,
    NotVulnerable,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct OpossumTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub status: OpossumStatus,
    pub details: String,
}

impl OpossumTestResult {
    pub(super) fn from_probe_statuses(
        version_status: OpossumStatus,
        parsing_status: OpossumStatus,
    ) -> Self {
        let status = if matches!(version_status, OpossumStatus::Vulnerable)
            || matches!(parsing_status, OpossumStatus::Vulnerable)
            || matches!(version_status, OpossumStatus::Inconclusive)
            || matches!(parsing_status, OpossumStatus::Inconclusive)
        {
            OpossumStatus::Inconclusive
        } else {
            OpossumStatus::NotVulnerable
        };

        Self {
            vulnerable: false,
            inconclusive: matches!(status, OpossumStatus::Inconclusive),
            status,
            details: details_for_status(status),
        }
    }
}

fn details_for_status(status: OpossumStatus) -> String {
    match status {
        OpossumStatus::Inconclusive | OpossumStatus::Vulnerable => {
            "Opossum test inconclusive - CVE-2022-0778 is a client-side parsing vulnerability \
             that cannot be reliably detected via remote scanning. Manual verification of \
             OpenSSL version (< 1.1.1n / 1.0.2ze / 3.0.2) is recommended."
                .to_string()
        }
        OpossumStatus::NotVulnerable => "No Opossum-like parsing hang observed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_probe_is_downgraded_to_inconclusive() {
        let result = OpossumTestResult::from_probe_statuses(
            OpossumStatus::Vulnerable,
            OpossumStatus::NotVulnerable,
        );

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert_eq!(result.status, OpossumStatus::Inconclusive);
    }

    #[test]
    fn clean_probes_report_not_vulnerable() {
        let result = OpossumTestResult::from_probe_statuses(
            OpossumStatus::NotVulnerable,
            OpossumStatus::NotVulnerable,
        );

        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
        assert_eq!(result.status, OpossumStatus::NotVulnerable);
    }
}
