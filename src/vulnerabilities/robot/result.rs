/// ROBOT status.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RobotStatus {
    Vulnerable,
    WeakOracle,
    NotVulnerable,
    Inconclusive,
}

impl RobotStatus {
    fn details(self) -> String {
        match self {
            Self::Vulnerable => {
                "Vulnerable to ROBOT attack - Server responds differently to invalid RSA padding"
                    .to_string()
            }
            Self::WeakOracle => {
                "Potentially vulnerable - Weak oracle detected, may be exploitable".to_string()
            }
            Self::NotVulnerable => {
                "Not vulnerable - No RSA padding oracle detected".to_string()
            }
            Self::Inconclusive => {
                "ROBOT test inconclusive - transport or handshake failures prevented a reliable oracle comparison".to_string()
            }
        }
    }
}

/// ROBOT test result.
#[derive(Debug, Clone)]
pub struct RobotTestResult {
    pub vulnerable: bool,
    pub status: RobotStatus,
    pub details: String,
}

impl RobotTestResult {
    pub(super) fn from_status(status: RobotStatus) -> Self {
        // Only a clear oracle is a confirmed verdict. WeakOracle can come from
        // response-byte divergence across independent connections on healthy servers.
        Self {
            vulnerable: matches!(status, RobotStatus::Vulnerable),
            status,
            details: status.details(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_oracle_is_not_confirmed_vulnerable() {
        let result = RobotTestResult::from_status(RobotStatus::WeakOracle);

        assert!(!result.vulnerable);
        assert!(result.details.contains("Potentially vulnerable"));
    }

    #[test]
    fn vulnerable_status_sets_confirmed_flag() {
        let result = RobotTestResult::from_status(RobotStatus::Vulnerable);

        assert!(result.vulnerable);
        assert!(result.details.contains("ROBOT attack"));
    }
}
