/// CCS test status with detailed failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Server correctly rejected CCS - not vulnerable
    NotVulnerable,
    /// Server accepted CCS - vulnerable to CVE-2014-0224
    Vulnerable,
    /// Connection or handshake error - test inconclusive
    Inconclusive,
    /// Connection failed to establish
    ConnectionFailed,
    /// Handshake failed during ServerHello read
    HandshakeFailed,
}

impl TestStatus {
    /// Returns true if the test result indicates vulnerability.
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, Self::Vulnerable)
    }

    /// Returns true if the test could not complete.
    pub fn is_inconclusive(&self) -> bool {
        matches!(
            self,
            Self::Inconclusive | Self::ConnectionFailed | Self::HandshakeFailed
        )
    }

    pub(super) fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Vulnerable, _) | (_, Self::Vulnerable) => Self::Vulnerable,
            (status, _) if status.is_inconclusive() => status,
            (_, status) if status.is_inconclusive() => status,
            _ => Self::NotVulnerable,
        }
    }

    fn details(self) -> String {
        match self {
            Self::Vulnerable => {
                "Vulnerable to CCS Injection (CVE-2014-0224) - Server accepts early CCS messages"
                    .to_string()
            }
            Self::NotVulnerable => "Not vulnerable - Server rejects early CCS messages".to_string(),
            Self::Inconclusive => {
                "CCS Injection test inconclusive - unexpected response pattern".to_string()
            }
            Self::ConnectionFailed => {
                "CCS Injection test inconclusive - connection failed".to_string()
            }
            Self::HandshakeFailed => {
                "CCS Injection test inconclusive - handshake timeout or error".to_string()
            }
        }
    }
}

/// CCS test result.
#[derive(Debug, Clone)]
pub struct CcsTestResult {
    pub vulnerable: bool,
    pub status: TestStatus,
    pub details: String,
}

impl CcsTestResult {
    pub(super) fn from_status(status: TestStatus) -> Self {
        Self {
            vulnerable: status.is_vulnerable(),
            status,
            details: status.details(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_vulnerable_over_inconclusive() {
        assert_eq!(
            TestStatus::HandshakeFailed.merge(TestStatus::Vulnerable),
            TestStatus::Vulnerable
        );
    }

    #[test]
    fn result_details_follow_status() {
        let result = CcsTestResult::from_status(TestStatus::ConnectionFailed);

        assert!(!result.vulnerable);
        assert!(result.status.is_inconclusive());
        assert!(result.details.contains("connection failed"));
    }
}
