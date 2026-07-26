/// Internal verdict from `test_session_ticket_leak` that separates conclusive
/// results from probe failures. Connection/timeout failures must be reported as
/// inconclusive rather than "not vulnerable".
#[derive(Debug)]
pub(super) enum TicketbleedProbeOutcome {
    Vulnerable,
    NotVulnerable(&'static str),
    Inconclusive(&'static str),
}

impl TicketbleedProbeOutcome {
    pub(super) fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Vulnerable, _) | (_, Self::Vulnerable) => Self::Vulnerable,
            (Self::Inconclusive(reason), _) | (_, Self::Inconclusive(reason)) => {
                Self::Inconclusive(reason)
            }
            (clean, _) => clean,
        }
    }

    pub(super) fn into_test_result(self) -> TicketbleedTestResult {
        match self {
            Self::Vulnerable => TicketbleedTestResult {
                vulnerable: true,
                inconclusive: false,
                details: "Vulnerable to Ticketbleed (CVE-2016-9244) - Server leaks memory in session ticket responses".to_string(),
            },
            Self::NotVulnerable(reason) => TicketbleedTestResult {
                vulnerable: false,
                inconclusive: false,
                details: format!("Not vulnerable - {}", reason),
            },
            Self::Inconclusive(reason) => TicketbleedTestResult {
                vulnerable: false,
                inconclusive: true,
                details: format!("Inconclusive - {}", reason),
            },
        }
    }
}

/// Ticketbleed test result
#[derive(Debug, Clone)]
pub struct TicketbleedTestResult {
    pub vulnerable: bool,
    /// True when the probe could not reach a conclusive verdict (e.g., TCP
    /// connect failed, handshake timed out, follow-up ClientHello produced no
    /// response). Callers must not treat inconclusive results as "clean".
    pub inconclusive: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_outcome_wins_merge() {
        let merged = TicketbleedProbeOutcome::NotVulnerable("clean")
            .merge(TicketbleedProbeOutcome::Vulnerable);

        assert!(matches!(merged, TicketbleedProbeOutcome::Vulnerable));
    }

    #[test]
    fn inconclusive_beats_clean_merge() {
        let merged = TicketbleedProbeOutcome::NotVulnerable("clean")
            .merge(TicketbleedProbeOutcome::Inconclusive("timeout"));

        assert!(matches!(
            merged,
            TicketbleedProbeOutcome::Inconclusive("timeout")
        ));
    }

    #[test]
    fn outcome_converts_to_public_result() {
        let result = TicketbleedProbeOutcome::Inconclusive("timeout").into_test_result();

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert_eq!(result.details, "Inconclusive - timeout");
    }
}
