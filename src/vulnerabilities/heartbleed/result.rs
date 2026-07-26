/// Heartbleed detection result with detailed information.
#[derive(Debug, Clone)]
pub struct HeartbleedResult {
    pub vulnerable: bool,
    pub bytes_received: usize,
    pub bytes_sent: usize,
    pub details: String,
    /// Whether the test was actually performed (false if connection/parsing failed)
    pub tested: bool,
}

impl HeartbleedResult {
    pub(super) fn aggregate_clean(any_tested: bool) -> Self {
        Self {
            vulnerable: false,
            bytes_received: 0,
            bytes_sent: 3,
            details: if any_tested {
                "Not vulnerable - No memory leak detected across TLS 1.0/1.1/1.2".to_string()
            } else {
                "Unable to test - No TLS protocol connection succeeded (inconclusive)".to_string()
            },
            tested: any_tested,
        }
    }

    pub(super) fn connection_failed() -> Self {
        Self::untested(
            "Connection failed - Vulnerability status UNKNOWN (unable to test)",
            0,
            0,
        )
    }

    pub(super) fn server_hello_timeout() -> Self {
        Self::untested("ServerHello timeout or empty response", 0, 0)
    }

    pub(super) fn unexpected_server_hello(bytes_received: usize) -> Self {
        Self::untested(
            "Unable to test - unexpected TLS response while probing heartbeat extension",
            bytes_received,
            0,
        )
    }

    pub(super) fn heartbeat_not_supported() -> Self {
        Self {
            vulnerable: false,
            bytes_received: 0,
            bytes_sent: 0,
            details: "Heartbeat extension not supported by server".to_string(),
            tested: true,
        }
    }

    pub(super) fn malformed_server_hello(error: crate::TlsError) -> Self {
        Self::untested(
            format!("Unable to test - malformed ServerHello: {}", error),
            0,
            0,
        )
    }

    pub(super) fn heartbeat_timeout(bytes_sent: usize) -> Self {
        Self::untested(
            "Timeout waiting for heartbeat response - server may have closed connection",
            0,
            bytes_sent,
        )
    }

    pub(super) fn heartbeat_connection_error(bytes_sent: usize) -> Self {
        Self::untested(
            "Connection error during heartbeat test - server may have closed connection",
            0,
            bytes_sent,
        )
    }

    fn untested(details: impl Into<String>, bytes_received: usize, bytes_sent: usize) -> Self {
        Self {
            vulnerable: false,
            bytes_received,
            bytes_sent,
            details: details.into(),
            tested: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_clean_preserves_inconclusive_when_no_protocol_was_tested() {
        let result = HeartbleedResult::aggregate_clean(false);

        assert!(!result.vulnerable);
        assert!(!result.tested);
        assert!(result.details.contains("Unable to test"));
    }

    #[test]
    fn heartbeat_not_supported_is_a_completed_clean_test() {
        let result = HeartbleedResult::heartbeat_not_supported();

        assert!(!result.vulnerable);
        assert!(result.tested);
        assert!(result.details.contains("not supported"));
    }
}
