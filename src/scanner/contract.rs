use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Core probe status for connection attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStatus {
    pub success: bool,
    pub error: Option<String>,
    pub error_type: Option<ErrorType>,
    pub connection_time_ms: Option<u64>,
    pub attempts: u32,
}

impl ProbeStatus {
    pub fn success(duration: Duration) -> Self {
        let connection_time_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self {
            success: true,
            error: None,
            error_type: None,
            connection_time_ms: Some(connection_time_ms),
            attempts: 1,
        }
    }

    pub fn failure_string(error_msg: String, error_type: ErrorType) -> Self {
        Self {
            success: false,
            error: Some(error_msg),
            error_type: Some(error_type),
            connection_time_ms: None,
            attempts: 1,
        }
    }

    pub fn partial_success(duration: Duration, warning: String) -> Self {
        let connection_time_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self {
            success: true,
            error: Some(warning),
            error_type: Some(ErrorType::Warning),
            connection_time_ms: Some(connection_time_ms),
            attempts: 1,
        }
    }
}

impl Default for ProbeStatus {
    fn default() -> Self {
        Self {
            success: false,
            error: Some("Not attempted".to_string()),
            error_type: Some(ErrorType::NotAttempted),
            connection_time_ms: None,
            attempts: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    Timeout,
    ConnectionRefused,
    DnsFailure,
    TlsHandshakeFailed,
    CertificateError,
    ProtocolNotSupported,
    NetworkError,
    Warning,
    NotAttempted,
    Unknown,
}

impl ErrorType {
    pub fn description(&self) -> &'static str {
        match self {
            ErrorType::Timeout => "Connection timeout",
            ErrorType::ConnectionRefused => "Connection refused",
            ErrorType::DnsFailure => "DNS resolution failed",
            ErrorType::TlsHandshakeFailed => "TLS handshake failed",
            ErrorType::CertificateError => "Certificate error",
            ErrorType::ProtocolNotSupported => "Protocol not supported",
            ErrorType::NetworkError => "Temporary network error",
            ErrorType::Warning => "Warning",
            ErrorType::NotAttempted => "Not attempted",
            ErrorType::Unknown => "Unknown error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorType, ProbeStatus};
    use std::time::Duration;

    #[test]
    fn probe_status_builders_preserve_outcomes_and_durations() {
        let success = ProbeStatus::success(Duration::from_millis(12));
        assert!(success.success);
        assert_eq!(success.connection_time_ms, Some(12));
        assert_eq!(success.attempts, 1);
        assert!(success.error.is_none());
        assert!(success.error_type.is_none());

        let overflow = ProbeStatus::success(Duration::from_millis(u64::MAX));
        assert_eq!(overflow.connection_time_ms, Some(u64::MAX));

        let failure =
            ProbeStatus::failure_string("refused".to_string(), ErrorType::ConnectionRefused);
        assert!(!failure.success);
        assert_eq!(failure.error.as_deref(), Some("refused"));
        assert_eq!(failure.error_type, Some(ErrorType::ConnectionRefused));
        assert!(failure.connection_time_ms.is_none());
        assert_eq!(failure.attempts, 1);

        let partial =
            ProbeStatus::partial_success(Duration::from_millis(25), "retry used".to_string());
        assert!(partial.success);
        assert_eq!(partial.error.as_deref(), Some("retry used"));
        assert_eq!(partial.error_type, Some(ErrorType::Warning));
        assert_eq!(partial.connection_time_ms, Some(25));
        assert_eq!(partial.attempts, 1);

        let not_attempted = ProbeStatus::default();
        assert!(!not_attempted.success);
        assert_eq!(not_attempted.error.as_deref(), Some("Not attempted"));
        assert_eq!(not_attempted.error_type, Some(ErrorType::NotAttempted));
        assert!(not_attempted.connection_time_ms.is_none());
        assert_eq!(not_attempted.attempts, 0);
    }

    #[test]
    fn error_types_have_stable_diagnostic_descriptions() {
        let cases = [
            (ErrorType::Timeout, "Connection timeout"),
            (ErrorType::ConnectionRefused, "Connection refused"),
            (ErrorType::DnsFailure, "DNS resolution failed"),
            (ErrorType::TlsHandshakeFailed, "TLS handshake failed"),
            (ErrorType::CertificateError, "Certificate error"),
            (ErrorType::ProtocolNotSupported, "Protocol not supported"),
            (ErrorType::NetworkError, "Temporary network error"),
            (ErrorType::Warning, "Warning"),
            (ErrorType::NotAttempted, "Not attempted"),
            (ErrorType::Unknown, "Unknown error"),
        ];

        for (error_type, description) in cases {
            assert_eq!(error_type.description(), description);
        }
    }
}
