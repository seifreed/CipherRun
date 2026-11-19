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
    use super::*;

    #[test]
    fn probe_status_constructors_preserve_success_and_failure_context() {
        let success = ProbeStatus::success(Duration::from_millis(125));
        assert!(success.success);
        assert_eq!(success.error, None);
        assert_eq!(success.error_type, None);
        assert_eq!(success.connection_time_ms, Some(125));
        assert_eq!(success.attempts, 1);

        let failure = ProbeStatus::failure_string(
            "connection refused".to_string(),
            ErrorType::ConnectionRefused,
        );
        assert!(!failure.success);
        assert_eq!(failure.error.as_deref(), Some("connection refused"));
        assert_eq!(failure.error_type, Some(ErrorType::ConnectionRefused));
        assert_eq!(failure.connection_time_ms, None);
        assert_eq!(failure.attempts, 1);

        let partial = ProbeStatus::partial_success(
            Duration::from_millis(250),
            "certificate chain incomplete".to_string(),
        );
        assert!(partial.success);
        assert_eq!(
            partial.error.as_deref(),
            Some("certificate chain incomplete")
        );
        assert_eq!(partial.error_type, Some(ErrorType::Warning));
        assert_eq!(partial.connection_time_ms, Some(250));
        assert_eq!(partial.attempts, 1);
    }

    #[test]
    fn probe_status_elapsed_time_saturates_at_u64_max() {
        assert_eq!(
            ProbeStatus::success(Duration::MAX).connection_time_ms,
            Some(u64::MAX)
        );
        assert_eq!(
            ProbeStatus::partial_success(Duration::MAX, "warning".to_string()).connection_time_ms,
            Some(u64::MAX)
        );
    }

    #[test]
    fn default_probe_status_means_not_attempted() {
        let status = ProbeStatus::default();
        assert!(!status.success);
        assert_eq!(status.error.as_deref(), Some("Not attempted"));
        assert_eq!(status.error_type, Some(ErrorType::NotAttempted));
        assert_eq!(status.connection_time_ms, None);
        assert_eq!(status.attempts, 0);
    }

    #[test]
    fn error_type_descriptions_are_stable() {
        for (error_type, expected) in [
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
        ] {
            assert_eq!(error_type.description(), expected);
        }
    }
}
