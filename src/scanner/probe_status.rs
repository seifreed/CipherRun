use crate::error::TlsError;
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
        Self {
            success: true,
            error: None,
            error_type: None,
            connection_time_ms: Some(duration.as_millis() as u64),
            attempts: 1,
        }
    }

    pub fn failure(error: TlsError) -> Self {
        let error_type = ErrorType::from_tls_error(&error);

        Self {
            success: false,
            error: Some(error.to_string()),
            error_type: Some(error_type),
            connection_time_ms: None,
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
        Self {
            success: true,
            error: Some(warning),
            error_type: Some(ErrorType::Warning),
            connection_time_ms: Some(duration.as_millis() as u64),
            attempts: 1,
        }
    }

    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    pub fn detailed_error(&self) -> Option<String> {
        self.error.clone()
    }

    pub fn is_retryable(&self) -> bool {
        if self.success {
            return false;
        }

        matches!(
            self.error_type,
            Some(ErrorType::Timeout) | Some(ErrorType::NetworkError)
        )
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
    pub fn from_tls_error(error: &TlsError) -> Self {
        match error {
            TlsError::ConnectionTimeout { .. } => ErrorType::Timeout,
            TlsError::ConnectionRefused { .. } => ErrorType::ConnectionRefused,
            TlsError::DnsResolutionFailed { .. } => ErrorType::DnsFailure,
            TlsError::InvalidHandshake { .. } => ErrorType::TlsHandshakeFailed,
            TlsError::CertificateError(_) => ErrorType::CertificateError,
            TlsError::ProtocolNotSupported { .. } => ErrorType::ProtocolNotSupported,
            TlsError::Timeout { .. } => ErrorType::Timeout,
            TlsError::IoError { .. } => ErrorType::NetworkError,
            _ => ErrorType::Unknown,
        }
    }

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
