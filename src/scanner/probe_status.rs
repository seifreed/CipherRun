use crate::error::TlsError;

pub use super::contract::{ErrorType, ProbeStatus};

impl ProbeStatus {
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
}
