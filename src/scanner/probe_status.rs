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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, net::SocketAddr, time::Duration};

    #[test]
    fn maps_tls_errors_to_probe_error_types() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let cases = [
            (
                TlsError::ConnectionTimeout {
                    duration: Duration::from_secs(1),
                    addr,
                },
                ErrorType::Timeout,
            ),
            (
                TlsError::ConnectionRefused { addr },
                ErrorType::ConnectionRefused,
            ),
            (
                TlsError::DnsResolutionFailed {
                    hostname: "example.test".into(),
                    source: io::Error::other("not found"),
                },
                ErrorType::DnsFailure,
            ),
            (
                TlsError::InvalidHandshake {
                    details: "invalid record".into(),
                },
                ErrorType::TlsHandshakeFailed,
            ),
            (
                TlsError::CertificateError(crate::error::CertificateValidationError::SelfSigned),
                ErrorType::CertificateError,
            ),
            (
                TlsError::ProtocolNotSupported {
                    protocol: "TLS 1.0".into(),
                },
                ErrorType::ProtocolNotSupported,
            ),
            (TlsError::Timeout { duration: None }, ErrorType::Timeout),
            (
                TlsError::IoError {
                    source: io::Error::other("network error"),
                },
                ErrorType::NetworkError,
            ),
            (TlsError::Other("unexpected".into()), ErrorType::Unknown),
        ];

        for (error, expected) in cases {
            assert_eq!(ErrorType::from_tls_error(&error), expected);
        }
    }

    #[test]
    fn failure_preserves_diagnostic_and_sets_attempt_metadata() {
        let status = ProbeStatus::failure(TlsError::Other("unexpected".into()));

        assert!(!status.success);
        assert_eq!(status.error.as_deref(), Some("unexpected"));
        assert_eq!(status.error_type, Some(ErrorType::Unknown));
        assert_eq!(status.connection_time_ms, None);
        assert_eq!(status.attempts, 1);
    }
}
