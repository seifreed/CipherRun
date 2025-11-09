// Error types for CipherRun
//
// This module provides structured error types using thiserror, replacing the generic
// anyhow::Result pattern for better error handling and exhaustive matching.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Main error type for CipherRun operations
#[derive(Debug, Error)]
pub enum TlsError {
    /// Connection timeout occurred
    #[error("Connection timeout after {duration:?} to {addr}")]
    ConnectionTimeout {
        duration: Duration,
        addr: SocketAddr,
    },

    /// Connection was refused by the remote host
    #[error("Connection refused by {addr}")]
    ConnectionRefused { addr: SocketAddr },

    /// DNS resolution failed for the hostname
    #[error("DNS resolution failed for {hostname}: {source}")]
    DnsResolutionFailed {
        hostname: String,
        #[source]
        source: io::Error,
    },

    /// Protocol version not supported by the server
    #[error("Protocol {protocol} not supported by server")]
    ProtocolNotSupported { protocol: String },

    /// TLS handshake failed or is invalid
    #[error("Invalid TLS handshake: {details}")]
    InvalidHandshake { details: String },

    /// Certificate validation error
    #[error("Certificate validation failed: {0}")]
    CertificateError(#[from] CertificateValidationError),

    /// Generic I/O error
    #[error("I/O error: {source}")]
    IoError {
        #[from]
        source: io::Error,
    },

    /// HTTP client error
    #[error("HTTP error (status {status}): {details}")]
    HttpError { status: u16, details: String },

    /// Parsing error for data formats
    #[error("Parse error: {message}")]
    ParseError { message: String },

    /// OpenSSL-specific errors
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    /// Reqwest HTTP client errors
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    /// URL parsing errors
    #[error("Invalid URL: {0}")]
    UrlParseError(#[from] url::ParseError),

    /// STARTTLS protocol errors
    #[error("STARTTLS protocol error ({protocol}): {details}")]
    StarttlsError { protocol: String, details: String },

    /// Cipher suite errors
    #[error("Cipher suite error: {message}")]
    CipherError { message: String },

    /// Invalid configuration or parameters
    #[error("Invalid configuration: {message}")]
    ConfigError { message: String },

    /// Timeout occurred during operation
    #[error("Operation timed out after {duration:?}")]
    Timeout { duration: Duration },

    /// Database operation errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Server sent unexpected response
    #[error("Unexpected server response: {details}")]
    UnexpectedResponse { details: String },

    /// Server closed connection unexpectedly
    #[error("Connection closed by server: {details}")]
    ConnectionClosed { details: String },

    /// Invalid input from user or configuration
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// UTF-8 conversion errors
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Integer parsing errors
    #[error("Integer parse error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    /// File system errors
    #[error("File system error: {path}: {source}")]
    FileSystemError {
        path: String,
        #[source]
        source: io::Error,
    },

    /// mTLS configuration errors
    #[error("mTLS configuration error: {message}")]
    MtlsError { message: String },

    /// PEM parsing errors
    #[error("PEM parsing error: {0}")]
    PemError(#[from] pem::PemError),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// Certificate validation specific errors
#[derive(Debug, Error)]
pub enum CertificateValidationError {
    /// Certificate has expired
    #[error("Certificate expired on {expiry_date}")]
    Expired { expiry_date: String },

    /// Certificate is not yet valid
    #[error("Certificate not valid until {valid_from}")]
    NotYetValid { valid_from: String },

    /// Hostname does not match certificate
    #[error("Hostname {hostname} does not match certificate (expected: {expected})")]
    HostnameMismatch { hostname: String, expected: String },

    /// Certificate chain is incomplete or broken
    #[error("Invalid certificate chain: {reason}")]
    InvalidChain { reason: String },

    /// Certificate is self-signed
    #[error("Certificate is self-signed")]
    SelfSigned,

    /// Certificate has been revoked
    #[error("Certificate has been revoked")]
    Revoked,

    /// Root CA is not trusted
    #[error("Untrusted root CA: {issuer}")]
    UntrustedRoot { issuer: String },

    /// Invalid signature
    #[error("Invalid certificate signature")]
    InvalidSignature,

    /// Weak key size
    #[error("Weak key size: {bits} bits (minimum: {minimum})")]
    WeakKeySize { bits: usize, minimum: usize },

    /// Invalid certificate format or parsing error
    #[error("Certificate parsing error: {details}")]
    ParseError { details: String },
}

/// Conversion from anyhow::Error for gradual migration
impl From<anyhow::Error> for TlsError {
    fn from(err: anyhow::Error) -> Self {
        TlsError::Other(err.to_string())
    }
}

// Additional conversions for missing types
impl From<std::str::Utf8Error> for TlsError {
    fn from(err: std::str::Utf8Error) -> Self {
        TlsError::ParseError {
            message: format!("UTF-8 string error: {}", err),
        }
    }
}

impl From<tokio::time::error::Elapsed> for TlsError {
    fn from(_err: tokio::time::error::Elapsed) -> Self {
        TlsError::ConnectionTimeout {
            duration: std::time::Duration::from_secs(0), // Timeout duration unknown
            addr: "0.0.0.0:0".parse().unwrap(),
        }
    }
}

impl<S: std::fmt::Debug> From<openssl::ssl::HandshakeError<S>> for TlsError {
    fn from(err: openssl::ssl::HandshakeError<S>) -> Self {
        TlsError::InvalidHandshake {
            details: format!("SSL handshake error: {}", err),
        }
    }
}

impl From<tokio::task::JoinError> for TlsError {
    fn from(err: tokio::task::JoinError) -> Self {
        TlsError::IoError {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Task join error: {}", err),
            ),
        }
    }
}

impl From<csv::Error> for TlsError {
    fn from(err: csv::Error) -> Self {
        TlsError::Other(format!("CSV error: {}", err))
    }
}

impl<W> From<csv::IntoInnerError<W>> for TlsError {
    fn from(err: csv::IntoInnerError<W>) -> Self {
        TlsError::IoError {
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("CSV writer error: {}", err),
            ),
        }
    }
}

impl From<handlebars::RenderError> for TlsError {
    fn from(err: handlebars::RenderError) -> Self {
        TlsError::Other(format!("Template render error: {}", err))
    }
}

impl From<lettre::address::AddressError> for TlsError {
    fn from(err: lettre::address::AddressError) -> Self {
        TlsError::Other(format!("Email address error: {}", err))
    }
}

impl From<lettre::error::Error> for TlsError {
    fn from(err: lettre::error::Error) -> Self {
        TlsError::Other(format!("Email error: {}", err))
    }
}

impl From<lettre::transport::smtp::Error> for TlsError {
    fn from(err: lettre::transport::smtp::Error) -> Self {
        TlsError::Other(format!("SMTP error: {}", err))
    }
}

/// Helper macro for creating context-specific errors
#[macro_export]
macro_rules! tls_bail {
    ($msg:literal $(,)?) => {
        return Err($crate::error::TlsError::Other($msg.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err($crate::error::TlsError::Other(format!($fmt, $($arg)*)))
    };
}

/// Helper macro for creating certificate errors
#[macro_export]
macro_rules! cert_error {
    ($variant:ident { $($field:ident: $value:expr),* $(,)? }) => {
        $crate::error::TlsError::CertificateError(
            $crate::error::CertificateValidationError::$variant { $($field: $value),* }
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_timeout_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let err = TlsError::ConnectionTimeout {
            duration: Duration::from_secs(5),
            addr,
        };

        let msg = err.to_string();
        assert!(msg.contains("timeout"));
        assert!(msg.contains("127.0.0.1:443"));
    }

    #[test]
    fn test_dns_resolution_failed() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "host not found");
        let err = TlsError::DnsResolutionFailed {
            hostname: "invalid.example".to_string(),
            source: io_err,
        };

        let msg = err.to_string();
        assert!(msg.contains("DNS resolution failed"));
        assert!(msg.contains("invalid.example"));
    }

    #[test]
    fn test_certificate_expired() {
        let cert_err = CertificateValidationError::Expired {
            expiry_date: "2023-01-01".to_string(),
        };
        let err = TlsError::CertificateError(cert_err);

        let msg = err.to_string();
        assert!(msg.contains("expired"));
        assert!(msg.contains("2023-01-01"));
    }

    #[test]
    fn test_certificate_hostname_mismatch() {
        let cert_err = CertificateValidationError::HostnameMismatch {
            hostname: "example.com".to_string(),
            expected: "*.example.org".to_string(),
        };

        let msg = cert_err.to_string();
        assert!(msg.contains("example.com"));
        assert!(msg.contains("*.example.org"));
    }

    #[test]
    fn test_error_conversion_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let tls_err: TlsError = io_err.into();

        assert!(matches!(tls_err, TlsError::IoError { .. }));
    }

    #[test]
    fn test_error_chain_preserved() {
        use std::error::Error;

        let io_err = io::Error::new(io::ErrorKind::NotFound, "dns failed");
        let err = TlsError::DnsResolutionFailed {
            hostname: "test.example".to_string(),
            source: io_err,
        };

        // Verify the source chain is preserved
        assert!(err.source().is_some());
    }
}
