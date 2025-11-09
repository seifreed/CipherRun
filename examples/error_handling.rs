//! Error Handling Examples
//!
//! This example demonstrates the new structured error types in CipherRun.
//! It shows how to create, match, and handle different error types.
//!
//! Run with: cargo run --example error_handling

use cipherrun::error::{CertificateValidationError, TlsError};
use cipherrun::Result;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Example 1: Creating specific error types
fn example_connection_errors() {
    println!("=== Example 1: Connection Errors ===\n");

    // Connection timeout error
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
    let timeout_err = TlsError::ConnectionTimeout {
        duration: Duration::from_secs(5),
        addr,
    };
    println!("Timeout error: {}", timeout_err);

    // Connection refused error
    let refused_err = TlsError::ConnectionRefused { addr };
    println!("Refused error: {}", refused_err);

    // DNS resolution failed
    let dns_err = TlsError::DnsResolutionFailed {
        hostname: "invalid.example.test".to_string(),
        source: io::Error::new(io::ErrorKind::NotFound, "Name or service not known"),
    };
    println!("DNS error: {}", dns_err);
    println!();
}

/// Example 2: Certificate validation errors
fn example_certificate_errors() {
    println!("=== Example 2: Certificate Errors ===\n");

    // Expired certificate
    let expired = TlsError::CertificateError(CertificateValidationError::Expired {
        expiry_date: "2023-01-01T00:00:00Z".to_string(),
    });
    println!("Expired cert: {}", expired);

    // Hostname mismatch
    let hostname_mismatch =
        TlsError::CertificateError(CertificateValidationError::HostnameMismatch {
            hostname: "example.com".to_string(),
            expected: "*.example.org".to_string(),
        });
    println!("Hostname mismatch: {}", hostname_mismatch);

    // Weak key size
    let weak_key = TlsError::CertificateError(CertificateValidationError::WeakKeySize {
        bits: 1024,
        minimum: 2048,
    });
    println!("Weak key: {}", weak_key);

    // Self-signed certificate
    let self_signed = TlsError::CertificateError(CertificateValidationError::SelfSigned);
    println!("Self-signed: {}", self_signed);
    println!();
}

/// Example 3: Protocol and handshake errors
fn example_protocol_errors() {
    println!("=== Example 3: Protocol Errors ===\n");

    // Protocol not supported
    let proto_err = TlsError::ProtocolNotSupported {
        protocol: "SSLv3".to_string(),
    };
    println!("Protocol error: {}", proto_err);

    // Invalid handshake
    let handshake_err = TlsError::InvalidHandshake {
        details: "ServerHello missing required extensions".to_string(),
    };
    println!("Handshake error: {}", handshake_err);

    // STARTTLS error
    let starttls_err = TlsError::StarttlsError {
        protocol: "SMTP".to_string(),
        details: "Server did not respond to STARTTLS command".to_string(),
    };
    println!("STARTTLS error: {}", starttls_err);
    println!();
}

/// Example 4: Pattern matching on errors
fn example_pattern_matching() {
    println!("=== Example 4: Pattern Matching ===\n");

    let errors: Vec<TlsError> = vec![
        TlsError::ConnectionTimeout {
            duration: Duration::from_secs(5),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        },
        TlsError::ConnectionRefused {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443),
        },
        TlsError::DnsResolutionFailed {
            hostname: "nonexistent.example".to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "host not found"),
        },
        TlsError::CertificateError(CertificateValidationError::Expired {
            expiry_date: "2023-12-31".to_string(),
        }),
    ];

    for err in &errors {
        let user_message = match err {
            TlsError::ConnectionTimeout { addr, duration } => {
                format!(
                    "Connection to {} timed out after {:?}. The server may be down or unreachable.",
                    addr, duration
                )
            }
            TlsError::ConnectionRefused { addr } => {
                format!(
                    "Connection to {} was refused. The server may not be accepting connections on this port.",
                    addr
                )
            }
            TlsError::DnsResolutionFailed { hostname, .. } => {
                format!(
                    "Could not resolve hostname '{}'. Please check the hostname and your DNS settings.",
                    hostname
                )
            }
            TlsError::CertificateError(cert_err) => match cert_err {
                CertificateValidationError::Expired { expiry_date } => {
                    format!(
                        "The server's certificate expired on {}. This may indicate a configuration issue.",
                        expiry_date
                    )
                }
                CertificateValidationError::HostnameMismatch {
                    hostname,
                    expected,
                } => {
                    format!(
                        "Certificate hostname mismatch: expected '{}' but got '{}'",
                        expected, hostname
                    )
                }
                _ => format!("Certificate validation failed: {}", cert_err),
            },
            _ => err.to_string(),
        };

        println!("User-friendly message:\n  {}\n", user_message);
    }
}

/// Example 5: Error chaining and source
fn example_error_chaining() {
    println!("=== Example 5: Error Chaining ===\n");

    let io_err = io::Error::new(io::ErrorKind::TimedOut, "connection timed out");
    let dns_err = TlsError::DnsResolutionFailed {
        hostname: "example.com".to_string(),
        source: io_err,
    };

    println!("Main error: {}", dns_err);

    // Access the source error
    if let Some(source) = std::error::Error::source(&dns_err) {
        println!("Caused by: {}", source);
    }
    println!();
}

/// Example 6: Handling errors in functions
fn simulate_connection(hostname: &str, port: u16) -> Result<String> {
    // Simulate DNS resolution
    if hostname.contains("invalid") {
        return Err(TlsError::DnsResolutionFailed {
            hostname: hostname.to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "Name not known"),
        });
    }

    // Simulate connection
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port);
    if port == 0 {
        return Err(TlsError::InvalidInput {
            message: "Port cannot be zero".to_string(),
        });
    }

    if port == 1 {
        return Err(TlsError::ConnectionRefused { addr });
    }

    Ok(format!("Connected to {}:{}", hostname, port))
}

fn example_function_errors() {
    println!("=== Example 6: Function Error Handling ===\n");

    // Successful connection
    match simulate_connection("example.com", 443) {
        Ok(msg) => println!("Success: {}", msg),
        Err(e) => println!("Error: {}", e),
    }

    // DNS failure
    match simulate_connection("invalid.example", 443) {
        Ok(msg) => println!("Success: {}", msg),
        Err(e) => println!("Error: {}", e),
    }

    // Invalid port
    match simulate_connection("example.com", 0) {
        Ok(msg) => println!("Success: {}", msg),
        Err(e) => println!("Error: {}", e),
    }

    // Connection refused
    match simulate_connection("example.com", 1) {
        Ok(msg) => println!("Success: {}", msg),
        Err(e) => println!("Error: {}", e),
    }
    println!();
}

/// Example 7: Exhaustive matching on certificate errors
fn example_exhaustive_cert_matching() {
    println!("=== Example 7: Exhaustive Certificate Error Matching ===\n");

    let cert_errors = vec![
        CertificateValidationError::Expired {
            expiry_date: "2023-01-01".to_string(),
        },
        CertificateValidationError::NotYetValid {
            valid_from: "2025-01-01".to_string(),
        },
        CertificateValidationError::HostnameMismatch {
            hostname: "example.com".to_string(),
            expected: "*.example.org".to_string(),
        },
        CertificateValidationError::SelfSigned,
        CertificateValidationError::Revoked,
        CertificateValidationError::UntrustedRoot {
            issuer: "Unknown CA".to_string(),
        },
        CertificateValidationError::WeakKeySize {
            bits: 1024,
            minimum: 2048,
        },
    ];

    for cert_err in &cert_errors {
        let severity = match cert_err {
            CertificateValidationError::Expired { .. } => "CRITICAL",
            CertificateValidationError::Revoked => "CRITICAL",
            CertificateValidationError::InvalidSignature => "CRITICAL",
            CertificateValidationError::UntrustedRoot { .. } => "HIGH",
            CertificateValidationError::HostnameMismatch { .. } => "HIGH",
            CertificateValidationError::WeakKeySize { .. } => "MEDIUM",
            CertificateValidationError::NotYetValid { .. } => "MEDIUM",
            CertificateValidationError::SelfSigned => "MEDIUM",
            CertificateValidationError::InvalidChain { .. } => "HIGH",
            CertificateValidationError::ParseError { .. } => "LOW",
        };

        println!("[{}] {}", severity, cert_err);
    }
    println!();
}

/// Example 8: Converting from other error types
fn example_error_conversions() {
    println!("=== Example 8: Error Conversions ===\n");

    // From std::io::Error
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let tls_err: TlsError = io_err.into();
    println!("From io::Error: {}", tls_err);

    // From ParseIntError
    let parse_result: std::result::Result<u16, _> = "invalid".parse();
    if let Err(parse_err) = parse_result {
        let tls_err: TlsError = parse_err.into();
        println!("From ParseIntError: {}", tls_err);
    }

    // From url::ParseError
    if let Err(url_err) = url::Url::parse("not a url") {
        let tls_err: TlsError = url_err.into();
        println!("From UrlParseError: {}", tls_err);
    }

    // From anyhow::Error (for migration)
    let anyhow_err = anyhow::anyhow!("generic error message");
    let tls_err: TlsError = anyhow_err.into();
    println!("From anyhow::Error: {}", tls_err);
    println!();
}

fn main() {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║   CipherRun Error Handling Examples          ║");
    println!("╚════════════════════════════════════════════════╝\n");

    example_connection_errors();
    example_certificate_errors();
    example_protocol_errors();
    example_pattern_matching();
    example_error_chaining();
    example_function_errors();
    example_exhaustive_cert_matching();
    example_error_conversions();

    println!("✓ All examples completed successfully!\n");
    println!("For more information, see MIGRATION_GUIDE.md");
}
