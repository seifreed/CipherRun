// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2024 CipherRun Team
// Licensed under GPL-2.0

//! CipherRun is a comprehensive TLS/SSL security scanner written in Rust.
//! It provides extensive testing capabilities for TLS/SSL protocols, ciphers,
//! vulnerabilities, and certificate validation.

pub mod api;
pub mod certificates;
pub mod ciphers;
pub mod cli;
pub mod client_sim;
pub mod commands;
pub mod compliance;
pub mod constants;
pub mod ct_logs;
pub mod data;
pub mod db;
pub mod error;
pub mod external;
pub mod fingerprint;
pub mod http;
pub mod input;
pub mod monitor;
pub mod output;
pub mod policy;
pub mod protocols;
pub mod rating;
pub mod scanner;
pub mod security;
pub mod starttls;
pub mod utils;
pub mod vulnerabilities;

// Kani formal verification proof harnesses
// Only compiled when running Kani verification
#[cfg(kani)]
pub mod proofs;

// Re-export commonly used types
pub use crate::cli::Args;
pub use crate::error::{CertificateValidationError, TlsError};
pub use crate::output::OutputFormat;
pub use crate::scanner::Scanner;

/// Result type for CipherRun operations
///
/// This is the standard Result type used throughout CipherRun, wrapping
/// the structured TlsError enum for better error handling and exhaustive matching.
///
/// # Examples
///
/// ```no_run
/// use cipherrun::{Result, TlsError};
///
/// fn connect_to_server(addr: &str) -> Result<()> {
///     // Function implementation
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, TlsError>;

/// Legacy compatibility: anyhow Result type
///
/// This is provided for gradual migration from anyhow to the structured TlsError.
/// New code should use the main Result<T> type above.
#[deprecated(
    since = "0.2.0",
    note = "Use cipherrun::Result<T> instead of AnyhowResult<T>"
)]
pub type AnyhowResult<T> = anyhow::Result<T>;
