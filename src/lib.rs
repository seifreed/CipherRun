// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2024 CipherRun Team
// Licensed under GPL-2.0

//! CipherRun is a comprehensive TLS/SSL security scanner written in Rust.
//! It provides extensive testing capabilities for TLS/SSL protocols, ciphers,
//! vulnerabilities, and certificate validation.

pub mod certificates;
pub mod ciphers;
pub mod cli;
pub mod client_sim;
pub mod data;
pub mod external;
pub mod http;
pub mod output;
pub mod protocols;
pub mod rating;
pub mod scanner;
pub mod starttls;
pub mod utils;
pub mod vulnerabilities;

// Re-export commonly used types
pub use crate::cli::Args;
pub use crate::output::OutputFormat;
pub use crate::scanner::Scanner;

/// Result type for CipherRun operations
pub type Result<T> = anyhow::Result<T>;

/// Error type for CipherRun operations
pub use anyhow::Error;
