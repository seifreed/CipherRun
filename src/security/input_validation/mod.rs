/*
 * Copyright (C) 2026 Marc Rivero López
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! Input Validation Module
//!
//! Provides comprehensive input validation to prevent command injection,
//! path traversal, SSRF, and other input-based vulnerabilities.
//!
//! # Security Standards
//! - CWE-78: OS Command Injection
//! - CWE-22: Path Traversal
//! - CWE-918: Server-Side Request Forgery (SSRF)
//! - OWASP A03:2021 - Injection

mod cipher;
mod hostname;
mod path;
mod port;
mod protocol;
pub mod ssrf; // Public for SSRF validation in network utilities
mod target;

/// Validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidHostname(String),
    InvalidPort(String),
    InvalidPath(String),
    InvalidCipher(String),
    InvalidProtocol(String),
    SsrfAttempt(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHostname(msg) => write!(f, "Invalid hostname: {}", msg),
            Self::InvalidPort(msg) => write!(f, "Invalid port: {}", msg),
            Self::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            Self::InvalidCipher(msg) => write!(f, "Invalid cipher: {}", msg),
            Self::InvalidProtocol(msg) => write!(f, "Invalid protocol: {}", msg),
            Self::SsrfAttempt(msg) => write!(f, "SSRF attempt detected: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

// Re-export all public functions to preserve the existing API
pub use cipher::validate_cipher;
pub use hostname::validate_hostname;
pub use path::sanitize_path;
pub use port::validate_port;
pub use protocol::validate_starttls_protocol;
pub use ssrf::{is_private_ip, validate_resolved_ips};
pub use target::validate_target;
