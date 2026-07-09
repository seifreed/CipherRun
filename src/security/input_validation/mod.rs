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

pub fn looks_like_obfuscated_ip(hostname: &str) -> bool {
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() == 1 {
        let label = labels[0];
        let is_hex = label
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
            && label.chars().skip(2).all(|ch| ch.is_ascii_hexdigit());
        return label.chars().all(|ch| ch.is_ascii_digit()) || is_hex;
    }

    labels.len() <= 4
        && labels.iter().all(|label| {
            !label.is_empty()
                && (label.chars().all(|ch| ch.is_ascii_digit())
                    || (label
                        .get(..2)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
                        && label.chars().skip(2).all(|ch| ch.is_ascii_hexdigit())))
        })
}

pub fn looks_like_dotted_ip_literal(hostname: &str) -> bool {
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    hostname
        .strip_suffix('.')
        .is_some_and(|candidate| candidate.parse::<std::net::IpAddr>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::{looks_like_dotted_ip_literal, looks_like_obfuscated_ip};

    #[test]
    fn test_looks_like_obfuscated_ip_rejects_single_label_hex() {
        assert!(looks_like_obfuscated_ip("0x7f000001"));
        assert!(looks_like_obfuscated_ip("0X7f000001"));
    }

    #[test]
    fn test_looks_like_dotted_ip_literal_detects_rooted_ip() {
        assert!(looks_like_dotted_ip_literal("127.0.0.1."));
        assert!(looks_like_dotted_ip_literal("2001:db8::1."));
        assert!(!looks_like_dotted_ip_literal("example.com."));
        assert!(!looks_like_dotted_ip_literal("127.0.0.1"));
    }
}
