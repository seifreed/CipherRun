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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Maximum length for hostname (RFC 1035)
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length for label in hostname (RFC 1035)
const MAX_LABEL_LENGTH: usize = 63;

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

/// Validate hostname according to RFC 1035 and RFC 1123
///
/// # Security Requirements
/// - Prevents command injection via shell metacharacters
/// - Enforces DNS hostname format
/// - Rejects path separators and special characters
/// - Validates length constraints per RFC 1035
///
/// # Arguments
/// * `hostname` - The hostname to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_hostname(hostname: &str) -> std::result::Result<(), ValidationError> {
    // Check empty
    if hostname.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Hostname cannot be empty".to_string(),
        ));
    }

    // Check length (RFC 1035: max 253 characters)
    if hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(ValidationError::InvalidHostname(format!(
            "Hostname too long (max {} characters)",
            MAX_HOSTNAME_LENGTH
        )));
    }

    // Check for dangerous characters that could enable command injection
    let dangerous_chars = [
        '|', '&', ';', '$', '`', '\n', '\r', '<', '>', '(', ')', '{', '}', '\\', '\'', '"', ' ',
    ];
    for ch in dangerous_chars.iter() {
        if hostname.contains(*ch) {
            return Err(ValidationError::InvalidHostname(format!(
                "Hostname contains forbidden character: '{}'",
                ch
            )));
        }
    }

    // Check for path separators
    if hostname.contains('/') || hostname.contains('\\') {
        return Err(ValidationError::InvalidHostname(
            "Hostname cannot contain path separators".to_string(),
        ));
    }

    // Validate as either IP address or DNS hostname
    if hostname.parse::<IpAddr>().is_ok() {
        // Valid IP address
        return Ok(());
    }

    // Validate DNS hostname format
    // Each label must be 1-63 characters
    // Labels must start with alphanumeric, end with alphanumeric
    // Labels can contain hyphens but not at start or end
    let labels: Vec<&str> = hostname.split('.').collect();

    if labels.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Invalid hostname format".to_string(),
        ));
    }

    for label in labels {
        // Check label length
        if label.is_empty() || label.len() > MAX_LABEL_LENGTH {
            return Err(ValidationError::InvalidHostname(format!(
                "Label '{}' has invalid length (must be 1-{} characters)",
                label, MAX_LABEL_LENGTH
            )));
        }

        // Check label characters
        for (i, ch) in label.chars().enumerate() {
            let is_first = i == 0;
            let is_last = i == label.len() - 1;

            // Valid characters: alphanumeric, or hyphen (not at start/end)
            let is_valid = ch.is_ascii_alphanumeric() || (ch == '-' && !is_first && !is_last);
            if !is_valid {
                return Err(ValidationError::InvalidHostname(format!(
                    "Label '{}' contains invalid character or invalid position for hyphen",
                    label
                )));
            }
        }
    }

    Ok(())
}

/// Validate port number
///
/// # Security Requirements
/// - Ensures port is within valid range (1-65535)
/// - Type-safe validation using u16
///
/// # Arguments
/// * `port` - The port number to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_port(port: u16) -> std::result::Result<(), ValidationError> {
    // u16 already constrains to 0-65535, but we reject 0
    if port == 0 {
        return Err(ValidationError::InvalidPort(
            "Port must be between 1 and 65535".to_string(),
        ));
    }
    Ok(())
}

/// Validate OpenSSL cipher string
///
/// # Security Requirements
/// - Allows standard cipher names and OpenSSL cipher string syntax
/// - Rejects shell metacharacters
/// - Prevents command injection
///
/// # Arguments
/// * `cipher` - The cipher string to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_cipher(cipher: &str) -> std::result::Result<(), ValidationError> {
    if cipher.is_empty() {
        return Err(ValidationError::InvalidCipher(
            "Cipher cannot be empty".to_string(),
        ));
    }

    // Maximum reasonable length for cipher string
    if cipher.len() > 512 {
        return Err(ValidationError::InvalidCipher(
            "Cipher string too long".to_string(),
        ));
    }

    // Allow alphanumeric, hyphens, underscores, colons, exclamation marks, plus signs, and @ (OpenSSL cipher syntax)
    // Reject dangerous shell metacharacters
    for ch in cipher.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | ':' | '!' | '+' | '@' => continue,
            _ => {
                return Err(ValidationError::InvalidCipher(format!(
                    "Cipher contains invalid character: '{}'",
                    ch
                )));
            }
        }
    }

    Ok(())
}

/// Validate STARTTLS protocol name
///
/// # Security Requirements
/// - Allows only known STARTTLS protocols
/// - Prevents command injection via protocol field
///
/// # Arguments
/// * `protocol` - The protocol name to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_starttls_protocol(protocol: &str) -> std::result::Result<(), ValidationError> {
    // Whitelist of valid STARTTLS protocols supported by OpenSSL s_client
    const VALID_PROTOCOLS: &[&str] = &[
        "smtp",
        "pop3",
        "imap",
        "ftp",
        "xmpp",
        "xmpp-server",
        "irc",
        "postgres",
        "mysql",
        "lmtp",
        "nntp",
        "sieve",
        "ldap",
    ];

    if !VALID_PROTOCOLS.contains(&protocol) {
        return Err(ValidationError::InvalidProtocol(format!(
            "Unknown STARTTLS protocol: '{}'. Valid protocols: {}",
            protocol,
            VALID_PROTOCOLS.join(", ")
        )));
    }

    Ok(())
}

/// Check if IP address is private/internal (SSRF prevention)
///
/// # Security Requirements
/// - Prevents SSRF attacks by blocking private IP ranges
/// - Implements RFC 1918, RFC 4193, and other reserved ranges
/// - OWASP A10:2021 - Server-Side Request Forgery
///
/// # Arguments
/// * `ip` - The IP address to check
///
/// # Returns
/// * `true` if IP is private/internal
/// * `false` if IP is public
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if IPv4 address is private/internal
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    // RFC 1918 private networks
    ip.is_private()
        // Loopback
        || ip.is_loopback()
        // Link-local
        || ip.is_link_local()
        // Documentation (RFC 5737)
        || ip.is_documentation()
        // Broadcast
        || ip.is_broadcast()
        // Unspecified
        || ip.is_unspecified()
        // Multicast
        || ip.is_multicast()
        // Reserved (240.0.0.0/4)
        || ip.octets()[0] >= 240
        // Carrier-grade NAT (100.64.0.0/10, RFC 6598)
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
        // IPv4 mapped IPv6 (RFC 4291)
        || (ip.octets()[0] == 0 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
}

/// Check if IPv6 address is private/internal
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback
    ip.is_loopback()
        // Unspecified
        || ip.is_unspecified()
        // Multicast
        || ip.is_multicast()
        // Unique local (fc00::/7, RFC 4193)
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // Link-local (fe80::/10, RFC 4291)
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        // Documentation (2001:db8::/32, RFC 3849)
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
}

/// Validate target format and check for SSRF
///
/// # Security Requirements
/// - Validates hostname or IP address
/// - Optionally validates port if present
/// - Checks for SSRF attempts via private IPs
/// - Enforces length limits
///
/// # Arguments
/// * `target` - The target in format "hostname" or "hostname:port"
/// * `allow_private_ips` - Whether to allow private IP addresses
///
/// # Returns
/// * `Ok((hostname, port))` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_target(
    target: &str,
    allow_private_ips: bool,
) -> std::result::Result<(String, Option<u16>), ValidationError> {
    // Check length
    if target.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Target cannot be empty".to_string(),
        ));
    }

    if target.len() > 300 {
        return Err(ValidationError::InvalidHostname(
            "Target string too long".to_string(),
        ));
    }

    // Parse hostname and port
    let parts: Vec<&str> = target.split(':').collect();

    let hostname = parts[0];
    let port = if parts.len() > 1 {
        parts[1]
            .parse::<u16>()
            .map_err(|_| ValidationError::InvalidPort("Invalid port format".to_string()))?
    } else {
        0
    };

    // Validate hostname
    validate_hostname(hostname)?;

    // Validate port if present
    if port != 0 {
        validate_port(port)?;
    }

    // SSRF check: reject private IPs if not allowed
    if !allow_private_ips
        && let Ok(ip) = hostname.parse::<IpAddr>()
            && is_private_ip(&ip) {
                return Err(ValidationError::SsrfAttempt(format!(
                    "Access to private IP addresses is not allowed: {}",
                    ip
                )));
            }

    let port_opt = if port != 0 { Some(port) } else { None };

    Ok((hostname.to_string(), port_opt))
}

/// Sanitize and validate filesystem path
///
/// # Security Requirements
/// - Prevents path traversal attacks (CWE-22)
/// - Canonicalizes path and verifies it's within allowed directory
/// - Rejects null bytes and other dangerous characters
/// - OWASP A01:2021 - Broken Access Control
///
/// # Arguments
/// * `path` - The path to sanitize
/// * `base_dir` - The base directory that path must be within
///
/// # Returns
/// * `Ok(PathBuf)` - The canonicalized safe path
/// * `Err(ValidationError)` if path is invalid or attempts traversal
pub fn sanitize_path(path: &str, base_dir: &Path) -> std::result::Result<PathBuf, ValidationError> {
    // Check for null bytes
    if path.contains('\0') {
        return Err(ValidationError::InvalidPath(
            "Path contains null byte".to_string(),
        ));
    }

    // Reject absolute paths or paths starting with path separators
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(ValidationError::InvalidPath(
            "Absolute paths are not allowed".to_string(),
        ));
    }

    // Reject path traversal sequences
    if path.contains("..") {
        return Err(ValidationError::InvalidPath(
            "Path traversal sequences (..) are not allowed".to_string(),
        ));
    }

    // On Windows, reject paths with drive letters
    #[cfg(windows)]
    {
        if path.len() >= 2 && path.as_bytes()[1] == b':' {
            return Err(ValidationError::InvalidPath(
                "Drive letters are not allowed".to_string(),
            ));
        }
    }

    // Build full path
    let full_path = base_dir.join(path);

    // Canonicalize both paths to resolve symlinks and relative components
    let canonical_base = base_dir.canonicalize().map_err(|e| {
        ValidationError::InvalidPath(format!("Cannot canonicalize base dir: {}", e))
    })?;

    let canonical_path = full_path.canonicalize().unwrap_or_else(|_| {
        // If file doesn't exist yet, canonicalize parent and append filename
        if let Some(parent) = full_path.parent()
            && let Ok(canonical_parent) = parent.canonicalize()
                && let Some(filename) = full_path.file_name() {
                    return canonical_parent.join(filename);
                }
        full_path.clone()
    });

    // Verify the canonical path is within the base directory
    if !canonical_path.starts_with(&canonical_base) {
        return Err(ValidationError::InvalidPath(format!(
            "Path escapes base directory: {} not under {}",
            canonical_path.display(),
            canonical_base.display()
        )));
    }

    Ok(canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("localhost").is_ok());
        assert!(validate_hostname("test-server-01.example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_invalid() {
        // Command injection attempts
        assert!(validate_hostname("example.com; rm -rf /").is_err());
        assert!(validate_hostname("example.com|whoami").is_err());
        assert!(validate_hostname("example.com`id`").is_err());
        assert!(validate_hostname("example.com$(whoami)").is_err());

        // Path traversal
        assert!(validate_hostname("../../etc/passwd").is_err());
        assert!(validate_hostname("example.com/../../etc").is_err());

        // Invalid characters
        assert!(validate_hostname("example com").is_err());
        assert!(validate_hostname("example\ncom").is_err());

        // Empty or too long
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname(&"a".repeat(300)).is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(443).is_ok());
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_cipher_valid() {
        assert!(validate_cipher("AES256-GCM-SHA384").is_ok());
        assert!(validate_cipher("ECDHE-RSA-AES256-GCM-SHA384").is_ok());
        assert!(validate_cipher("HIGH:!aNULL:!MD5").is_ok());
        assert!(validate_cipher("TLS_AES_256_GCM_SHA384").is_ok());
    }

    #[test]
    fn test_validate_cipher_invalid() {
        assert!(validate_cipher("AES256; rm -rf /").is_err());
        assert!(validate_cipher("AES256|whoami").is_err());
        assert!(validate_cipher("AES256`id`").is_err());
        assert!(validate_cipher("").is_err());
    }

    #[test]
    fn test_validate_starttls_protocol() {
        assert!(validate_starttls_protocol("smtp").is_ok());
        assert!(validate_starttls_protocol("imap").is_ok());
        assert!(validate_starttls_protocol("invalid").is_err());
        assert!(validate_starttls_protocol("smtp; whoami").is_err());
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));

        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"2001:db8::1".parse().unwrap()));

        assert!(!is_private_ip(&"2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn test_validate_target() {
        // Valid targets
        assert!(validate_target("example.com", true).is_ok());
        assert!(validate_target("example.com:443", true).is_ok());

        // SSRF prevention
        assert!(validate_target("127.0.0.1", false).is_err());
        assert!(validate_target("10.0.0.1:443", false).is_err());
        assert!(validate_target("192.168.1.1", false).is_err());

        // Allow private IPs when flag is set
        assert!(validate_target("127.0.0.1", true).is_ok());
        assert!(validate_target("10.0.0.1:443", true).is_ok());

        // Invalid targets
        assert!(validate_target("", true).is_err());
        assert!(validate_target("example.com:99999", true).is_err());
    }

    #[test]
    fn test_sanitize_path() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let base = temp_dir.path();

        // Create a test file and subdirectory
        let test_file = base.join("test.txt");
        fs::write(&test_file, "test").expect("test assertion should succeed");

        // Create subdirectory for nested path test
        let subdir = base.join("subdir");
        fs::create_dir(&subdir).expect("test assertion should succeed");
        let nested_file = subdir.join("test.txt");
        fs::write(&nested_file, "test").expect("test assertion should succeed");

        // Valid paths
        assert!(sanitize_path("test.txt", base).is_ok());
        assert!(sanitize_path("subdir/test.txt", base).is_ok());

        // Path traversal attempts
        assert!(sanitize_path("../etc/passwd", base).is_err());
        assert!(sanitize_path("../../etc/passwd", base).is_err());
        assert!(sanitize_path("./../etc/passwd", base).is_err());

        // Absolute paths
        assert!(sanitize_path("/etc/passwd", base).is_err());

        // Null bytes
        assert!(sanitize_path("test\0.txt", base).is_err());
    }
}
