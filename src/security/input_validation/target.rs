use super::ValidationError;
use super::hostname::validate_hostname;
use super::port::validate_port;
use super::ssrf::is_private_ip;
use std::net::{IpAddr, Ipv6Addr};

/// Validate target format and check for SSRF
///
/// # Security Requirements
/// - Validates hostname or IP address
/// - Optionally validates port if present
/// - Checks for SSRF attempts via private IPs
/// - Enforces length limits
pub fn validate_target(
    target: &str,
    allow_private_ips: bool,
) -> std::result::Result<(String, Option<u16>), ValidationError> {
    if target.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "Target cannot be empty".to_string(),
        ));
    }

    let (hostname, port) = if target.starts_with('[') {
        parse_bracketed_ipv6(target)?
    } else if target.contains("::") || target.matches(':').count() >= 2 {
        parse_unbracketed_ipv6(target)?
    } else {
        parse_host_port(target)?
    };

    validate_hostname(&hostname)?;

    if let Some(p) = port {
        validate_port(p)?;
    }

    if !allow_private_ips
        && let Ok(ip) = hostname.parse::<IpAddr>()
        && is_private_ip(&ip)
    {
        return Err(ValidationError::SsrfAttempt(format!(
            "Access to private IP addresses is not allowed: {}",
            ip
        )));
    }

    Ok((hostname, port))
}

/// Parse bracketed IPv6 target: `[::1]:443` or `[::1]`
fn parse_bracketed_ipv6(
    target: &str,
) -> std::result::Result<(String, Option<u16>), ValidationError> {
    if let Some(bracket_end) = target.find(']') {
        let hostname = &target[1..bracket_end];
        let rest = &target[bracket_end + 1..];
        let port = if let Some(port_str) = rest.strip_prefix(':') {
            Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| ValidationError::InvalidPort("Invalid port format".to_string()))?,
            )
        } else if rest.is_empty() {
            None
        } else {
            return Err(ValidationError::InvalidPort(
                "Invalid format after IPv6 address".to_string(),
            ));
        };
        Ok((hostname.to_string(), port))
    } else {
        Err(ValidationError::InvalidHostname(
            "Invalid IPv6 address format - missing closing bracket".to_string(),
        ))
    }
}

/// Parse unbracketed IPv6 target (multiple colons, no brackets).
/// Handles cases like `::1` (localhost), `2001:db8::1` (IPv6 only).
///
/// IMPORTANT: IPv6 addresses with ports MUST use bracketed notation:
/// - Correct: `[::1]:443`, `[2001:db8::1]:8080`
/// - Unbracketed IPv6 targets are treated as host-only values, even when the
///   final hextet is numeric.
fn parse_unbracketed_ipv6(
    target: &str,
) -> std::result::Result<(String, Option<u16>), ValidationError> {
    // First, try parsing as pure IPv6 address (no port)
    if target.parse::<Ipv6Addr>().is_ok() {
        return Ok((target.to_string(), None));
    }

    // Check if this looks like an IPv6 address with a port appended
    // (e.g., "::1:443" or "2001:db8::1:8080")
    if let Some(last_colon) = target.rfind(':') {
        let potential_port = &target[last_colon + 1..];
        if let Ok(port) = potential_port.parse::<u16>() {
            let potential_host = &target[..last_colon];
            // The host part must be a valid IPv6 address
            if potential_host.parse::<Ipv6Addr>().is_ok() {
                // AMBIGUOUS: This could be:
                // - IPv6 address `::1:443` (with port component in address)
                // - IPv6 `::1` with port `443`
                //
                // We REQUIRE bracketed notation to disambiguate.
                // Return an error with helpful guidance
                return Err(ValidationError::InvalidHostname(format!(
                    "Ambiguous IPv6 address with port: '{}'. \
                     IPv6 addresses with ports must use bracketed notation. \
                     Use '[{}]:{}' instead.",
                    target, potential_host, port
                )));
            }
        }
    }

    // If we reach here, the input looks like IPv6 but couldn't be fully parsed
    // Log a warning for the user to use bracketed notation
    if target.contains("::") || target.matches(':').count() >= 2 {
        tracing::warn!(
            "Potentially malformed IPv6 address '{}'. \
             Use bracketed notation [IPv6]:port for IPv6 addresses with ports, \
             e.g., '[::1]:443' or '[2001:db8::1]:443'.",
            target
        );
    }

    Ok((target.to_string(), None))
}

/// Parse regular hostname or IPv4 with optional port: `host:port` or `host`
fn parse_host_port(target: &str) -> std::result::Result<(String, Option<u16>), ValidationError> {
    let parts: Vec<&str> = target.split(':').collect();
    let hostname = parts[0].to_string();
    let port = if parts.len() > 1 {
        Some(
            parts[1]
                .parse::<u16>()
                .map_err(|_| ValidationError::InvalidPort("Invalid port format".to_string()))?,
        )
    } else {
        None
    };
    Ok((hostname, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_target() {
        assert!(validate_target("example.com", true).is_ok());
        assert!(validate_target("example.com:443", true).is_ok());

        assert!(validate_target("127.0.0.1", false).is_err());
        assert!(validate_target("10.0.0.1:443", false).is_err());
        assert!(validate_target("192.168.1.1", false).is_err());

        assert!(validate_target("127.0.0.1", true).is_ok());
        assert!(validate_target("10.0.0.1:443", true).is_ok());

        assert!(validate_target("", true).is_err());
        assert!(validate_target("example.com:99999", true).is_err());
    }

    #[test]
    fn test_validate_target_private_ipv6() {
        assert!(validate_target("fc00::1", false).is_err());
        assert!(validate_target("fc00::1", true).is_ok());
    }

    #[test]
    fn test_validate_target_public_ipv6_allowed() {
        let result = validate_target("2001:4860:4860::8888", false);
        assert!(result.is_ok(), "Expected IPv6 address to be valid");
        let (host, port) = result.expect("test assertion should succeed");
        assert_eq!(host, "2001:4860:4860::8888");
        assert!(port.is_none());
    }

    #[test]
    fn test_validate_target_ipv6_with_port() {
        let result = validate_target("[::1]:443", true);
        assert!(result.is_ok());
        let (host, port) = result.expect("test assertion should succeed");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn test_validate_target_ipv6_without_port() {
        let result = validate_target("::1", true);
        assert!(result.is_ok());
        let (host, port) = result.expect("test assertion should succeed");
        assert_eq!(host, "::1");
        assert!(port.is_none());
    }

    #[test]
    fn test_validate_target_with_max_port() {
        let result = validate_target("example.com:65535", true);
        assert!(result.is_ok());
        let (_host, port) = result.expect("test assertion should succeed");
        assert_eq!(port, Some(65535));
    }

    #[test]
    fn test_validate_target_allows_max_hostname_with_port() {
        let hostname = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(hostname.len(), 253);

        let result = validate_target(&format!("{}:443", hostname), true);
        assert!(
            result.is_ok(),
            "Hostname at RFC limit should remain valid with a port"
        );
        let (host, port) = result.expect("test assertion should succeed");
        assert_eq!(host, hostname);
        assert_eq!(port, Some(443));
    }

    #[test]
    fn test_validate_target_allows_ipv6_like_tail_without_brackets() {
        let result = validate_target("::1:443", true);

        assert!(
            result.is_ok(),
            "IPv6 literal should remain valid without brackets"
        );
        let (host, port) = result.expect("test assertion should succeed");

        assert_eq!(host, "::1:443");
        assert!(port.is_none());
    }

    #[test]
    fn test_validate_target_allows_compact_ipv6_with_numeric_tail() {
        let result = validate_target("2001:db8::1:2", true);

        assert!(result.is_ok(), "Compact IPv6 should remain valid");
        let (host, port) = result.expect("test assertion should succeed");

        assert_eq!(host, "2001:db8::1:2");
        assert!(port.is_none());
    }

    #[test]
    fn test_validate_target_allows_bracketed_ipv6_with_port_only() {
        let result = validate_target("[2001:db8::1]:8443", true);

        assert!(result.is_ok(), "Bracketed IPv6 with port should be allowed");
        let (host, port) = result.expect("test assertion should succeed");

        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, Some(8443));
    }
}
