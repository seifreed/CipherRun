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

    if target.len() > 300 {
        return Err(ValidationError::InvalidHostname(
            "Target string too long".to_string(),
        ));
    }

    let (hostname, port) = if target.starts_with('[') {
        parse_bracketed_ipv6(target)?
    } else if target.contains("::") || target.matches(':').count() >= 2 {
        parse_unbracketed_ipv6(target)
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
fn parse_unbracketed_ipv6(target: &str) -> (String, Option<u16>) {
    if target.parse::<Ipv6Addr>().is_ok() {
        return (target.to_string(), None);
    }
    if let Some(last_colon) = target.rfind(':') {
        let potential_port = &target[last_colon + 1..];
        if let Ok(port) = potential_port.parse::<u16>() {
            let potential_host = &target[..last_colon];
            if potential_host.parse::<Ipv6Addr>().is_ok() {
                return (potential_host.to_string(), Some(port));
            }
        }
    }
    (target.to_string(), None)
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
}
