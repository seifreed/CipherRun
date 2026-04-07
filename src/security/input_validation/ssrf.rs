use super::ValidationError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if IP address is private/internal (SSRF prevention)
///
/// # Security Requirements
/// - Prevents SSRF attacks by blocking private IP ranges
/// - Implements RFC 1918, RFC 4193, and other reserved ranges
/// - OWASP A10:2021 - Server-Side Request Forgery
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if IPv4 address is private/internal
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Reserved (240.0.0.0/4)
        || ip.octets()[0] >= 240
        // Carrier-grade NAT (100.64.0.0/10, RFC 6598)
        || (ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127)
}

/// Check if IPv6 address is private/internal
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Unique local (fc00::/7, RFC 4193)
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // Link-local (fe80::/10, RFC 4291)
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        // Documentation (2001:db8::/32, RFC 3849)
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        || is_ipv4_mapped_private(ip)
        // IPv4-compatible IPv6 addresses (::x.x.x.x, deprecated)
        || is_ipv4_compatible_ipv6(ip)
        // Deprecated site-local addresses (fec0::/10, RFC 3879)
        || (ip.segments()[0] & 0xffc0) == 0xfec0
}

/// Check if IPv6 address is IPv4-mapped (::ffff:x.x.x.x) AND the embedded IPv4 is private
fn is_ipv4_mapped_private(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let ipv4_addr = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        is_private_ipv4(&ipv4_addr)
    } else {
        false
    }
}

/// Check if IPv6 address is IPv4-compatible (::x.x.x.x, deprecated)
///
/// Only marks as private if the embedded IPv4 address is private.
fn is_ipv4_compatible_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    let all_zero_prefix = segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0;

    if !all_zero_prefix {
        return false;
    }

    let ipv4_addr = Ipv4Addr::new(
        (segments[6] >> 8) as u8,
        (segments[6] & 0xff) as u8,
        (segments[7] >> 8) as u8,
        (segments[7] & 0xff) as u8,
    );

    is_private_ipv4(&ipv4_addr)
}

/// Validate resolved IP addresses against SSRF rules.
///
/// This function MUST be called after DNS resolution to prevent DNS rebinding attacks.
pub fn validate_resolved_ips(
    ips: &[IpAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), ValidationError> {
    if allow_private_ips {
        return Ok(());
    }

    for ip in ips {
        if is_private_ip(ip) {
            return Err(ValidationError::SsrfAttempt(format!(
                "DNS resolution returned private IP address (DNS rebinding attack): {}",
                ip
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_is_private_ipv4_no_false_positives_for_zero_prefix() {
        assert!(
            !is_private_ip(&"0.0.0.1".parse().unwrap()),
            "0.0.0.1 should NOT be private - it's not an IPv4-mapped address"
        );
        assert!(
            !is_private_ip(&"0.0.0.255".parse().unwrap()),
            "0.0.0.255 should NOT be private"
        );
        assert!(
            !is_private_ip(&"0.1.2.3".parse().unwrap()),
            "0.1.2.3 should NOT be private"
        );
        assert!(
            is_private_ip(&"0.0.0.0".parse().unwrap()),
            "0.0.0.0 (unspecified) should be private"
        );
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
    fn test_is_private_ipv6_ipv4_mapped() {
        assert!(
            is_private_ip(&"::ffff:127.0.0.1".parse().unwrap()),
            "::ffff:127.0.0.1 (IPv4-mapped loopback) should be private"
        );
        assert!(
            is_private_ip(&"::ffff:10.0.0.1".parse().unwrap()),
            "::ffff:10.0.0.1 (IPv4-mapped private) should be private"
        );
        assert!(
            is_private_ip(&"::ffff:192.168.1.1".parse().unwrap()),
            "::ffff:192.168.1.1 (IPv4-mapped private) should be private"
        );
        assert!(
            is_private_ip(&"::ffff:172.16.0.1".parse().unwrap()),
            "::ffff:172.16.0.1 (IPv4-mapped private) should be private"
        );

        assert!(
            !is_private_ip(&"::ffff:8.8.8.8".parse().unwrap()),
            "::ffff:8.8.8.8 (IPv4-mapped public) should NOT be private"
        );
        assert!(
            !is_private_ip(&"::ffff:1.1.1.1".parse().unwrap()),
            "::ffff:1.1.1.1 (IPv4-mapped public) should NOT be private"
        );
    }

    #[test]
    fn test_is_private_ipv6_ipv4_compatible() {
        assert!(
            is_private_ip(&"::192.168.1.1".parse().unwrap()),
            "::192.168.1.1 (IPv4-compatible) should be private"
        );
        assert!(
            is_private_ip(&"::10.0.0.1".parse().unwrap()),
            "::10.0.0.1 (IPv4-compatible) should be private"
        );
    }

    #[test]
    fn test_is_private_ipv6_site_local() {
        assert!(
            is_private_ip(&"fec0::1".parse().unwrap()),
            "fec0::1 (deprecated site-local) should be private"
        );
        assert!(
            is_private_ip(&"fec0:0:0:ffff::1".parse().unwrap()),
            "fec0:0:0:ffff::1 should be private"
        );
    }

    #[test]
    fn test_validate_resolved_ips_rejects_private() {
        let private_ips: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];

        let result = validate_resolved_ips(&private_ips, false);
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::SsrfAttempt(_))));

        let public_ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let result = validate_resolved_ips(&public_ips, false);
        assert!(result.is_ok());

        let result = validate_resolved_ips(&private_ips, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_resolved_ips_detects_dns_rebinding() {
        let malicious_ips: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
        ];

        let result = validate_resolved_ips(&malicious_ips, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_resolved_ips_ipv6_mapped() {
        let ipv4_mapped_private: Vec<IpAddr> = vec!["::ffff:127.0.0.1".parse().unwrap()];
        let result = validate_resolved_ips(&ipv4_mapped_private, false);
        assert!(
            result.is_err(),
            "::ffff:127.0.0.1 (IPv4-mapped private) should be rejected"
        );

        let ipv4_mapped_public: Vec<IpAddr> = vec!["::ffff:8.8.8.8".parse().unwrap()];
        let result = validate_resolved_ips(&ipv4_mapped_public, false);
        assert!(
            result.is_ok(),
            "::ffff:8.8.8.8 (IPv4-mapped public) should be allowed"
        );
    }
}
