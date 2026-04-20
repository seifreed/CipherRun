// Reverse PTR Lookup Module
// Performs reverse DNS lookups to determine SNI from IP addresses

use crate::Result;
use crate::error::TlsError;
use crate::utils::sni_generator::SniGenerator;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::*;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use std::net::IpAddr;

/// Reverse PTR lookup utilities
pub struct ReversePtrLookup;

impl ReversePtrLookup {
    fn build_resolver() -> Result<TokioResolver> {
        TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|error| TlsError::ConfigError {
            message: format!("Failed to initialize DNS resolver: {error}"),
        })
    }

    /// Perform reverse PTR lookup for IP address
    pub async fn lookup_ptr(ip: &IpAddr) -> Result<String> {
        let resolver = Self::build_resolver()?;

        let lookup =
            resolver
                .reverse_lookup(*ip)
                .await
                .map_err(|e| TlsError::DnsResolutionFailed {
                    hostname: ip.to_string(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()),
                })?;

        // Get first PTR record
        let ptr_name = lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::PTR(ptr) => Some(ptr.to_string()),
                _ => None,
            })
            .ok_or_else(|| TlsError::DnsResolutionFailed {
                hostname: ip.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "No PTR records found"),
            })?;

        // Remove trailing dot if present
        let hostname = if ptr_name.ends_with('.') {
            ptr_name[..ptr_name.len() - 1].to_string()
        } else {
            ptr_name
        };

        // Validate hostname format
        if SniGenerator::is_valid_hostname(&hostname) {
            Ok(hostname)
        } else {
            Err(TlsError::InvalidInput {
                message: format!("Invalid hostname from PTR: {}", hostname),
            })
        }
    }

    /// Get SNI from IP address with fallback strategies
    pub async fn get_sni_for_ip(ip: &IpAddr) -> String {
        // Strategy 1: Try reverse PTR lookup
        if let Ok(hostname) = Self::lookup_ptr(ip).await {
            return hostname;
        }

        // Strategy 2: Try common patterns for known IP ranges
        if let Some(hostname) = Self::try_common_patterns(ip) {
            return hostname;
        }

        // Strategy 3: Generate random SNI as fallback
        SniGenerator::generate_random()
    }

    /// Try common hostname patterns for known IP ranges
    fn try_common_patterns(ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();

                // Check for common cloud provider patterns
                // AWS pattern: ec2-x-x-x-x.compute-1.amazonaws.com
                if (octets[0] == 3 || octets[0] == 52 || octets[0] == 54) && octets[1] < 255 {
                    return Some(format!(
                        "ec2-{}-{}-{}-{}.compute-1.amazonaws.com",
                        octets[0], octets[1], octets[2], octets[3]
                    ));
                }

                // Google Cloud pattern: x.x.x.x.bc.googleusercontent.com
                if octets[0] == 35 || octets[0] == 34 {
                    return Some(format!(
                        "{}.{}.{}.{}.bc.googleusercontent.com",
                        octets[3], octets[2], octets[1], octets[0]
                    ));
                }

                // Cloudflare pattern
                if octets[0] == 104 && octets[1] >= 16 && octets[1] <= 31 {
                    return Some("cloudflare.example.com".to_string());
                }

                None
            }
            IpAddr::V6(_) => {
                // For IPv6, we don't attempt pattern matching
                None
            }
        }
    }

    /// Construct reverse DNS query name (for debugging/manual queries)
    pub fn construct_reverse_query_name(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let mut nibbles = Vec::new();

                for segment in segments.iter().rev() {
                    for i in 0..4 {
                        let nibble = (segment >> (i * 4)) & 0xF;
                        nibbles.push(format!("{:x}", nibble));
                    }
                }

                format!("{}.ip6.arpa", nibbles.join("."))
            }
        }
    }

    /// Batch lookup multiple IPs
    pub async fn lookup_batch(ips: &[IpAddr]) -> Vec<(IpAddr, Option<String>)> {
        let mut results = Vec::new();

        for ip in ips {
            let hostname = Self::lookup_ptr(ip).await.ok();
            results.push((*ip, hostname));
        }

        results
    }

    /// Validate if PTR record matches forward lookup (for security)
    pub async fn validate_ptr_forward_match(ip: &IpAddr) -> Result<bool> {
        // Get PTR record
        let hostname = Self::lookup_ptr(ip).await?;

        // Perform forward lookup
        let resolver = Self::build_resolver()?;

        match ip {
            IpAddr::V4(_) => {
                let lookup = resolver.ipv4_lookup(&hostname).await.map_err(|e| {
                    TlsError::DnsResolutionFailed {
                        hostname: hostname.clone(),
                        source: std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()),
                    }
                })?;

                for resolved_ip in lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::A(ipv4) => Some(IpAddr::V4(ipv4.0)),
                        _ => None,
                    })
                {
                    if resolved_ip == *ip {
                        return Ok(true);
                    }
                }
            }
            IpAddr::V6(_) => {
                let lookup = resolver.ipv6_lookup(&hostname).await.map_err(|e| {
                    TlsError::DnsResolutionFailed {
                        hostname: hostname.clone(),
                        source: std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()),
                    }
                })?;

                for resolved_ip in lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::AAAA(ipv6) => Some(IpAddr::V6(ipv6.0)),
                        _ => None,
                    })
                {
                    if resolved_ip == *ip {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_reverse_query_name_ipv4() {
        let ip: IpAddr = "192.0.2.1".parse().expect("test assertion should succeed");
        let query = ReversePtrLookup::construct_reverse_query_name(&ip);
        assert_eq!(query, "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn test_construct_reverse_query_name_ipv4_zero() {
        let ip: IpAddr = "0.0.0.0".parse().expect("test assertion should succeed");
        let query = ReversePtrLookup::construct_reverse_query_name(&ip);
        assert_eq!(query, "0.0.0.0.in-addr.arpa");
    }

    #[test]
    fn test_construct_reverse_query_name_ipv6() {
        let ip: IpAddr = "2001:db8::1"
            .parse()
            .expect("test assertion should succeed");
        let query = ReversePtrLookup::construct_reverse_query_name(&ip);
        assert!(query.ends_with(".ip6.arpa"));
        assert!(query.contains("1.0.0.0"));
    }

    #[test]
    fn test_try_common_patterns_aws() {
        let ip: IpAddr = "52.1.2.3".parse().expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_some());
        assert!(pattern.unwrap().contains("amazonaws.com"));
    }

    #[test]
    fn test_try_common_patterns_gcp() {
        let ip: IpAddr = "35.1.2.3".parse().expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_some());
        assert!(pattern.unwrap().contains("googleusercontent.com"));
    }

    #[test]
    fn test_try_common_patterns_unknown() {
        let ip: IpAddr = "192.168.1.1"
            .parse()
            .expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_try_common_patterns_cloudflare() {
        let ip: IpAddr = "104.16.1.2".parse().expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert_eq!(pattern.as_deref(), Some("cloudflare.example.com"));
    }

    #[test]
    fn test_try_common_patterns_ipv6_none_additional() {
        let ip: IpAddr = "2001:db8::1"
            .parse()
            .expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_try_common_patterns_aws_alt_block() {
        let ip: IpAddr = "3.1.2.3".parse().expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_some());
        assert!(pattern.unwrap().contains("amazonaws.com"));
    }

    #[test]
    fn test_try_common_patterns_ipv6_none() {
        let ip: IpAddr = "2001:db8::2"
            .parse()
            .expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_construct_reverse_query_name_ipv6_contains_tail() {
        let ip: IpAddr = "2001:db8::1"
            .parse()
            .expect("test assertion should succeed");
        let query = ReversePtrLookup::construct_reverse_query_name(&ip);
        assert!(query.starts_with("1.0.0.0"));
        assert!(query.contains("8.b.d.0.1.0.0.2"));
        assert!(query.ends_with(".ip6.arpa"));
    }

    #[test]
    fn test_try_common_patterns_aws_54_block() {
        let ip: IpAddr = "54.10.20.30"
            .parse()
            .expect("test assertion should succeed");
        let pattern = ReversePtrLookup::try_common_patterns(&ip);
        assert!(pattern.is_some());
        assert!(pattern.unwrap().contains("amazonaws.com"));
    }

    // Note: Actual PTR lookups require network access and working DNS
    // These tests would be integration tests rather than unit tests
}
