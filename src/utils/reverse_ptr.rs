// Reverse PTR Lookup Module
// Performs reverse DNS lookups to determine SNI from IP addresses

use crate::Result;
use crate::error::TlsError;
use crate::utils::network::build_system_resolver;
use crate::utils::sni_generator::SniGenerator;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use std::future::Future;
use std::net::IpAddr;

/// Reverse PTR lookup utilities
pub struct ReversePtrLookup;

impl ReversePtrLookup {
    /// Perform reverse PTR lookup for IP address
    pub async fn lookup_ptr(ip: &IpAddr) -> Result<String> {
        let resolver = build_system_resolver().map_err(|error| TlsError::ConfigError {
            message: format!("Failed to initialize DNS resolver: {error}"),
        })?;
        Self::lookup_ptr_with_resolver(&resolver, ip).await
    }

    async fn lookup_ptr_with_resolver(resolver: &TokioResolver, ip: &IpAddr) -> Result<String> {
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
        let hostname = ptr_name.strip_suffix('.').unwrap_or(&ptr_name).to_string();

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
        Self::get_sni_for_ip_with_lookup(ip, Self::lookup_ptr(ip)).await
    }

    async fn get_sni_for_ip_with_lookup(
        ip: &IpAddr,
        lookup: impl Future<Output = Result<String>>,
    ) -> String {
        // Strategy 1: Try reverse PTR lookup
        if let Ok(hostname) = lookup.await {
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
        let resolver = build_system_resolver().map_err(|error| TlsError::ConfigError {
            message: format!("Failed to initialize DNS resolver: {error}"),
        })?;
        Self::validate_ptr_forward_match_with_resolver(ip, &hostname, &resolver).await
    }

    async fn validate_ptr_forward_match_with_resolver(
        ip: &IpAddr,
        hostname: &str,
        resolver: &TokioResolver,
    ) -> Result<bool> {
        match ip {
            IpAddr::V4(_) => {
                let lookup = resolver.ipv4_lookup(hostname).await.map_err(|e| {
                    TlsError::DnsResolutionFailed {
                        hostname: hostname.to_string(),
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
                let lookup = resolver.ipv6_lookup(hostname).await.map_err(|e| {
                    TlsError::DnsResolutionFailed {
                        hostname: hostname.to_string(),
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
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::{Name, Record, RecordType, rdata};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    async fn local_resolver_for(
        ptr_name: Option<&str>,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
    ) -> TokioResolver {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("local DNS socket should bind");
        let address = socket
            .local_addr()
            .expect("local DNS socket should have an address");
        let ptr_name = ptr_name.map(str::to_owned);
        tokio::spawn(async move {
            let mut buffer = [0; 2048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let mut response = Message::response(query.metadata.id, query.metadata.op_code);
                response.add_queries(query.queries.iter().cloned());
                for question in &query.queries {
                    let answer = match question.query_type() {
                        RecordType::PTR => ptr_name.as_ref().map(|name| {
                            Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::PTR(rdata::PTR(
                                    Name::from_ascii(name).expect("valid fixture DNS name"),
                                )),
                            )
                        }),
                        RecordType::A => Some(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::A(rdata::A(ipv4)),
                        )),
                        RecordType::AAAA => Some(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::AAAA(rdata::AAAA(ipv6)),
                        )),
                        _ => None,
                    };
                    if let Some(answer) = answer {
                        response.add_answer(answer);
                    }
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });

        let SocketAddr::V4(address) = address else {
            unreachable!("local DNS server uses IPv4");
        };
        let mut udp = ConnectionConfig::udp();
        udp.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(
                IpAddr::V4(*address.ip()),
                false,
                vec![udp],
            )],
        );
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .expect("local DNS resolver should build")
    }

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
    fn test_sni_generator_rejects_ip_literals() {
        assert!(!SniGenerator::is_valid_hostname("127.0.0.1"));
        assert!(!SniGenerator::is_valid_hostname("127.1"));
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
    fn test_try_common_patterns_provider_boundaries() {
        let cases = [
            ("52.255.1.2", None),
            ("34.1.2.3", Some("3.2.1.34.bc.googleusercontent.com")),
            ("104.15.1.2", None),
            ("104.31.1.2", Some("cloudflare.example.com")),
            ("104.32.1.2", None),
        ];

        for (address, expected) in cases {
            let ip: IpAddr = address.parse().expect("test assertion should succeed");
            assert_eq!(
                ReversePtrLookup::try_common_patterns(&ip).as_deref(),
                expected,
                "{address}"
            );
        }
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

    #[tokio::test]
    async fn get_sni_for_ip_prefers_ptr_lookup() {
        let ip: IpAddr = "52.1.2.3".parse().expect("test assertion should succeed");
        let hostname = ReversePtrLookup::get_sni_for_ip_with_lookup(&ip, async {
            Ok("ptr.example.com".to_string())
        })
        .await;

        assert_eq!(hostname, "ptr.example.com");
    }

    #[tokio::test]
    async fn get_sni_for_ip_uses_cloud_pattern_after_ptr_failure() {
        let ip: IpAddr = "52.1.2.3".parse().expect("test assertion should succeed");
        let hostname = ReversePtrLookup::get_sni_for_ip_with_lookup(&ip, async {
            Err(TlsError::InvalidInput {
                message: "PTR lookup failed".to_string(),
            })
        })
        .await;

        assert_eq!(hostname, "ec2-52-1-2-3.compute-1.amazonaws.com");
    }

    #[tokio::test]
    async fn get_sni_for_ip_generates_valid_fallback_after_ptr_failure() {
        let ip: IpAddr = "192.0.2.1".parse().expect("test assertion should succeed");
        let hostname = ReversePtrLookup::get_sni_for_ip_with_lookup(&ip, async {
            Err(TlsError::InvalidInput {
                message: "PTR lookup failed".to_string(),
            })
        })
        .await;

        assert!(SniGenerator::is_valid_hostname(&hostname));
    }

    #[tokio::test]
    async fn local_dns_exercises_ptr_and_forward_match_for_both_ip_families() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let ipv6 = "2001:db8::1".parse().expect("valid IPv6 address");
        let resolver = local_resolver_for(Some("ptr.example.com."), ipv4, ipv6).await;

        let hostname = ReversePtrLookup::lookup_ptr_with_resolver(&resolver, &ipv4.into())
            .await
            .expect("PTR response should produce a hostname");
        assert_eq!(hostname, "ptr.example.com");
        assert!(
            ReversePtrLookup::validate_ptr_forward_match_with_resolver(
                &ipv4.into(),
                &hostname,
                &resolver
            )
            .await
            .expect("matching A record should validate")
        );
        assert!(
            !ReversePtrLookup::validate_ptr_forward_match_with_resolver(
                &"192.0.2.2".parse().expect("valid IPv4 address"),
                &hostname,
                &resolver
            )
            .await
            .expect("non-matching forward address should be rejected")
        );

        let invalid_resolver = local_resolver_for(Some("invalid_hostname."), ipv4, ipv6).await;
        assert!(matches!(
            ReversePtrLookup::lookup_ptr_with_resolver(&invalid_resolver, &ipv4.into()).await,
            Err(TlsError::InvalidInput { .. })
        ));

        let empty_resolver = local_resolver_for(None, ipv4, ipv6).await;
        assert!(matches!(
            ReversePtrLookup::lookup_ptr_with_resolver(&empty_resolver, &ipv4.into()).await,
            Err(TlsError::DnsResolutionFailed { .. })
        ));
        assert!(
            ReversePtrLookup::validate_ptr_forward_match_with_resolver(
                &ipv6.into(),
                &hostname,
                &resolver
            )
            .await
            .expect("matching AAAA record should validate")
        );
    }

    // Note: Actual PTR lookups require network access and working DNS
    // These tests would be integration tests rather than unit tests
}
