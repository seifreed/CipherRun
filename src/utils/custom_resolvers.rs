/// Custom DNS Resolvers - Support for custom DNS resolver configuration
///
/// This module provides functionality to use custom DNS resolvers instead of
/// the system default resolvers. This is useful for:
/// - Testing with specific DNS servers (e.g., Google DNS, Cloudflare DNS)
/// - DNS enumeration and reconnaissance
/// - Testing behind corporate proxies with custom DNS
/// - Avoiding DNS spoofing or poisoning from ISP DNS
use crate::Result;
use crate::security::input_validation::{looks_like_obfuscated_ip, validate_resolved_ips};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Custom DNS resolver configuration
pub struct CustomResolver {
    /// Addresses of DNS resolvers to use
    resolvers: Vec<SocketAddr>,
    /// Timeout for DNS queries
    query_timeout: Duration,
}

impl CustomResolver {
    /// Create a new custom resolver from a list of resolver addresses
    ///
    /// # Arguments
    /// * `resolvers` - List of DNS resolver addresses (can be IP:port or just IP)
    ///   - If only IP is provided, port 53 is assumed
    ///   - Examples: "8.8.8.8", "1.1.1.1:53", "208.67.222.222:5353"
    ///
    /// # Returns
    /// A Result containing the new CustomResolver or an error if parsing fails
    ///
    /// # Errors
    /// Returns an error if any resolver address cannot be parsed
    ///
    /// # Examples
    /// ```ignore
    /// let resolver = CustomResolver::new(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()])?;
    /// ```
    pub fn new(resolvers: Vec<String>) -> Result<Self> {
        let mut parsed_resolvers = Vec::new();

        for resolver_str in resolvers {
            let resolver_str = resolver_str.trim();

            // Prefer full socket address parsing first (handles IPv4:port and [IPv6]:port).
            let socket_addr = if let Ok(addr) = SocketAddr::from_str(resolver_str) {
                addr
            } else if let Some(ip_str) = resolver_str
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                let ip =
                    IpAddr::from_str(ip_str).map_err(|_| crate::TlsError::InvalidHandshake {
                        details: format!("Invalid resolver address '{}'", resolver_str),
                    })?;
                SocketAddr::new(ip, 53)
            } else if let Ok(ip) = IpAddr::from_str(resolver_str) {
                // Bare IP (IPv4 or IPv6) -> default DNS port 53.
                SocketAddr::new(ip, 53)
            } else if resolver_str.contains(':') {
                return Err(crate::TlsError::InvalidHandshake {
                    details: format!(
                        "Invalid resolver address '{}': expected [IPv6]:port or IPv4:port",
                        resolver_str
                    ),
                });
            } else {
                return Err(crate::TlsError::InvalidHandshake {
                    details: format!("Invalid resolver address '{}'", resolver_str),
                });
            };

            if socket_addr.port() == 0 {
                return Err(crate::TlsError::InvalidHandshake {
                    details: format!(
                        "Invalid resolver address '{}': port must be between 1 and 65535",
                        resolver_str
                    ),
                });
            }

            parsed_resolvers.push(socket_addr);
        }

        if parsed_resolvers.is_empty() {
            return Err(crate::TlsError::InvalidHandshake {
                details: "No valid resolvers provided".to_string(),
            });
        }

        Ok(Self {
            resolvers: parsed_resolvers,
            query_timeout: crate::constants::DNS_QUERY_TIMEOUT,
        })
    }

    /// Set the query timeout
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    fn build_resolver(&self) -> Result<TokioResolver> {
        let name_servers = self
            .resolvers
            .iter()
            .map(|resolver| {
                let mut udp = ConnectionConfig::udp();
                udp.port = resolver.port();

                let mut tcp = ConnectionConfig::tcp();
                tcp.port = resolver.port();

                NameServerConfig::new(resolver.ip(), true, vec![udp, tcp])
            })
            .collect();

        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);

        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|error| crate::TlsError::ConfigError {
                message: format!("Failed to initialize custom DNS resolver: {error}"),
            })
    }

    /// Resolve a hostname to IP addresses using custom resolvers
    ///
    /// Attempts to resolve the hostname using each configured resolver.
    /// Returns results from the first resolver that successfully responds.
    ///
    /// # Arguments
    /// * `hostname` - The hostname to resolve
    ///
    /// # Returns
    /// A Result containing a vector of resolved IP addresses
    ///
    /// # Errors
    /// Returns an error if all resolvers fail or the hostname cannot be resolved
    ///
    /// # Examples
    /// ```ignore
    /// let ips = resolver.resolve("example.com").await?;
    /// for ip in ips {
    ///     println!("IP: {}", ip);
    /// }
    /// ```
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        validate_custom_resolver_hostname(hostname, "hostname")?;

        let resolver = self.build_resolver()?;
        let response = tokio::time::timeout(self.query_timeout, resolver.lookup_ip(hostname))
            .await
            .map_err(|_| crate::TlsError::InvalidHandshake {
                details: format!(
                    "Timed out resolving hostname '{}' with custom resolvers",
                    hostname
                ),
            })?
            .map_err(|error| crate::TlsError::InvalidHandshake {
                details: format!(
                    "Failed to resolve hostname '{}' with custom resolvers: {}",
                    hostname, error
                ),
            })?;

        let mut all_ips: Vec<IpAddr> = response.iter().collect();
        all_ips.sort();
        all_ips.dedup();

        if all_ips.is_empty() {
            return Err(crate::TlsError::InvalidHandshake {
                details: format!(
                    "Failed to resolve hostname '{}' with custom resolvers",
                    hostname
                ),
            });
        }

        validate_custom_resolved_ips(hostname, &all_ips)?;

        Ok(all_ips)
    }

    /// Resolve MX records for a domain using the configured resolvers.
    pub async fn lookup_mx(&self, hostname: &str) -> Result<Vec<(u16, String)>> {
        validate_custom_resolver_hostname(hostname, "MX hostname")?;

        let resolver = self.build_resolver()?;
        let response = tokio::time::timeout(self.query_timeout, resolver.mx_lookup(hostname))
            .await
            .map_err(|_| crate::TlsError::InvalidHandshake {
                details: format!(
                    "Timed out resolving MX records for '{}' with custom resolvers",
                    hostname
                ),
            })?
            .map_err(|error| crate::TlsError::InvalidHandshake {
                details: format!(
                    "Failed to resolve MX records for '{}' with custom resolvers: {}",
                    hostname, error
                ),
            })?;

        let mut records = Vec::new();
        for record in response.answers() {
            if let RData::MX(mx) = &record.data
                && let Some(hostname) = normalize_mx_hostname(&mx.exchange.to_utf8())?
            {
                records.push((mx.preference, hostname));
            }
        }
        records.sort_by_key(|(priority, hostname)| (*priority, hostname.clone()));
        records.dedup();

        if records.is_empty() {
            return Err(crate::TlsError::InvalidHandshake {
                details: format!(
                    "No MX records found for '{}' with custom resolvers",
                    hostname
                ),
            });
        }

        Ok(records)
    }

    /// Get the list of configured resolvers
    pub fn resolvers(&self) -> &[SocketAddr] {
        &self.resolvers
    }

    /// Validate resolver addresses without actually performing queries
    ///
    /// This checks that all resolver addresses are valid and reachable.
    /// Returns a list of which resolvers are responsive.
    pub async fn validate_resolvers(&self) -> Vec<(SocketAddr, bool)> {
        let mut results = Vec::new();

        for resolver in &self.resolvers {
            // Try to connect to the resolver via TCP with a short timeout
            let validation_timeout = Duration::from_secs(2);
            let is_responsive = match tokio::time::timeout(
                validation_timeout,
                TcpStream::connect(resolver),
            )
            .await
            {
                Ok(Ok(_)) => true,   // Connection successful
                Ok(Err(_)) => false, // Connection failed
                Err(_) => false,     // Timeout
            };

            results.push((*resolver, is_responsive));
        }

        results
    }

    /// Get the primary (first) resolver
    pub fn primary_resolver(&self) -> Option<SocketAddr> {
        self.resolvers.first().copied()
    }

    /// Get the number of configured resolvers
    pub fn count(&self) -> usize {
        self.resolvers.len()
    }

    /// Get the query timeout
    pub fn delay(&self) -> Duration {
        self.query_timeout
    }
}

fn normalize_mx_hostname(hostname: &str) -> Result<Option<String>> {
    let hostname = hostname.trim();
    if hostname == "." {
        return Ok(None);
    }
    let hostname = hostname.trim_end_matches('.').to_string();
    crate::security::validate_hostname(&hostname).map_err(|error| {
        crate::TlsError::InvalidInput {
            message: format!("Invalid MX hostname: {error}"),
        }
    })?;
    let normalized_host = hostname.to_ascii_lowercase();
    if normalized_host == "localhost"
        || normalized_host.ends_with(".local")
        || normalized_host.ends_with(".internal")
    {
        return Err(crate::TlsError::InvalidInput {
            message: format!("Invalid MX hostname: private/local host {hostname}"),
        });
    }
    if hostname.parse::<IpAddr>().is_ok() || looks_like_obfuscated_ip(&hostname) {
        return Err(crate::TlsError::InvalidInput {
            message: format!("Invalid MX hostname: IP-like host {hostname}"),
        });
    }
    Ok(Some(hostname))
}

fn validate_custom_resolver_hostname(hostname: &str, label: &str) -> Result<()> {
    crate::security::validate_hostname(hostname).map_err(|error| crate::TlsError::InvalidInput {
        message: format!("Invalid custom resolver {label}: {error}"),
    })
}

fn validate_custom_resolved_ips(hostname: &str, ips: &[IpAddr]) -> Result<()> {
    validate_resolved_ips(ips, false).map_err(|error| crate::TlsError::InvalidInput {
        message: format!("Custom resolver result failed SSRF validation for {hostname}: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_with_port() {
        let resolvers = vec!["8.8.8.8:53".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        assert_eq!(resolver.count(), 1);
        assert_eq!(
            resolver.primary_resolver().unwrap(),
            SocketAddr::from_str("8.8.8.8:53").unwrap()
        );
    }

    #[test]
    fn test_parse_without_port() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::new("8.8.8.8".parse().unwrap(), 53);
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_normalize_mx_hostname_rejects_invalid_name() {
        let err = normalize_mx_hostname("bad/host.example.")
            .expect_err("invalid MX hostname should fail");

        assert!(err.to_string().contains("Invalid MX hostname"));
    }

    #[test]
    fn test_normalize_mx_hostname_rejects_ip_literal() {
        let err = normalize_mx_hostname("127.0.0.1.").expect_err("MX exchange must be a hostname");

        assert!(err.to_string().contains("IP-like host"));
    }

    #[test]
    fn test_normalize_mx_hostname_rejects_obfuscated_ip() {
        let err = normalize_mx_hostname("127.1.")
            .expect_err("obfuscated MX exchange must be a hostname");

        assert!(err.to_string().contains("obfuscated IP"));
    }

    #[test]
    fn test_normalize_mx_hostname_rejects_private_host() {
        let err = normalize_mx_hostname("localhost.")
            .expect_err("private MX exchange must be rejected");

        assert!(err.to_string().contains("private/local host"));
    }

    #[test]
    fn test_parse_multiple_resolvers() {
        let resolvers = vec![
            "8.8.8.8".to_string(),
            "1.1.1.1:53".to_string(),
            "208.67.222.222:5353".to_string(),
        ];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        assert_eq!(resolver.count(), 3);
    }

    #[test]
    fn test_primary_resolver_is_first() {
        let resolvers = vec!["8.8.8.8".to_string(), "1.1.1.1:53".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");
        assert_eq!(
            resolver.primary_resolver().unwrap(),
            SocketAddr::new("8.8.8.8".parse().unwrap(), 53)
        );
    }

    #[test]
    fn test_empty_resolvers() {
        let resolvers: Vec<String> = vec![];
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ip() {
        let resolvers = vec!["invalid-ip".to_string()];
        let result = CustomResolver::new(resolvers);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_port() {
        let resolvers = vec!["8.8.8.8:notaport".to_string()];
        let result = CustomResolver::new(resolvers);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv6_with_port() {
        let resolvers = vec!["[2001:db8::1]:5353".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::from_str("[2001:db8::1]:5353").unwrap();
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_parse_bracketed_ipv6_without_port_defaults_53() {
        let resolvers = vec!["[2001:db8::1]".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("bracketed IPv6 should parse");

        let expected = SocketAddr::new("2001:db8::1".parse().unwrap(), 53);
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_resolver_port_zero_is_error() {
        let result = CustomResolver::new(vec!["8.8.8.8:0".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolvers_access() {
        let resolvers = vec!["8.8.8.8".to_string(), "1.1.1.1:53".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        let list = resolver.resolvers();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|addr| addr.ip().to_string() == "8.8.8.8"));
    }

    #[test]
    fn test_with_timeout() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers)
            .unwrap()
            .with_timeout(std::time::Duration::from_secs(10));

        assert_eq!(resolver.query_timeout, std::time::Duration::from_secs(10));
    }

    #[test]
    fn test_delay_returns_timeout() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers)
            .unwrap()
            .with_timeout(std::time::Duration::from_secs(5));

        assert_eq!(resolver.delay(), std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_parse_ipv6_without_port_defaults_53() {
        let resolvers = vec!["2001:db8::1".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");

        assert_eq!(resolver.count(), 1);
        let expected = SocketAddr::new("2001:db8::1".parse().unwrap(), 53);
        assert_eq!(resolver.primary_resolver().unwrap(), expected);
    }

    #[test]
    fn test_parse_trims_whitespace() {
        let resolvers = vec![" 1.1.1.1:53 ".to_string()];
        let resolver = CustomResolver::new(resolvers).expect("test assertion should succeed");
        assert_eq!(resolver.count(), 1);
    }

    #[test]
    fn test_empty_string_resolver_is_error() {
        let resolvers = vec!["".to_string()];
        let result = CustomResolver::new(resolvers);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_delay_is_five_seconds() {
        let resolver = CustomResolver::new(vec!["8.8.8.8".to_string()])
            .expect("test assertion should succeed");
        assert_eq!(resolver.delay(), Duration::from_secs(5));
    }

    #[test]
    fn test_normalize_mx_hostname_skips_null_mx() {
        assert_eq!(
            normalize_mx_hostname(".").expect("null MX should parse"),
            None
        );
        assert_eq!(
            normalize_mx_hostname("mx.example.com.").expect("hostname should parse"),
            Some("mx.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_rejects_invalid_hostname_before_lookup() {
        let resolver =
            CustomResolver::new(vec!["8.8.8.8".to_string()]).expect("resolver should parse");

        let err = resolver
            .resolve("example.com/path")
            .await
            .expect_err("invalid hostname should fail before lookup");
        assert!(err.to_string().contains("Invalid custom resolver hostname"));
    }

    #[tokio::test]
    async fn test_lookup_mx_rejects_invalid_hostname_before_lookup() {
        let resolver =
            CustomResolver::new(vec!["8.8.8.8".to_string()]).expect("resolver should parse");

        let err = resolver
            .lookup_mx("example.com/path")
            .await
            .expect_err("invalid MX hostname should fail before lookup");
        assert!(
            err.to_string()
                .contains("Invalid custom resolver MX hostname")
        );
    }

    #[test]
    fn test_validate_custom_resolved_ips_rejects_private_ip() {
        let ips = ["127.0.0.1".parse().unwrap()];

        let err = validate_custom_resolved_ips("example.com", &ips)
            .expect_err("private custom resolver answers should be blocked");
        assert!(err.to_string().contains("SSRF validation"));
    }

    #[test]
    fn test_resolver_order_preserved() {
        let resolver = CustomResolver::new(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()])
            .expect("test assertion should succeed");

        let list = resolver.resolvers();
        assert_eq!(list[0].ip().to_string(), "1.1.1.1");
        assert_eq!(list[1].ip().to_string(), "8.8.8.8");
    }

    #[test]
    fn test_count_matches_resolvers_len() {
        let resolver = CustomResolver::new(vec!["8.8.8.8".to_string()])
            .expect("test assertion should succeed");
        assert_eq!(resolver.count(), resolver.resolvers().len());
    }
}
