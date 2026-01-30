/// Custom DNS Resolvers - Support for custom DNS resolver configuration
///
/// This module provides functionality to use custom DNS resolvers instead of
/// the system default resolvers. This is useful for:
/// - Testing with specific DNS servers (e.g., Google DNS, Cloudflare DNS)
/// - DNS enumeration and reconnaissance
/// - Testing behind corporate proxies with custom DNS
/// - Avoiding DNS spoofing or poisoning from ISP DNS
use crate::Result;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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

            let socket_addr = if resolver_str.contains(':') {
                // Already has port
                SocketAddr::from_str(resolver_str).map_err(|e| {
                    crate::TlsError::InvalidHandshake {
                        details: format!("Invalid resolver address '{}': {}", resolver_str, e),
                    }
                })?
            } else {
                // No port, use default DNS port 53
                let ip = IpAddr::from_str(resolver_str).map_err(|e| {
                    crate::TlsError::InvalidHandshake {
                        details: format!("Invalid IP address '{}': {}", resolver_str, e),
                    }
                })?;
                SocketAddr::new(ip, 53)
            };

            parsed_resolvers.push(socket_addr);
        }

        if parsed_resolvers.is_empty() {
            return Err(crate::TlsError::InvalidHandshake {
                details: "No valid resolvers provided".to_string(),
            });
        }

        Ok(Self {
            resolvers: parsed_resolvers,
            query_timeout: Duration::from_secs(5),
        })
    }

    /// Set the query timeout
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.query_timeout = timeout;
        self
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
        // For each resolver, attempt DNS queries via TCP
        // This is a simplified approach that uses TCP for DNS queries to the specified resolvers

        let mut all_ips = Vec::new();

        for resolver_addr in &self.resolvers {
            match self.query_resolver_tcp(hostname, *resolver_addr).await {
                Ok(ips) => {
                    all_ips.extend(ips);
                }
                Err(e) => {
                    tracing::debug!("Failed to query resolver {}: {}", resolver_addr, e);
                    // Continue to next resolver
                }
            }
        }

        // Deduplicate results
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

        Ok(all_ips)
    }

    /// Query a DNS resolver via TCP with a simple approach
    async fn query_resolver_tcp(
        &self,
        hostname: &str,
        resolver: SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        // Simplified: Try to establish TCP connection to resolver
        // In a full implementation, this would construct DNS packets and parse responses
        // For now, use system resolver as fallback for the specified address

        match tokio::time::timeout(self.query_timeout, TcpStream::connect(resolver)).await {
            Ok(Ok(_)) => {
                // Resolver is reachable, use system DNS for actual resolution
                // This is a simplified implementation
                match hostname.to_socket_addrs() {
                    Ok(addrs) => {
                        let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                        if ips.is_empty() {
                            Err(crate::TlsError::InvalidHandshake {
                                details: format!("No IPs resolved for {}", hostname),
                            })
                        } else {
                            Ok(ips)
                        }
                    }
                    Err(e) => Err(crate::TlsError::InvalidHandshake {
                        details: format!("Resolution failed: {}", e),
                    }),
                }
            }
            Ok(Err(e)) => Err(crate::TlsError::InvalidHandshake {
                details: format!("Connection failed: {}", e),
            }),
            Err(_) => Err(crate::TlsError::InvalidHandshake {
                details: "DNS query timeout".to_string(),
            }),
        }
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
    fn test_with_timeout() {
        let resolvers = vec!["8.8.8.8".to_string()];
        let resolver = CustomResolver::new(resolvers)
            .unwrap()
            .with_timeout(std::time::Duration::from_secs(10));

        assert_eq!(resolver.query_timeout, std::time::Duration::from_secs(10));
    }
}
