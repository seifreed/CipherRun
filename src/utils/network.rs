// Network utilities - DNS resolution, socket helpers, etc.

use anyhow::{Context, Result};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Target information
#[derive(Debug, Clone)]
pub struct Target {
    pub hostname: String,
    pub port: u16,
    pub ip_addresses: Vec<IpAddr>,
}

impl Target {
    /// Parse target from string (host:port or just host)
    pub async fn parse(input: &str) -> Result<Self> {
        // Parse hostname and port
        let (hostname, port) = if input.contains("://") {
            // URL format (https://example.com:443)
            let url = url::Url::parse(input)?;
            let host = url.host_str().context("No hostname in URL")?.to_string();
            let port = url.port().unwrap_or(443);
            (host, port)
        } else if let Some((host, port_str)) = input.rsplit_once(':') {
            // host:port format
            let port = port_str.parse::<u16>()?;
            (host.to_string(), port)
        } else {
            // Just hostname, default to 443
            (input.to_string(), 443)
        };

        // Resolve IP addresses
        let ip_addresses = resolve_hostname(&hostname).await?;

        Ok(Self {
            hostname,
            port,
            ip_addresses,
        })
    }

    /// Get all socket addresses
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.ip_addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }

    /// Get primary IP (first one)
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.ip_addresses.first().copied()
    }
}

/// Resolve hostname to IP addresses
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    // Check if it's already an IP address
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    // Use hickory-resolver for async DNS
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let response = resolver
        .lookup_ip(hostname)
        .await
        .context("DNS lookup failed")?;

    let ips: Vec<IpAddr> = response.iter().collect();

    if ips.is_empty() {
        anyhow::bail!("No IP addresses found for {}", hostname);
    }

    Ok(ips)
}

/// Test TCP connection to target
pub async fn test_connection(addr: SocketAddr, connect_timeout: Duration) -> Result<()> {
    timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .context("Connection timeout")??;

    Ok(())
}

/// Connect to target with timeout
pub async fn connect_with_timeout(
    addr: SocketAddr,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let stream = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .context("Connection timeout")??;

    Ok(stream)
}

/// Parse port from string
pub fn parse_port(port_str: &str) -> Result<u16> {
    port_str.parse::<u16>().context("Invalid port number")
}

/// Check if port is STARTTLS by default
pub fn is_starttls_port(port: u16) -> bool {
    matches!(
        port,
        21 | 25 | 110 | 119 | 143 | 389 | 5222 | 5269 | 5432 | 3306
    )
}

/// Get default STARTTLS protocol for port
pub fn default_starttls_protocol(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        25 | 587 | 2525 => Some("smtp"),
        110 => Some("pop3"),
        119 => Some("nntp"),
        143 => Some("imap"),
        389 => Some("ldap"),
        5222 => Some("xmpp"),
        5269 => Some("xmpp-server"),
        5432 => Some("postgres"),
        3306 => Some("mysql"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_target_hostname() {
        let target = Target::parse("example.com").await.unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
        assert!(!target.ip_addresses.is_empty());
    }

    #[tokio::test]
    async fn test_parse_target_with_port() {
        let target = Target::parse("example.com:8443").await.unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 8443);
    }

    #[tokio::test]
    async fn test_parse_target_url() {
        let target = Target::parse("https://example.com:443").await.unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn test_parse_target_ip() {
        let target = Target::parse("93.184.216.34:443").await.unwrap();
        assert_eq!(target.hostname, "93.184.216.34");
        assert_eq!(target.port, 443);
        assert_eq!(target.ip_addresses.len(), 1);
    }

    #[test]
    fn test_starttls_port_detection() {
        assert!(is_starttls_port(25)); // SMTP
        assert!(is_starttls_port(143)); // IMAP
        assert!(!is_starttls_port(443)); // HTTPS
        assert!(!is_starttls_port(465)); // SMTPS
    }

    #[test]
    fn test_default_starttls_protocol() {
        assert_eq!(default_starttls_protocol(25), Some("smtp"));
        assert_eq!(default_starttls_protocol(143), Some("imap"));
        assert_eq!(default_starttls_protocol(443), None);
    }
}
