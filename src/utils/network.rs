// Network utilities - DNS resolution, socket helpers, etc.

use anyhow::{Context, Result};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVersion};
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Target information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

        // Validate non-empty IP addresses
        if ip_addresses.is_empty() {
            return Err(anyhow::anyhow!(
                "No IP addresses could be resolved for target: {}",
                hostname
            ));
        }

        Ok(Self {
            hostname,
            port,
            ip_addresses,
        })
    }

    /// Create a Target with pre-resolved IP addresses.
    /// Returns error if ip_addresses is empty.
    pub fn with_ips(hostname: String, port: u16, ip_addresses: Vec<IpAddr>) -> Result<Self> {
        if ip_addresses.is_empty() {
            return Err(anyhow::anyhow!("Target must have at least one IP address"));
        }
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

    /// Returns the primary IP address (guaranteed to exist after construction)
    pub fn primary_ip(&self) -> IpAddr {
        // Safe because we enforce non-empty in constructors
        self.ip_addresses[0]
    }
}

/// Resolve hostname to IP addresses with DNS caching
///
/// Performance optimization: Uses global DNS cache to avoid redundant lookups.
/// This significantly improves mass scanning performance by reducing DNS queries.
///
/// # Performance Characteristics
/// - Cache hit: O(1) - instant return
/// - Cache miss: O(n) where n is DNS resolution time
/// - Typical improvement: 100-500ms saved per cached lookup
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    // Check if it's already an IP address
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    // Check DNS cache first
    let cache = super::dns_cache::global_cache();
    if let Some(cached_ips) = cache.get(hostname).await {
        tracing::debug!("DNS cache hit for {}", hostname);
        return Ok(cached_ips);
    }

    // Cache miss - perform DNS lookup
    tracing::debug!("DNS cache miss for {}, performing lookup", hostname);
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let response = resolver
        .lookup_ip(hostname)
        .await
        .context("DNS lookup failed")?;

    let ips: Vec<IpAddr> = response.iter().collect();

    if ips.is_empty() {
        anyhow::bail!("No IP addresses found for {}", hostname);
    }

    // Store in cache for future use
    cache.insert(hostname.to_string(), ips.clone()).await;

    Ok(ips)
}

/// Test TCP connection to target with optional retry logic.
///
/// This function attempts to establish a TCP connection with configurable retry behavior.
/// It uses exponential backoff to handle transient network failures while avoiding
/// unnecessary retries for permanent failures (e.g., connection refused).
///
/// # Arguments
///
/// * `addr` - The socket address to connect to
/// * `connect_timeout` - Timeout for each connection attempt
/// * `retry_config` - Optional retry configuration. If None, no retries are performed.
pub async fn test_connection(
    addr: SocketAddr,
    connect_timeout: Duration,
    retry_config: Option<&super::retry::RetryConfig>,
) -> Result<()> {
    let connect_op = || async {
        let effective_timeout = retry_config
            .and_then(|config| config.adaptive.as_ref())
            .map(|adaptive| adaptive.connect_timeout())
            .unwrap_or(connect_timeout);

        timeout(effective_timeout, TcpStream::connect(addr))
            .await
            .context("Connection timeout")??;
        Ok(())
    };

    if let Some(config) = retry_config {
        // Use retry logic with exponential backoff
        super::retry::retry_with_backoff(config, connect_op).await
    } else {
        // No retry - fail immediately
        connect_op().await
    }
}

/// Connect to target with timeout and optional retry logic.
///
/// This function attempts to establish a TCP connection and return the stream.
/// It supports configurable retry behavior with exponential backoff for handling
/// transient network failures.
///
/// # Arguments
///
/// * `addr` - The socket address to connect to
/// * `connect_timeout` - Timeout for each connection attempt
/// * `retry_config` - Optional retry configuration. If None, no retries are performed.
pub async fn connect_with_timeout(
    addr: SocketAddr,
    connect_timeout: Duration,
    retry_config: Option<&super::retry::RetryConfig>,
) -> Result<TcpStream> {
    let connect_op = || async {
        let effective_timeout = retry_config
            .and_then(|config| config.adaptive.as_ref())
            .map(|adaptive| adaptive.connect_timeout())
            .unwrap_or(connect_timeout);

        let stream = timeout(effective_timeout, TcpStream::connect(addr))
            .await
            .context("Connection timeout")??;
        Ok(stream)
    };

    if let Some(config) = retry_config {
        // Use retry logic with exponential backoff
        super::retry::retry_with_backoff(config, connect_op).await
    } else {
        // No retry - fail immediately
        connect_op().await
    }
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

/// Configuration for SSL connection attempts in vulnerability testing
#[derive(Debug, Clone)]
pub struct VulnSslConfig {
    pub min_version: Option<SslVersion>,
    pub max_version: Option<SslVersion>,
    pub cipher_list: Option<&'static str>,
    pub timeout_secs: u64,
    pub verify_hostname: bool,
}

impl Default for VulnSslConfig {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            cipher_list: None,
            timeout_secs: 5,
            verify_hostname: true,
        }
    }
}

impl VulnSslConfig {
    /// Create config for testing SSL 3.0 support
    pub fn ssl3_only() -> Self {
        Self {
            min_version: Some(SslVersion::SSL3),
            max_version: Some(SslVersion::SSL3),
            ..Default::default()
        }
    }

    /// Create config for testing TLS 1.0 with specific ciphers
    pub fn tls10_with_ciphers(cipher_list: &'static str) -> Self {
        Self {
            min_version: Some(SslVersion::TLS1),
            max_version: Some(SslVersion::TLS1),
            cipher_list: Some(cipher_list),
            ..Default::default()
        }
    }

    /// Create config for testing specific cipher support
    pub fn with_ciphers(cipher_list: &'static str) -> Self {
        Self {
            cipher_list: Some(cipher_list),
            ..Default::default()
        }
    }

    /// Create config for testing export ciphers (requires SSL3 minimum)
    pub fn export_cipher(cipher_list: &'static str) -> Self {
        Self {
            min_version: Some(SslVersion::SSL3),
            cipher_list: Some(cipher_list),
            timeout_secs: 3,
            ..Default::default()
        }
    }

    /// Create config with custom timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

/// Result of a vulnerability SSL connection attempt
#[derive(Debug)]
pub enum VulnSslResult {
    /// Connection succeeded - returns the SSL stream for further inspection
    Connected(SslStream<StdTcpStream>),
    /// Connection failed (handshake rejected, timeout, etc.)
    Failed,
}

impl VulnSslResult {
    /// Check if the connection was successful
    pub fn is_connected(&self) -> bool {
        matches!(self, VulnSslResult::Connected(_))
    }
}

/// Attempt an SSL connection with the given configuration for vulnerability testing.
///
/// This helper consolidates the common pattern used across vulnerability testers:
/// 1. TCP connect with timeout
/// 2. Convert to std stream and set blocking mode
/// 3. Configure SSL builder with version/cipher constraints
/// 4. Attempt SSL handshake
///
/// Returns `VulnSslResult::Connected` with the stream if successful, allowing
/// further inspection (e.g., checking cipher used, DH parameters, etc.).
pub async fn try_vuln_ssl_connection(
    target: &Target,
    config: VulnSslConfig,
) -> Result<VulnSslResult> {
    let addr = target
        .socket_addrs()
        .first()
        .copied()
        .context("No socket addresses available for target")?;
    let hostname = target.hostname.clone();

    let stream = match timeout(
        Duration::from_secs(config.timeout_secs),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return Ok(VulnSslResult::Failed),
    };

    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;

    // Wrap blocking SSL operations in spawn_blocking to avoid blocking async runtime
    let result = tokio::task::spawn_blocking(move || -> Result<VulnSslResult> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;

        if let Some(min_ver) = config.min_version {
            builder.set_min_proto_version(Some(min_ver))?;
        }

        if let Some(max_ver) = config.max_version {
            builder.set_max_proto_version(Some(max_ver))?;
        }

        if let Some(ciphers) = config.cipher_list
            && builder.set_cipher_list(ciphers).is_err() {
                return Ok(VulnSslResult::Failed);
            }

        let connector = builder.build();

        match connector.connect(&hostname, std_stream) {
            Ok(ssl_stream) => Ok(VulnSslResult::Connected(ssl_stream)),
            Err(_) => Ok(VulnSslResult::Failed),
        }
    })
    .await
    .context("Spawn blocking failed")??;

    Ok(result)
}

/// Simplified helper that returns a boolean for basic vulnerability checks.
///
/// Use this when you only need to know if the connection succeeded with
/// the given configuration (e.g., checking if SSL3 is supported).
pub async fn test_vuln_ssl_connection(target: &Target, config: VulnSslConfig) -> Result<bool> {
    let result = try_vuln_ssl_connection(target, config).await?;
    Ok(result.is_connected())
}

/// Test if a specific cipher is supported by the target.
///
/// This is a convenience function for vulnerability testers that need to check
/// support for individual ciphers (e.g., FREAK testing export ciphers, LOGJAM
/// testing DHE ciphers).
///
/// The `allow_ssl3` parameter enables SSL3 for export cipher testing.
pub async fn test_cipher_support(
    target: &Target,
    cipher: &str,
    allow_ssl3: bool,
    timeout_secs: u64,
) -> Result<bool> {
    let addr = target
        .socket_addrs()
        .first()
        .copied()
        .context("No socket addresses available for target")?;
    let hostname = target.hostname.clone();
    let cipher = cipher.to_string();

    let stream = match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return Ok(false),
    };

    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;

    // Wrap blocking SSL operations in spawn_blocking to avoid blocking async runtime
    let result = tokio::task::spawn_blocking(move || -> Result<bool> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;

        if allow_ssl3 {
            builder.set_min_proto_version(Some(SslVersion::SSL3))?;
        }

        if builder.set_cipher_list(&cipher).is_err() {
            return Ok(false);
        }

        let connector = builder.build();

        match connector.connect(&hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    })
    .await
    .context("Spawn blocking failed")??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_target_hostname() {
        let target = Target::parse("example.com")
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
        assert!(!target.ip_addresses.is_empty());
    }

    #[tokio::test]
    async fn test_parse_target_with_port() {
        let target = Target::parse("example.com:8443")
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 8443);
    }

    #[tokio::test]
    async fn test_parse_target_url() {
        let target = Target::parse("https://example.com:443")
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn test_parse_target_ip() {
        let target = Target::parse("93.184.216.34:443")
            .await
            .expect("test assertion should succeed");
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

    #[test]
    fn test_with_ips_valid() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        );
        assert!(target.is_ok());
        let target = target.unwrap();
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.ip_addresses.len(), 1);
    }

    #[test]
    fn test_with_ips_empty_fails() {
        let result = Target::with_ips("example.com".to_string(), 443, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one IP"));
    }

    #[test]
    fn test_primary_ip() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![
                "93.184.216.34".parse().unwrap(),
                "93.184.216.35".parse().unwrap(),
            ],
        )
        .unwrap();
        let primary: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(target.primary_ip(), primary);
    }
}
