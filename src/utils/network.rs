// Network utilities - DNS resolution, socket helpers, etc.

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVersion};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// Import SSRF validation for DNS rebinding protection
use crate::security::input_validation::ssrf::validate_resolved_ips;

/// Target information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub hostname: String,
    pub port: u16,
    pub ip_addresses: Vec<IpAddr>,
}

/// Canonical target formatter.
///
/// Hostnames and IPv4 addresses are rendered as `host:port`.
/// IPv6 addresses are rendered as `[host]:port` to avoid ambiguity.
pub fn canonical_target(hostname: &str, port: u16) -> String {
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);

    if hostname.contains(':') {
        format!("[{}]:{}", hostname, port)
    } else {
        format!("{}:{}", hostname, port)
    }
}

/// Build a TLS server name from a hostname or IP literal.
///
/// This accepts DNS names, bracketed IPv6 literals, and raw IP literals.
/// IP targets are converted to `ServerName::IpAddress` so they can be used
/// in TLS handshakes without being treated as invalid DNS names.
pub fn server_name_for_hostname(
    hostname: &str,
) -> crate::Result<rustls_pki_types::ServerName<'static>> {
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(rustls_pki_types::ServerName::from(ip).to_owned());
    }

    rustls_pki_types::ServerName::try_from(hostname.to_string()).map_err(|_| {
        crate::error::TlsError::ParseError {
            message: "Invalid DNS name".into(),
        }
    })
}

/// Choose the hostname to use for an SNI extension.
///
/// Explicit overrides win. Otherwise, raw IP literals are omitted because SNI
/// is defined for DNS hostnames, not address literals.
pub fn sni_hostname_for_target(hostname: &str, override_hostname: Option<&str>) -> Option<String> {
    if let Some(override_hostname) = override_hostname {
        return Some(override_hostname.to_string());
    }

    let hostname = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);

    if hostname.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(hostname.to_string())
    }
}

/// Display a hostname without a port.
///
/// IPv6 literals are bracketed so the display remains unambiguous.
pub fn display_target_host(hostname: &str) -> String {
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);

    if hostname.contains(':') {
        format!("[{}]", hostname)
    } else {
        hostname.to_string()
    }
}

/// Split a target string into hostname and optional port without resolving DNS.
///
/// This parser accepts URLs, bracketed IPv6, raw IPv6 literals, and host[:port]
/// inputs. Raw IPv6 literals without brackets are treated as host-only values.
pub fn split_target_host_port(input: &str) -> Result<(String, Option<u16>)> {
    if input.contains("://") {
        let url = url::Url::parse(input)?;
        let host = url.host_str().context("No hostname in URL")?.to_string();
        return Ok((host, url.port()));
    }

    if let Some(rest) = input.strip_prefix('[') {
        if let Some(bracket_end) = rest.find(']') {
            let hostname = rest[..bracket_end].to_string();
            let suffix = &rest[bracket_end + 1..];
            if suffix.is_empty() {
                return Ok((hostname, None));
            }
            if let Some(port_str) = suffix.strip_prefix(':') {
                return Ok((hostname, Some(parse_port(port_str)?)));
            }
            return Err(anyhow::anyhow!("Invalid format after IPv6 address"));
        }
        return Err(anyhow::anyhow!(
            "Invalid IPv6 address format - missing closing bracket"
        ));
    }

    if let Ok(ipv6) = input.parse::<Ipv6Addr>() {
        return Ok((ipv6.to_string(), None));
    }

    if let Some((host, port_str)) = input.rsplit_once(':')
        && !host.contains(':')
    {
        return Ok((host.to_string(), Some(parse_port(port_str)?)));
    }

    if input.contains(':') {
        anyhow::bail!("Invalid target format: use [IPv6]:port for IPv6 addresses with ports");
    }

    Ok((input.to_string(), None))
}

impl Target {
    /// Parse target from string (host:port or just host)
    pub async fn parse(input: &str) -> Result<Self> {
        Self::parse_with_port_override(input, None).await
    }

    /// Parse target from string, allowing an explicit port override.
    ///
    /// The override wins over any embedded port in the input.
    pub async fn parse_with_port_override(input: &str, port_override: Option<u16>) -> Result<Self> {
        let (hostname, parsed_port) = split_target_host_port(input)?;
        let port = port_override.or(parsed_port).unwrap_or(443);
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
    ///
    /// # Panics
    /// This method will panic if the Target was constructed improperly (empty IP list).
    /// This should never happen with Target::parse() or Target::with_ips() which
    /// enforce non-empty IP addresses.
    pub fn primary_ip(&self) -> IpAddr {
        // Use first() for clearer intent and better error message if invariant is violated
        *self.ip_addresses.first().expect(
            "Target must have at least one IP address (constructors enforce this invariant)",
        )
    }
}

/// Resolve hostname to IP addresses with DNS caching
///
/// Performance optimization: Uses global DNS cache to avoid redundant lookups.
/// This significantly improves mass scanning performance by reducing DNS queries.
///
/// # Security
/// Validates resolved IPs against SSRF rules by default (blocks private IPs).
/// Use `resolve_hostname_unsafe()` for internal scanning scenarios.
///
/// # Performance Characteristics
/// - Cache hit: O(1) - instant return
/// - Cache miss: O(n) where n is DNS resolution time
/// - Typical improvement: 100-500ms saved per cached lookup
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    resolve_hostname_with_ssrf_check(hostname, false).await
}

/// Resolve hostname without SSRF validation (for internal scanning).
///
/// # Security Warning
/// This function bypasses SSRF protection and should only be used when
/// internal network scanning is explicitly authorized.
pub async fn resolve_hostname_unsafe(hostname: &str) -> Result<Vec<IpAddr>> {
    resolve_hostname_with_ssrf_check(hostname, true).await
}

/// Internal implementation with SSRF check parameter.
async fn resolve_hostname_with_ssrf_check(
    hostname: &str,
    allow_private_ips: bool,
) -> Result<Vec<IpAddr>> {
    // Check if it's already an IP address
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        // SECURITY: Validate against SSRF rules (DNS rebinding protection)
        validate_resolved_ips(&[ip], allow_private_ips)
            .map_err(|e| anyhow::anyhow!("SSRF validation failed: {}", e))?;
        return Ok(vec![ip]);
    }

    // Check DNS cache first
    let cache = super::dns_cache::global_cache();
    if let Some(cached_ips) = cache.get(hostname).await {
        tracing::debug!("DNS cache hit for {}", hostname);
        // SECURITY: Validate cached IPs against SSRF rules
        validate_resolved_ips(&cached_ips, allow_private_ips).map_err(|e| {
            anyhow::anyhow!("SSRF validation failed for cached {}: {}", hostname, e)
        })?;
        return Ok(cached_ips);
    }

    // Cache miss - perform DNS lookup
    tracing::debug!("DNS cache miss for {}, performing lookup", hostname);
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();

    let response = resolver
        .lookup_ip(hostname)
        .await
        .context("DNS lookup failed")?;

    let ips: Vec<IpAddr> = response.iter().collect();

    if ips.is_empty() {
        anyhow::bail!("No IP addresses found for {}", hostname);
    }

    // SECURITY: Validate resolved IPs against SSRF rules (DNS rebinding protection)
    validate_resolved_ips(&ips, allow_private_ips)
        .map_err(|e| anyhow::anyhow!("SSRF validation failed for {}: {}", hostname, e))?;

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
        21 | 25 | 110 | 119 | 143 | 389 | 587 | 2525 | 5222 | 5269 | 5432 | 3306
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
            && builder.set_cipher_list(ciphers).is_err()
        {
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
    async fn test_split_target_host_port_hostname() {
        let (hostname, port) =
            split_target_host_port("example.com").expect("test assertion should succeed");
        assert_eq!(hostname, "example.com");
        assert_eq!(port, None);
    }

    #[tokio::test]
    async fn test_split_target_host_port_with_port() {
        let (hostname, port) =
            split_target_host_port("example.com:8443").expect("test assertion should succeed");
        assert_eq!(hostname, "example.com");
        assert_eq!(port, Some(8443));
    }

    #[tokio::test]
    async fn test_split_target_host_port_url() {
        let (hostname, port) = split_target_host_port("https://example.com:8443")
            .expect("test assertion should succeed");
        assert_eq!(hostname, "example.com");
        assert_eq!(port, Some(8443));
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

    #[tokio::test]
    async fn test_parse_target_raw_ipv6_without_port() {
        let target = Target::parse("2001:4860:4860::8888")
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "2001:4860:4860::8888");
        assert_eq!(target.port, 443);
        assert_eq!(target.ip_addresses.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_target_bracketed_ipv6_with_port() {
        let target = Target::parse("[2001:4860:4860::8888]:443")
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "2001:4860:4860::8888");
        assert_eq!(target.port, 443);
        assert_eq!(target.ip_addresses.len(), 1);
    }

    #[test]
    fn test_split_target_host_port_rejects_extra_colons() {
        let err = split_target_host_port("example.com:443:extra")
            .expect_err("should reject malformed host:port input");
        assert!(
            err.to_string()
                .contains("Invalid target format: use [IPv6]:port")
        );
    }

    #[tokio::test]
    async fn test_parse_target_with_explicit_port_override() {
        let target = Target::parse_with_port_override("93.184.216.34:443", Some(8443))
            .await
            .expect("test assertion should succeed");
        assert_eq!(target.hostname, "93.184.216.34");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn test_canonical_target_brackets_ipv6() {
        assert_eq!(canonical_target("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn test_canonical_target_strips_existing_brackets() {
        assert_eq!(canonical_target("[2001:db8::1]", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn test_sni_hostname_for_target_omits_ip_literals_without_override() {
        assert_eq!(sni_hostname_for_target("93.184.216.34", None), None);
        assert_eq!(sni_hostname_for_target("2001:db8::1", None), None);
        assert_eq!(
            sni_hostname_for_target("example.com", None),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_sni_hostname_for_target_prefers_override() {
        assert_eq!(
            sni_hostname_for_target("93.184.216.34", Some("sni.example")),
            Some("sni.example".to_string())
        );
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
    fn test_primary_ip_and_socket_addrs() {
        let ip: IpAddr = "192.0.2.10".parse().expect("test assertion should succeed");
        let target = Target::with_ips("example.com".to_string(), 8443, vec![ip])
            .expect("test assertion should succeed");
        assert_eq!(target.primary_ip(), ip);
        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), ip);
        assert_eq!(addrs[0].port(), 8443);
    }

    #[test]
    fn test_socket_addrs_multiple_ips() {
        let ips = vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()];
        let target = Target::with_ips("example.com".to_string(), 443, ips.clone())
            .expect("test assertion should succeed");
        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].ip(), ips[0]);
        assert_eq!(addrs[1].ip(), ips[1]);
    }

    #[tokio::test]
    async fn test_resolve_hostname_short_circuit_ip() {
        // Use a public IP address (Google DNS) to avoid SSRF validation
        let ips = resolve_hostname("8.8.8.8")
            .await
            .expect("test assertion should succeed");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "8.8.8.8".parse::<IpAddr>().unwrap());
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

    #[test]
    fn test_parse_port_invalid() {
        let result = parse_port("not-a-port");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_valid() {
        let port = parse_port("443").expect("test assertion should succeed");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_default_starttls_protocol_additional_ports() {
        assert_eq!(default_starttls_protocol(587), Some("smtp"));
        assert_eq!(default_starttls_protocol(2525), Some("smtp"));
        assert_eq!(default_starttls_protocol(3306), Some("mysql"));
    }

    #[test]
    fn test_starttls_port_and_protocol_mappings() {
        assert!(is_starttls_port(21));
        assert!(is_starttls_port(389));
        assert!(is_starttls_port(587));
        assert_eq!(default_starttls_protocol(21), Some("ftp"));
        assert_eq!(default_starttls_protocol(389), Some("ldap"));
        assert_eq!(default_starttls_protocol(465), None);
    }
}
