// Network utilities - DNS resolution, socket helpers, etc.

use crate::Result;
use crate::error::TlsError;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::*;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use openssl::ssl::{ErrorCode, HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// Import SSRF validation for DNS rebinding protection
use crate::security::input_validation::{
    looks_like_obfuscated_ip, validate_hostname, validate_resolved_ips,
};
use crate::utils::{network_runtime, proxy::connect_via_proxy};

/// Target information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "TargetUnchecked")]
pub struct Target {
    pub hostname: String,
    pub port: u16,
    pub ip_addresses: Vec<IpAddr>,
}

#[derive(serde::Deserialize)]
struct TargetUnchecked {
    hostname: String,
    port: u16,
    ip_addresses: Vec<IpAddr>,
}

impl TryFrom<TargetUnchecked> for Target {
    type Error = String;

    fn try_from(value: TargetUnchecked) -> std::result::Result<Self, Self::Error> {
        Self::with_ips(value.hostname, value.port, value.ip_addresses).map_err(|e| e.to_string())
    }
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

    if hostname.parse::<std::net::IpAddr>().is_ok() && hostname.contains(':') {
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

    if looks_like_obfuscated_ip(hostname) {
        return Err(crate::error::TlsError::ParseError {
            message: "Invalid DNS name".into(),
        });
    }

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(rustls_pki_types::ServerName::from(ip).to_owned());
    }

    rustls_pki_types::ServerName::try_from(hostname.to_string()).map_err(|_| {
        crate::error::TlsError::ParseError {
            message: "Invalid DNS name".into(),
        }
    })
}

/// Canonicalize a DNS hostname by removing a single trailing dot.
///
/// `example.com.` is a valid absolute (rooted) FQDN and resolves fine, but the
/// rooted form must not reach the TLS layer: the SNI extension (RFC 6066
/// `HostName`) forbids a trailing dot, rustls' DNS `ServerName` rejects it, and
/// a certificate's SAN never carries one — so leaving it on causes the TLS 1.3
/// probe to fail and a spurious hostname mismatch. IP literals (which never end
/// in a dot) and the bare root `.` are left untouched.
pub fn normalize_dns_hostname(hostname: String) -> String {
    if hostname.parse::<IpAddr>().is_ok() {
        return hostname;
    }
    match hostname.strip_suffix('.') {
        Some(stripped) if !stripped.is_empty() => stripped.to_string(),
        _ => hostname,
    }
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

    if hostname.parse::<IpAddr>().is_ok() || looks_like_obfuscated_ip(hostname) {
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
    let input = input.trim();
    if input.trim().is_empty() {
        crate::tls_bail!("Target cannot be empty");
    }

    if input.contains("://") {
        let url = url::Url::parse(input)?;
        if !matches!(url.scheme(), "http" | "https") {
            crate::tls_bail!("Unsupported target URL scheme: {}", url.scheme());
        }
        if !url.username().is_empty() || url.password().is_some() {
            crate::tls_bail!("Target URL must not contain credentials");
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            crate::tls_bail!("Target URL must not include a path, query, or fragment");
        }
        let host = url
            .host_str()
            .ok_or_else(|| TlsError::Other("No hostname in URL".to_string()))?
            .to_string();
        if matches!(url.port(), Some(0)) {
            crate::tls_bail!("Port must be between 1 and 65535");
        }
        return Ok((host, url.port_or_known_default()));
    }

    if let Some(rest) = input.strip_prefix('[') {
        if let Some(bracket_end) = rest.find(']') {
            let (hostname, suffix) = rest.split_at(bracket_end);
            if hostname.parse::<Ipv6Addr>().is_err() {
                crate::tls_bail!("Bracketed targets must contain an IPv6 address");
            }
            let hostname = hostname.to_string();
            let suffix = suffix.strip_prefix(']').unwrap_or(suffix);
            if suffix.is_empty() {
                return Ok((hostname, None));
            }
            if let Some(port_str) = suffix.strip_prefix(':') {
                return Ok((hostname, Some(parse_port(port_str.trim())?)));
            }
            return Err(TlsError::Other(
                "Invalid format after IPv6 address".to_string(),
            ));
        }
        return Err(TlsError::Other(
            "Invalid IPv6 address format - missing closing bracket".to_string(),
        ));
    }

    if let Ok(ipv6) = input.parse::<Ipv6Addr>() {
        return Ok((ipv6.to_string(), None));
    }

    if let Some((host, port_str)) = input.rsplit_once(':')
        && !host.contains(':')
    {
        let host = host.trim();
        if host.is_empty() {
            crate::tls_bail!("Target host cannot be empty");
        }
        return Ok((host.to_string(), Some(parse_port(port_str.trim())?)));
    }

    if input.contains(':') {
        crate::tls_bail!("Invalid target format: use [IPv6]:port for IPv6 addresses with ports");
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
        let hostname = normalize_dns_hostname(hostname);
        validate_hostname(&hostname)
            .map_err(|error| TlsError::Other(format!("Invalid target hostname: {}", error)))?;
        let port = port_override.or(parsed_port).unwrap_or(443);
        if port == 0 {
            crate::tls_bail!("Port must be between 1 and 65535");
        }
        let ip_addresses = resolve_hostname(&hostname).await?;

        // Validate non-empty IP addresses
        if ip_addresses.is_empty() {
            return Err(TlsError::Other(format!(
                "No IP addresses could be resolved for target: {hostname}"
            )));
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
        let hostname = hostname.trim();
        if hostname.is_empty() {
            return Err(TlsError::Other(
                "Target hostname cannot be empty".to_string(),
            ));
        }
        if ip_addresses.is_empty() {
            return Err(TlsError::Other(
                "Target must have at least one IP address".to_string(),
            ));
        }
        if port == 0 {
            return Err(TlsError::Other(
                "Port must be between 1 and 65535".to_string(),
            ));
        }
        validate_hostname(hostname)
            .map_err(|error| TlsError::Other(format!("Invalid target hostname: {}", error)))?;
        // Canonicalize here too so every construction path (the --ip override and
        // custom-resolver branches build Targets directly through this) yields
        // the same hostname as the DNS path; otherwise a rooted FQDN reaches the
        // TLS layer / output inconsistently depending on how the scan was invoked.
        Ok(Self {
            hostname: normalize_dns_hostname(hostname.to_string()),
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

    /// Returns the primary IP address.
    pub fn primary_ip(&self) -> Result<IpAddr> {
        self.ip_addresses
            .first()
            .copied()
            .ok_or_else(|| TlsError::Other("Target must have at least one IP address".to_string()))
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

/// Public DNS servers used when the host has no usable system resolver
/// configuration (`/etc/resolv.conf` missing or empty, e.g. minimal containers).
const FALLBACK_DNS_SERVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];

/// Build an asynchronous DNS resolver from the host's system configuration.
///
/// Reads `/etc/resolv.conf` on Unix and the registry on Windows. When the
/// system configuration is unavailable, falls back to public DNS servers so
/// hostname resolution still works on hosts without a resolver configuration.
///
/// `ResolverConfig::default()` must not be used here: in hickory 0.26 it
/// carries no name servers, so every lookup fails with "no connections
/// available".
pub fn build_system_resolver() -> Result<TokioResolver> {
    if let Ok(builder) = TokioResolver::builder_tokio() {
        return builder.build().map_err(|e| {
            TlsError::Other(format!(
                "failed to build DNS resolver from system configuration: {e}"
            ))
        });
    }

    let name_servers = FALLBACK_DNS_SERVERS
        .iter()
        .map(|ip| {
            NameServerConfig::new(
                *ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            )
        })
        .collect();
    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| TlsError::Other(format!("failed to build fallback DNS resolver: {e}")))
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
            .map_err(|e| TlsError::Other(format!("SSRF validation failed: {e}")))?;
        return Ok(vec![ip]);
    }

    if looks_like_obfuscated_ip(hostname) {
        return Err(TlsError::InvalidInput {
            message: format!("Invalid hostname: obfuscated IP notation is not allowed: {hostname}"),
        });
    }

    // Check DNS cache first
    let cache = super::dns_cache::global_cache();
    if let Some(cached_ips) = cache.get(hostname).await {
        tracing::debug!("DNS cache hit for {}", hostname);
        // SECURITY: Validate cached IPs against SSRF rules
        validate_resolved_ips(&cached_ips, allow_private_ips).map_err(|e| {
            TlsError::Other(format!("SSRF validation failed for cached {hostname}: {e}"))
        })?;
        return Ok(cached_ips);
    }

    // Cache miss - perform DNS lookup
    tracing::debug!("DNS cache miss for {}, performing lookup", hostname);
    let resolver = build_system_resolver()?;

    let response =
        resolver
            .lookup_ip(hostname)
            .await
            .map_err(|e| TlsError::DnsResolutionFailed {
                hostname: hostname.to_string(),
                source: std::io::Error::other(e.to_string()),
            })?;

    let ips: Vec<IpAddr> = response.iter().collect();

    if ips.is_empty() {
        crate::tls_bail!("No IP addresses found for {}", hostname);
    }

    // SECURITY: Validate resolved IPs against SSRF rules (DNS rebinding protection)
    validate_resolved_ips(&ips, allow_private_ips)
        .map_err(|e| TlsError::Other(format!("SSRF validation failed for {hostname}: {e}")))?;

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
        connect_once(addr, connect_timeout, retry_config)
            .await
            .map(|_| ())
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
    let connect_op = || async { connect_once(addr, connect_timeout, retry_config).await };

    if let Some(config) = retry_config {
        // Use retry logic with exponential backoff
        super::retry::retry_with_backoff(config, connect_op).await
    } else {
        // No retry - fail immediately
        connect_op().await
    }
}

/// Connect to `addr` and, for plaintext-first services, upgrade the connection
/// via STARTTLS before returning it.
///
/// When `starttls` is `None` this is equivalent to [`connect_with_timeout`].
/// When `Some`, the appropriate STARTTLS negotiation is performed so callers
/// (vulnerability probes, certificate/cipher testers) receive a stream that is
/// positioned at the start of the TLS handshake rather than at the plaintext
/// application greeting (which would otherwise be misread as a corrupt TLS
/// record). `hostname` is used where the negotiation announces a client/server
/// name (e.g. SMTP EHLO, XMPP `to`).
pub async fn connect_with_starttls(
    addr: SocketAddr,
    connect_timeout: Duration,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    hostname: &str,
) -> Result<TcpStream> {
    let mut stream = connect_with_timeout(addr, connect_timeout, None).await?;
    if let Some(protocol) = starttls {
        let negotiator = crate::starttls::protocols::get_negotiator(protocol, hostname.to_string());
        crate::starttls::protocols::negotiate_starttls_with_timeout(
            negotiator.as_ref(),
            &mut stream,
            connect_timeout,
        )
        .await
        .map_err(|e| TlsError::StarttlsError {
            protocol: protocol.to_string(),
            details: format!("STARTTLS negotiation failed: {e}"),
        })?;
    }
    Ok(stream)
}

async fn connect_once(
    addr: SocketAddr,
    connect_timeout: Duration,
    retry_config: Option<&super::retry::RetryConfig>,
) -> Result<TcpStream> {
    let effective_timeout = retry_config
        .and_then(|config| config.adaptive.as_ref())
        .map(|adaptive| adaptive.connect_timeout())
        .unwrap_or(connect_timeout);

    if let Some(proxy) = network_runtime::current_proxy() {
        return connect_via_proxy(
            &proxy,
            &addr.ip().to_string(),
            addr.port(),
            effective_timeout,
        )
        .await
        .map_err(|e| TlsError::Other(format!("Proxy connection failed: {e}")));
    }

    timeout(effective_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| TlsError::ConnectionTimeout {
            duration: effective_timeout,
            addr,
        })?
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::ConnectionRefused {
                TlsError::ConnectionRefused { addr }
            } else {
                source.into()
            }
        })
}

/// Convert a Tokio TCP stream into a blocking std stream with socket timeouts.
///
/// OpenSSL handshakes in this codebase run on blocking sockets. Without explicit
/// read/write timeouts, some negative-handshake paths can wait indefinitely for
/// peer data and stall tests or scans.
pub fn into_blocking_std_stream(
    stream: TcpStream,
    socket_timeout: Duration,
) -> Result<StdTcpStream> {
    let std_stream = stream.into_std().map_err(|e| {
        TlsError::Other(format!(
            "failed to convert Tokio TCP stream to std::net::TcpStream: {e}"
        ))
    })?;
    std_stream.set_nonblocking(false).map_err(|e| {
        TlsError::Other(format!("failed to switch TCP stream to blocking mode: {e}"))
    })?;
    std_stream
        .set_read_timeout(Some(socket_timeout))
        .map_err(|e| TlsError::Other(format!("failed to configure TCP read timeout: {e}")))?;
    std_stream
        .set_write_timeout(Some(socket_timeout))
        .map_err(|e| TlsError::Other(format!("failed to configure TCP write timeout: {e}")))?;
    Ok(std_stream)
}

/// Parse port from string
pub fn parse_port(port_str: &str) -> Result<u16> {
    let port = port_str
        .parse::<u16>()
        .map_err(|e| TlsError::Other(format!("Invalid port number: {e}")))?;
    if port == 0 {
        crate::tls_bail!("Port must be between 1 and 65535");
    }
    Ok(port)
}

/// Whether a TLS handshake error string describes a transport-level anomaly
/// (connection reset, timeout, clean/unexpected EOF, no usable protocols)
/// rather than a protocol-level rejection (a TLS alert).
///
/// OpenSSL 3.x surfaces a mid-handshake connection close as an `SSL`-class
/// error ("unexpected eof while reading") rather than a `SYSCALL`, so callers
/// that classify a probe outcome must inspect the message to keep such
/// anomalies inconclusive instead of treating them as a definite "not
/// supported"/"not vulnerable" verdict.
pub fn is_transport_anomaly_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("unexpected eof")
        || error.contains("connection reset")
        || error.contains("reset by peer")
        || error.contains("connection refused")
        || error.contains("timed out")
        || error.contains("timeout")
        || error.contains("closed")
        || error.contains("no protocols available")
        || error.contains("shutdown while in init")
        || error.contains("errno=54")
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
    /// STARTTLS protocol to negotiate before the TLS handshake (plaintext-first
    /// services); `None` connects directly.
    pub starttls: Option<crate::starttls::StarttlsProtocol>,
}

impl Default for VulnSslConfig {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            cipher_list: None,
            timeout_secs: 5,
            verify_hostname: true,
            starttls: None,
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

    /// Negotiate STARTTLS before the handshake (for plaintext-first services).
    pub fn with_starttls(mut self, starttls: Option<crate::starttls::StarttlsProtocol>) -> Self {
        self.starttls = starttls;
        self
    }
}

/// Result of a vulnerability SSL connection attempt
#[derive(Debug)]
pub enum VulnSslResult {
    /// Connection succeeded - returns the SSL stream for further inspection
    Connected(SslStream<StdTcpStream>),
    /// Probe could not complete (transport/STARTTLS/local setup failure)
    Inconclusive,
    /// Connection failed definitively enough to mean "not supported" for the probe.
    Failed,
}

impl VulnSslResult {
    /// Check if the connection was successful
    pub fn is_connected(&self) -> bool {
        matches!(self, VulnSslResult::Connected(_))
    }

    pub fn is_inconclusive(&self) -> bool {
        matches!(self, VulnSslResult::Inconclusive)
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
        .ok_or(TlsError::NoSocketAddresses)?;
    let hostname = target.hostname.clone();

    // For plaintext-first services, upgrade via STARTTLS before the TLS handshake.
    let stream = match connect_with_starttls(
        addr,
        Duration::from_secs(config.timeout_secs),
        config.starttls,
        &hostname,
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return Ok(VulnSslResult::Inconclusive),
    };

    let std_stream = into_blocking_std_stream(stream, Duration::from_secs(config.timeout_secs))?;

    // Wrap blocking SSL operations in spawn_blocking to avoid blocking async runtime
    let result = tokio::task::spawn_blocking(move || -> Result<VulnSslResult> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        // Vulnerability/cipher probes detect a capability by whether a handshake
        // with a specific cipher/version succeeds; certificate validity is
        // irrelevant and is assessed separately. A verifying connector would
        // fail at cert validation on bad-cert hosts and false-negative.
        builder.set_verify(SslVerifyMode::NONE);

        if let Some(min_ver) = config.min_version {
            builder.set_min_proto_version(Some(min_ver))?;
        }

        if let Some(max_ver) = config.max_version {
            builder.set_max_proto_version(Some(max_ver))?;
        }

        if let Some(ciphers) = config.cipher_list
            && builder.set_cipher_list(ciphers).is_err()
        {
            return Ok(VulnSslResult::Inconclusive);
        }

        let connector = builder.build();

        match connector.connect(&hostname, std_stream) {
            Ok(ssl_stream) => Ok(VulnSslResult::Connected(ssl_stream)),
            Err(error) => Ok(classify_vuln_ssl_handshake_error(error)),
        }
    })
    .await
    .map_err(|e| TlsError::Other(format!("Spawn blocking failed: {e}")))??;

    Ok(result)
}

fn classify_vuln_ssl_handshake_error(
    error: HandshakeError<StdTcpStream>,
) -> VulnSslResult {
    match error {
        HandshakeError::SetupFailure(_) | HandshakeError::WouldBlock(_) => {
            VulnSslResult::Inconclusive
        }
        HandshakeError::Failure(stream) => match stream.error().code() {
            ErrorCode::SYSCALL
            | ErrorCode::ZERO_RETURN
            | ErrorCode::WANT_READ
            | ErrorCode::WANT_WRITE => VulnSslResult::Inconclusive,
            _ => {
                if is_transport_anomaly_error(&stream.error().to_string()) {
                    VulnSslResult::Inconclusive
                } else {
                    VulnSslResult::Failed
                }
            }
        },
    }
}

/// Simplified helper that returns a boolean for basic vulnerability checks.
///
/// Use this when you only need to know if the connection succeeded with
/// the given configuration (e.g., checking if SSL3 is supported).
pub async fn test_vuln_ssl_connection(target: &Target, config: VulnSslConfig) -> Result<bool> {
    let result = try_vuln_ssl_connection(target, config).await?;
    Ok(result.is_connected())
}

pub async fn test_vuln_ssl_connection_outcome(
    target: &Target,
    config: VulnSslConfig,
) -> Result<Option<bool>> {
    let result = try_vuln_ssl_connection(target, config).await?;
    if result.is_inconclusive() {
        Ok(None)
    } else {
        Ok(match result {
            VulnSslResult::Connected(_) => Some(true),
            VulnSslResult::Failed => Some(false),
            VulnSslResult::Inconclusive => None,
        })
    }
}

/// Outcome for single-cipher support probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSupportOutcome {
    Supported,
    NotSupported,
    Inconclusive,
}

impl CipherSupportOutcome {
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
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
    Ok(
        test_cipher_support_outcome(target, cipher, allow_ssl3, timeout_secs)
            .await?
            .is_supported(),
    )
}

/// Test if a specific cipher is supported, preserving inconclusive probe failures.
pub async fn test_cipher_support_outcome(
    target: &Target,
    cipher: &str,
    allow_ssl3: bool,
    timeout_secs: u64,
) -> Result<CipherSupportOutcome> {
    let addr = target
        .socket_addrs()
        .first()
        .copied()
        .ok_or(TlsError::NoSocketAddresses)?;
    let hostname = target.hostname.clone();
    let cipher = cipher.to_string();

    let stream = match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => return Ok(CipherSupportOutcome::Inconclusive),
    };

    let std_stream = into_blocking_std_stream(stream, Duration::from_secs(timeout_secs))?;

    // Wrap blocking SSL operations in spawn_blocking to avoid blocking async runtime
    let result = tokio::task::spawn_blocking(move || -> Result<CipherSupportOutcome> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        // Cipher support is independent of certificate validity (assessed
        // separately); a verifying connector would false-negative on bad-cert
        // hosts by failing the handshake at cert validation.
        builder.set_verify(SslVerifyMode::NONE);

        if allow_ssl3
            && builder
                .set_min_proto_version(Some(SslVersion::SSL3))
                .is_err()
        {
            return Ok(CipherSupportOutcome::Inconclusive);
        }

        // A `set_cipher_list` failure means the local OpenSSL build cannot offer
        // this cipher (e.g. RC4/3DES/export are compiled out of the vendored
        // build), so the server's support is undeterminable — not "unsupported".
        // Reporting NotSupported here would be a false negative.
        if builder.set_cipher_list(&cipher).is_err() {
            return Ok(CipherSupportOutcome::Inconclusive);
        }

        let connector = builder.build();

        match connector.connect(&hostname, std_stream) {
            Ok(_) => Ok(CipherSupportOutcome::Supported),
            Err(error) => {
                if is_transport_anomaly_error(&error.to_string()) {
                    Ok(CipherSupportOutcome::Inconclusive)
                } else {
                    Ok(CipherSupportOutcome::NotSupported)
                }
            }
        }
    })
    .await
    .map_err(|e| TlsError::Other(format!("Spawn blocking failed: {e}")))??;

    Ok(result)
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
