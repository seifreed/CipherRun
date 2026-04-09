// Proxy support for HTTP/HTTPS connections
// Supports CONNECT method for HTTPS proxying

use crate::Result;
use crate::utils::network::canonical_target;
use anyhow::Context;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Parse proxy string (host:port or user:pass@host:port)
    pub fn parse(proxy_str: &str) -> Result<Self> {
        // Check for user:pass@host:port format
        if let Some((auth, hostport)) = proxy_str.split_once('@') {
            let (username, password) = if let Some((u, p)) = auth.split_once(':') {
                (Some(u.to_string()), Some(p.to_string()))
            } else {
                (Some(auth.to_string()), None)
            };

            let (host, port) = Self::parse_hostport(hostport)?;
            Ok(Self {
                host,
                port,
                username,
                password,
            })
        } else {
            // Simple host:port format
            let (host, port) = Self::parse_hostport(proxy_str)?;
            Ok(Self {
                host,
                port,
                username: None,
                password: None,
            })
        }
    }

    /// Parse host:port string
    fn parse_hostport(hostport: &str) -> Result<(String, u16)> {
        use crate::utils::network::split_target_host_port;

        let (host, port) = split_target_host_port(hostport)?;
        // Default to port 8080 for HTTP proxies
        Ok((host, port.unwrap_or(8080)))
    }

    /// Get socket address for proxy
    pub async fn socket_addr(&self) -> Result<SocketAddr> {
        let addrs = self.socket_addrs().await?;
        Ok(addrs
            .into_iter()
            .next()
            .context("No IP addresses found for proxy")?)
    }

    /// Get all socket addresses for proxy resolution.
    pub async fn socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        use crate::utils::network::resolve_hostname_unsafe;

        let ips = resolve_hostname_unsafe(&self.host).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect())
    }
}

/// Connect to target through HTTP CONNECT proxy
pub async fn connect_via_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    // Connect to proxy
    let proxy_addrs = proxy.socket_addrs().await?;
    let mut stream = connect_to_any_socket_addr(&proxy_addrs, connect_timeout).await?;

    // Send CONNECT request
    let connect_request =
        build_connect_request(target_host, target_port, &proxy.username, &proxy.password);

    stream.write_all(connect_request.as_bytes()).await?;

    // Read proxy response
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();

    timeout(Duration::from_secs(10), reader.read_line(&mut status_line))
        .await
        .context("Proxy response timeout")??;

    // Parse status line
    if !status_line.contains("200") {
        crate::tls_bail!("Proxy CONNECT failed: {}", status_line.trim());
    }

    // Read remaining headers until empty line
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header.trim().is_empty() {
            break;
        }
    }

    // Return the underlying stream
    Ok(reader.into_inner())
}

async fn connect_to_any_socket_addr(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let mut last_error: Option<anyhow::Error> = None;

    for addr in addrs {
        match timeout(connect_timeout, TcpStream::connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                last_error = Some(anyhow::anyhow!(
                    "Failed to connect to proxy {}: {}",
                    addr,
                    err
                ));
            }
            Err(_) => {
                last_error = Some(anyhow::anyhow!("Proxy connection timeout for {}", addr));
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("No IP addresses found for proxy"))
        .into())
}

/// Build HTTP CONNECT request
fn build_connect_request(
    host: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
) -> String {
    let authority = canonical_target(normalize_connect_host(host), port);
    let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", authority, authority);

    // Add Proxy-Authorization if credentials provided
    if let (Some(user), Some(pass)) = (username, password) {
        use base64::{Engine as _, engine::general_purpose};
        let credentials = format!("{}:{}", user, pass);
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }

    request.push_str("\r\n");
    request
}

fn normalize_connect_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

/// Check if proxy is working
pub async fn test_proxy(proxy: &ProxyConfig) -> Result<bool> {
    match connect_via_proxy(proxy, "example.com", 443, Duration::from_secs(10)).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_simple() {
        let proxy = ProxyConfig::parse("localhost:8080").expect("test assertion should succeed");
        assert_eq!(proxy.host, "localhost");
        assert_eq!(proxy.port, 8080);
        assert!(proxy.username.is_none());
    }

    #[test]
    fn test_parse_proxy_with_auth() {
        let proxy = ProxyConfig::parse("user:pass@proxy.example.com:3128")
            .expect("test assertion should succeed");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_proxy_default_port() {
        let proxy = ProxyConfig::parse("proxy.local").expect("test assertion should succeed");
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
    }

    #[test]
    fn test_parse_proxy_bracketed_ipv6() {
        let proxy = ProxyConfig::parse("[::1]:3128").expect("test assertion should succeed");
        assert_eq!(proxy.host, "::1");
        assert_eq!(proxy.port, 3128);
    }

    #[test]
    fn test_build_connect_request_no_auth() {
        let request = build_connect_request("example.com", 443, &None, &None);
        assert!(request.contains("CONNECT example.com:443"));
        assert!(request.contains("Host: example.com:443"));
        assert!(!request.contains("Proxy-Authorization"));
    }

    #[test]
    fn test_build_connect_request_with_auth() {
        let request = build_connect_request(
            "example.com",
            443,
            &Some("user".to_string()),
            &Some("pass".to_string()),
        );
        assert!(request.contains("CONNECT example.com:443"));
        assert!(request.contains("Proxy-Authorization: Basic"));
    }

    #[test]
    fn test_build_connect_request_brackets_ipv6() {
        let request = build_connect_request("2001:db8::1", 443, &None, &None);
        assert!(request.contains("CONNECT [2001:db8::1]:443"));
        assert!(request.contains("Host: [2001:db8::1]:443"));
    }

    #[test]
    fn test_parse_proxy_invalid_port_non_numeric() {
        let err = ProxyConfig::parse("proxy.example.com:notaport").expect_err("should fail");
        assert!(err.to_string().contains("Invalid port"));
    }

    #[test]
    fn test_parse_proxy_invalid_port() {
        let err = ProxyConfig::parse("proxy.local:notaport").expect_err("should fail");
        assert!(err.to_string().contains("Invalid port"));
    }

    #[test]
    fn test_parse_proxy_username_only() {
        let proxy =
            ProxyConfig::parse("user@proxy.local:8080").expect("test assertion should succeed");
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert!(proxy.password.is_none());
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
    }

    #[test]
    fn test_build_connect_request_username_only_no_header() {
        let request = build_connect_request("example.com", 443, &Some("user".to_string()), &None);
        assert!(!request.contains("Proxy-Authorization"));
    }

    #[test]
    fn test_parse_proxy_user_without_port_defaults() {
        let proxy = ProxyConfig::parse("user@proxy.local").expect("test assertion should succeed");
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert!(proxy.password.is_none());
    }

    #[tokio::test]
    async fn test_socket_addr_allows_private_ip_proxy() {
        let proxy = ProxyConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            username: None,
            password: None,
        };

        let addr = proxy
            .socket_addr()
            .await
            .expect("private proxy IP should be allowed");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_connect_to_any_socket_addr_falls_back_to_second_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let fallback_addr = listener
            .local_addr()
            .expect("listener should expose local addr");
        let unreachable_addr =
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);

        let stream =
            connect_to_any_socket_addr(&[unreachable_addr, fallback_addr], Duration::from_secs(1))
                .await
                .expect("second address should succeed");

        let peer = stream
            .peer_addr()
            .expect("connected stream should expose peer address");
        assert_eq!(peer, fallback_addr);
    }
}
