// Proxy support for HTTP/HTTPS connections
// Supports CONNECT method for HTTPS proxying

use crate::Result;
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
        if let Some((host, port_str)) = hostport.rsplit_once(':') {
            let port = port_str.parse::<u16>().context("Invalid proxy port")?;
            Ok((host.to_string(), port))
        } else {
            // Default to port 8080 for HTTP proxies
            Ok((hostport.to_string(), 8080))
        }
    }

    /// Get socket address for proxy
    pub async fn socket_addr(&self) -> Result<SocketAddr> {
        use crate::utils::network::resolve_hostname;

        let ips = resolve_hostname(&self.host).await?;
        let ip = ips.first().context("No IP addresses found for proxy")?;

        Ok(SocketAddr::new(*ip, self.port))
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
    let proxy_addr = proxy.socket_addr().await?;
    let mut stream = timeout(connect_timeout, TcpStream::connect(proxy_addr))
        .await
        .context("Proxy connection timeout")??;

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
        anyhow::bail!("Proxy CONNECT failed: {}", status_line.trim());
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

/// Build HTTP CONNECT request
fn build_connect_request(
    host: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
) -> String {
    let mut request = format!(
        "CONNECT {}:{} HTTP/1.1\r\n\
         Host: {}:{}\r\n",
        host, port, host, port
    );

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
        let proxy = ProxyConfig::parse("localhost:8080").unwrap();
        assert_eq!(proxy.host, "localhost");
        assert_eq!(proxy.port, 8080);
        assert!(proxy.username.is_none());
    }

    #[test]
    fn test_parse_proxy_with_auth() {
        let proxy = ProxyConfig::parse("user:pass@proxy.example.com:3128").unwrap();
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_proxy_default_port() {
        let proxy = ProxyConfig::parse("proxy.local").unwrap();
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
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
}
