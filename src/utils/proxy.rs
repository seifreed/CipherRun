// Proxy support for HTTP/HTTPS connections
// Supports CONNECT method for HTTPS proxying

use crate::Result;
use crate::error::TlsError;
use crate::utils::network::canonical_target;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    /// Parse proxy string (host:port, http://host:port, or user:pass@host:port)
    pub fn parse(proxy_str: &str) -> Result<Self> {
        let proxy_str = proxy_str.trim();
        if proxy_str.contains("://") && !proxy_str.starts_with("http://") {
            crate::tls_bail!("Unsupported proxy scheme; only http:// proxies are supported");
        }
        let proxy_str = proxy_str.strip_prefix("http://").unwrap_or(proxy_str);
        // Check for user:pass@host:port format
        if let Some((auth, hostport)) = proxy_str.rsplit_once('@') {
            let (username, password) = if let Some((u, p)) = auth.split_once(':') {
                if u.is_empty() {
                    crate::tls_bail!("Proxy username cannot be empty");
                }
                (Some(u.to_string()), Some(p.to_string()))
            } else {
                if auth.is_empty() {
                    crate::tls_bail!("Proxy username cannot be empty");
                }
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

        if hostport.trim().is_empty() {
            crate::tls_bail!("Proxy host cannot be empty");
        }
        if hostport.contains("://") {
            crate::tls_bail!("Proxy host must be host[:port], not a URL");
        }
        let (host, port) = split_target_host_port(hostport)?;
        if host.is_empty() {
            crate::tls_bail!("Proxy host cannot be empty");
        }
        // Default to port 8080 for HTTP proxies
        Ok((host, port.unwrap_or(8080)))
    }

    /// Get socket address for proxy
    pub async fn socket_addr(&self) -> Result<SocketAddr> {
        let addrs = self.socket_addrs().await?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::Other("No IP addresses found for proxy".to_string()))
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

    pub fn authority(&self) -> String {
        canonical_target(&self.host, self.port)
    }

    pub fn url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                format!("http://{}:{}@{}", username, password, self.authority())
            }
            (Some(username), None) => format!("http://{}@{}", username, self.authority()),
            _ => format!("http://{}", self.authority()),
        }
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

    timeout(
        Duration::from_secs(10),
        read_proxy_line(&mut reader, &mut status_line),
    )
    .await
    .map_err(|_| TlsError::Other("Proxy response timeout".to_string()))??;

    // Parse HTTP status code from "HTTP/1.x NNN Reason" — substring matching "200"
    // would accept any response body or reason phrase that happens to contain "200".
    let status_token =
        status_line
            .split(' ')
            .nth(1)
            .ok_or_else(|| TlsError::UnexpectedResponse {
                details: format!(
                    "Proxy CONNECT response missing status code: {}",
                    status_line.trim()
                ),
            })?;
    let status_code: u16 = status_token
        .parse()
        .map_err(|e| TlsError::UnexpectedResponse {
            details: format!(
                "Proxy CONNECT response has invalid status code '{}': {}",
                status_token, e
            ),
        })?;
    if !(200..300).contains(&status_code) {
        crate::tls_bail!("Proxy CONNECT failed: {}", status_line.trim());
    }

    // Read remaining headers until empty line.
    // Guard against a slow or malicious proxy sending headers indefinitely.
    const MAX_PROXY_HEADERS: usize = 100;
    let mut header_count = 0usize;
    loop {
        let mut header = String::new();
        timeout(
            Duration::from_secs(10),
            read_proxy_line(&mut reader, &mut header),
        )
        .await
        .map_err(|_| TlsError::Other("Proxy header read timeout".to_string()))??;
        header_count += 1;
        if header_count > MAX_PROXY_HEADERS {
            crate::tls_bail!("Proxy returned too many response headers");
        }
        if header.trim().is_empty() {
            break;
        }
    }

    // Return the underlying stream
    Ok(reader.into_inner())
}

async fn read_proxy_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
) -> Result<usize> {
    const MAX_PROXY_LINE_LEN: usize = 8192;
    let mut bytes = Vec::new();

    loop {
        let (take, done) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Err(TlsError::ConnectionClosed {
                        details: "Proxy closed connection before sending a response line"
                            .to_string(),
                    });
                }
                return Err(TlsError::UnexpectedResponse {
                    details: "Proxy response line ended before newline".to_string(),
                });
            }

            let newline_pos = available.iter().position(|&byte| byte == b'\n');
            let take = newline_pos.map_or(available.len(), |pos| pos + 1);
            if bytes.len().saturating_add(take) > MAX_PROXY_LINE_LEN {
                return Err(TlsError::UnexpectedResponse {
                    details: "Proxy response line too long".to_string(),
                });
            }
            bytes.extend_from_slice(&available[..take]);
            (take, newline_pos.is_some())
        };

        reader.consume(take);
        if done {
            break;
        }
    }

    let text = String::from_utf8(bytes).map_err(|error| TlsError::UnexpectedResponse {
        details: format!("Proxy response line is not valid UTF-8: {error}"),
    })?;
    let len = text.len();
    line.push_str(&text);
    Ok(len)
}

async fn connect_to_any_socket_addr(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let mut last_error: Option<TlsError> = None;

    for addr in addrs {
        match timeout(connect_timeout, TcpStream::connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                last_error = Some(TlsError::Other(format!(
                    "Failed to connect to proxy {addr}: {err}"
                )));
            }
            Err(_) => {
                last_error = Some(TlsError::Other(format!(
                    "Proxy connection timeout for {addr}"
                )));
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| TlsError::Other("No IP addresses found for proxy".to_string())))
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
    if let Some(user) = username {
        use base64::{Engine as _, engine::general_purpose};
        let credentials = format!("{}:{}", user, password.as_deref().unwrap_or(""));
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
    fn test_parse_proxy_accepts_http_url() {
        let proxy =
            ProxyConfig::parse("http://proxy.example.com:3128").expect("proxy URL should parse");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert!(proxy.username.is_none());
    }

    #[test]
    fn test_parse_proxy_rejects_https_url() {
        let err = ProxyConfig::parse("https://proxy.example.com:443")
            .expect_err("HTTPS proxy URLs are not supported");
        assert!(err.to_string().contains("Unsupported proxy scheme"));
    }

    #[test]
    fn test_parse_proxy_rejects_nested_url_after_http_scheme() {
        let err = ProxyConfig::parse("http://https://proxy.example.com:443")
            .expect_err("nested proxy URL should fail");
        assert!(err.to_string().contains("Proxy host must be host"));
    }

    #[test]
    fn test_parse_proxy_round_trips_url_with_auth() {
        let original =
            ProxyConfig::parse("user:pass@proxy.example.com:3128").expect("proxy should parse");
        let proxy = ProxyConfig::parse(&original.url()).expect("proxy URL should parse");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_proxy_trims_outer_whitespace() {
        let proxy = ProxyConfig::parse("  user:pass@proxy.example.com:3128\t")
            .expect("proxy should be trimmed");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_proxy_password_can_contain_at_sign() {
        let proxy = ProxyConfig::parse("user:pa@ss@proxy.example.com:3128")
            .expect("password with @ should parse using the final authority separator");
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pa@ss"));
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
    fn test_parse_proxy_rejects_zero_port() {
        let err = ProxyConfig::parse("proxy.local:0").expect_err("port zero should fail");
        assert!(err.to_string().contains("Port must be between"));
    }

    #[test]
    fn test_parse_proxy_rejects_empty_host_after_auth() {
        let err = ProxyConfig::parse("user:pass@").expect_err("empty proxy host should fail");
        assert!(err.to_string().contains("Proxy host cannot be empty"));
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
    fn test_build_connect_request_username_only_sends_empty_password() {
        let request = build_connect_request("example.com", 443, &Some("user".to_string()), &None);
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjo="));
    }

    #[test]
    fn test_parse_proxy_user_without_port_defaults() {
        let proxy = ProxyConfig::parse("user@proxy.local").expect("test assertion should succeed");
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert!(proxy.password.is_none());
    }

    #[test]
    fn test_parse_proxy_rejects_empty_username() {
        let err = ProxyConfig::parse("@proxy.local").expect_err("empty username should fail");
        assert!(err.to_string().contains("Proxy username cannot be empty"));

        let err = ProxyConfig::parse(":pass@proxy.local").expect_err("empty username should fail");
        assert!(err.to_string().contains("Proxy username cannot be empty"));
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

    #[tokio::test]
    async fn test_connect_via_proxy_rejects_malformed_status_code() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"HTTP/1.1 OK\r\n\r\n").await;
            }
        });

        let proxy = ProxyConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: None,
            password: None,
        };

        let err = connect_via_proxy(&proxy, "example.com", 443, Duration::from_secs(1))
            .await
            .expect_err("malformed proxy status code should fail");
        assert!(err.to_string().contains("invalid status code"));
    }

    #[tokio::test]
    async fn test_connect_via_proxy_rejects_oversized_status_line() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let line = vec![b'A'; 9000];
                let _ = socket.write_all(&line).await;
            }
        });

        let proxy = ProxyConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: None,
            password: None,
        };

        let err = connect_via_proxy(&proxy, "example.com", 443, Duration::from_secs(1))
            .await
            .expect_err("oversized proxy status line should fail");
        assert!(err.to_string().contains("too long"));
    }

    #[tokio::test]
    async fn test_read_proxy_line_rejects_unterminated_line() {
        let mut reader = BufReader::new(&b"HTTP/1.1 200 OK"[..]);
        let mut line = String::new();

        let err = read_proxy_line(&mut reader, &mut line)
            .await
            .expect_err("unterminated proxy line should fail");

        assert!(err.to_string().contains("ended before newline"));
    }

    #[tokio::test]
    async fn test_read_proxy_line_rejects_empty_eof() {
        let mut reader = BufReader::new(&b""[..]);
        let mut line = String::new();

        let err = read_proxy_line(&mut reader, &mut line)
            .await
            .expect_err("empty EOF should fail");

        assert!(matches!(err, TlsError::ConnectionClosed { .. }));
    }
}
