// Automatic Protocol Detection
// Detects HTTP, SMTP, IMAP, POP3, FTP, XMPP, LDAP, etc. automatically

mod heuristics;
mod model;

pub use model::{ApplicationProtocol, DetectedProtocol};

use crate::Result;
use heuristics::{analyze_banner, extract_version, protocol_from_port, requires_starttls};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Protocol detector
pub struct ProtocolDetector;

const MAX_HTTP_STATUS_LINE_LEN: usize = 8192;

#[cfg(test)]
fn protocol_read_timeout() -> Duration {
    Duration::from_millis(50)
}

#[cfg(not(test))]
fn protocol_read_timeout() -> Duration {
    Duration::from_secs(3)
}

impl ProtocolDetector {
    /// Detect protocol automatically
    pub async fn detect(host: &str, port: u16) -> Result<DetectedProtocol> {
        let port_hint = protocol_from_port(port);
        let detected = Self::detect_by_banner(host, port).await?;

        let protocol = if detected.protocol != ApplicationProtocol::Unknown {
            detected.protocol
        } else {
            port_hint
        };

        Ok(DetectedProtocol {
            protocol,
            version: detected.version,
            banner: detected.banner,
            requires_starttls: requires_starttls(protocol),
            confidence: detected.confidence,
        })
    }

    /// Detect protocol by connecting and reading banner
    async fn detect_by_banner(host: &str, port: u16) -> Result<DetectedProtocol> {
        let connect_timeout = Duration::from_secs(5);
        let read_timeout = protocol_read_timeout();

        let mut stream = timeout(connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| crate::TlsError::Other("Connection timeout".to_string()))??;

        let mut banner = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match timeout(read_timeout, stream.read(&mut chunk)).await {
                Ok(Ok(0)) if (port == 80 || port == 443 || port == 8080) && banner.is_empty() => {
                    return Self::detect_http(&mut stream).await;
                }
                Ok(Ok(0)) if banner.is_empty() => {
                    return Ok(DetectedProtocol {
                        protocol: ApplicationProtocol::Unknown,
                        version: None,
                        banner: None,
                        requires_starttls: false,
                        confidence: 0.0,
                    });
                }
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    banner.extend_from_slice(&chunk[..n]);
                    let (protocol, _) = analyze_banner(&banner);
                    if matches!(
                        protocol,
                        ApplicationProtocol::Mysql | ApplicationProtocol::MongoDB
                    ) || banner.contains(&b'\n')
                        || banner.len() >= 1024
                    {
                        break;
                    }
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) if !banner.is_empty() => break,
                Err(_) if port == 80 || port == 443 || port == 8080 => {
                    return Self::detect_http(&mut stream).await;
                }
                Err(_) => {
                    return Err(crate::TlsError::Timeout {
                        duration: Some(read_timeout),
                    });
                }
            }
        }

        let banner_bytes = banner.as_slice();
        let (protocol, confidence) = analyze_banner(banner_bytes);

        if protocol == ApplicationProtocol::Unknown && (port == 80 || port == 443 || port == 8080) {
            return Self::detect_http(&mut stream).await;
        }

        Ok(DetectedProtocol {
            protocol,
            version: extract_version(banner_bytes, protocol)?,
            banner: if !banner_bytes.is_empty() {
                Some(String::from_utf8_lossy(banner_bytes).to_string())
            } else {
                None
            },
            requires_starttls: requires_starttls(protocol),
            confidence,
        })
    }

    /// Detect HTTP specifically
    async fn detect_http(stream: &mut TcpStream) -> Result<DetectedProtocol> {
        let request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        stream.write_all(request).await?;

        let read_timeout = protocol_read_timeout();
        let mut reader = BufReader::new(stream);
        let mut response_str = String::new();
        timeout(read_timeout, Self::read_http_status_line(&mut reader, &mut response_str))
            .await
            .map_err(|_| crate::TlsError::Timeout {
                duration: Some(read_timeout),
            })??;

        if response_str.starts_with("HTTP/") {
            let version = response_str
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .map(|value| value.to_string());

            Ok(DetectedProtocol {
                protocol: ApplicationProtocol::Http,
                version,
                banner: Some(response_str),
                requires_starttls: false,
                confidence: 0.99,
            })
        } else {
            Ok(DetectedProtocol {
                protocol: ApplicationProtocol::Unknown,
                version: None,
                banner: None,
                requires_starttls: false,
                confidence: 0.0,
            })
        }
    }

    async fn read_http_status_line<R>(reader: &mut R, line: &mut String) -> Result<usize>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut bytes = Vec::new();

        loop {
            let (consume, done) = {
                let available = reader.fill_buf().await?;
                if available.is_empty() {
                    break;
                }

                let newline = available.iter().position(|&byte| byte == b'\n');
                let consume = newline.map_or(available.len(), |index| index + 1);
                if bytes.len().saturating_add(consume) > MAX_HTTP_STATUS_LINE_LEN {
                    return Err(crate::TlsError::UnexpectedResponse {
                        details: "HTTP status line too long".to_string(),
                    });
                }

                bytes.extend_from_slice(&available[..consume]);
                (consume, newline.is_some())
            };

            reader.consume(consume);
            if done {
                break;
            }
        }

        let text = String::from_utf8(bytes).map_err(|error| crate::TlsError::ParseError {
            message: format!("HTTP status line is not valid UTF-8: {error}"),
        })?;
        let len = text.len();
        line.push_str(&text);
        Ok(len)
    }

    /// Get STARTTLS command for protocol
    pub fn starttls_command(protocol: ApplicationProtocol) -> Option<&'static str> {
        match protocol {
            ApplicationProtocol::SmtpStartTls => Some("STARTTLS\r\n"),
            ApplicationProtocol::ImapStartTls => Some(". STARTTLS\r\n"),
            ApplicationProtocol::Pop3StartTls => Some("STLS\r\n"),
            ApplicationProtocol::FtpStartTls => Some("AUTH TLS\r\n"),
            ApplicationProtocol::XmppStartTls => {
                Some("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            }
            ApplicationProtocol::LdapStartTls => None,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::auto_detection::heuristics::{
        analyze_banner, protocol_from_port, requires_starttls,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_protocol_from_port() {
        assert_eq!(protocol_from_port(443), ApplicationProtocol::Https);
        assert_eq!(protocol_from_port(25), ApplicationProtocol::SmtpStartTls);
        assert_eq!(protocol_from_port(143), ApplicationProtocol::ImapStartTls);
        assert_eq!(protocol_from_port(110), ApplicationProtocol::Pop3StartTls);
    }

    #[test]
    fn test_analyze_smtp_banner() {
        let banner = "220 mail.example.com ESMTP Postfix";
        let (protocol, confidence) = analyze_banner(banner.as_bytes());
        assert_eq!(protocol, ApplicationProtocol::SmtpStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_pop3_banner() {
        let banner = "+OK POP3 server ready";
        let (protocol, confidence) = analyze_banner(banner.as_bytes());
        assert_eq!(protocol, ApplicationProtocol::Pop3StartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_pop3_banner_without_pop_keyword() {
        let banner = "+OK Dovecot ready";
        let (protocol, confidence) = analyze_banner(banner.as_bytes());
        assert_eq!(protocol, ApplicationProtocol::Pop3StartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_imap_banner() {
        let banner = "* OK IMAP4rev1 Server ready";
        let (protocol, confidence) = analyze_banner(banner.as_bytes());
        assert_eq!(protocol, ApplicationProtocol::ImapStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_banner_unknown() {
        let banner = "Welcome to custom service";
        let (protocol, confidence) = analyze_banner(banner.as_bytes());
        assert_eq!(protocol, ApplicationProtocol::Unknown);
        assert!(confidence < 0.5);
    }

    #[test]
    fn test_requires_starttls() {
        assert!(requires_starttls(ApplicationProtocol::SmtpStartTls));
        assert!(requires_starttls(ApplicationProtocol::ImapStartTls));
        assert!(!requires_starttls(ApplicationProtocol::Https));
    }

    #[test]
    fn test_starttls_command() {
        assert_eq!(
            ProtocolDetector::starttls_command(ApplicationProtocol::SmtpStartTls),
            Some("STARTTLS\r\n")
        );
        assert_eq!(
            ProtocolDetector::starttls_command(ApplicationProtocol::ImapStartTls),
            Some(". STARTTLS\r\n")
        );
        assert_eq!(
            ProtocolDetector::starttls_command(ApplicationProtocol::Pop3StartTls),
            Some("STLS\r\n")
        );
    }

    async fn spawn_banner_server(banner: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(banner).await;
            }
        });

        port
    }

    async fn spawn_http_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        port
    }

    async fn spawn_stalling_server(read_request: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                if read_request {
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        port
    }

    async fn spawn_mysql_banner_without_newline() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let banner = b"\x09\x00\x00\x00\x0a8.0.31\x00";
                let _ = stream.write_all(banner).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        port
    }

    #[tokio::test]
    async fn test_detect_by_banner_smtp() {
        let port = spawn_banner_server(b"220 mail.example.com ESMTP Postfix\r\n").await;
        let detected = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::SmtpStartTls);
        assert!(detected.banner.is_some());
    }

    #[tokio::test]
    async fn test_detect_by_banner_rejects_invalid_utf8_version() {
        let port = spawn_banner_server(b"220 mail.example.com ESMTP Postfix\xff\r\n").await;
        let err = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .expect_err("invalid banner UTF-8 should fail");

        assert!(err.to_string().contains("Invalid protocol banner UTF-8"));
    }

    #[tokio::test]
    async fn test_detect_http_response() {
        let port = spawn_http_server().await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let detected = ProtocolDetector::detect_http(&mut stream)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::Http);
        assert!(
            detected
                .version
                .as_deref()
                .unwrap_or("")
                .starts_with("HTTP/")
        );
    }

    #[tokio::test]
    async fn test_detect_http_fragmented_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                stream.write_all(b"HTTP/1.1 200").await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                stream
                    .write_all(b" OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let detected = ProtocolDetector::detect_http(&mut stream)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::Http);
        assert!(
            detected
                .version
                .as_deref()
                .unwrap_or("")
                .starts_with("HTTP/")
        );
    }

    #[tokio::test]
    async fn test_detect_http_rejects_oversized_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                let line = vec![b'A'; MAX_HTTP_STATUS_LINE_LEN + 1];
                let _ = stream.write_all(&line).await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let err = ProtocolDetector::detect_http(&mut stream)
            .await
            .expect_err("oversized status line should fail");

        assert!(err.to_string().contains("HTTP status line too long"));
    }

    #[tokio::test]
    async fn test_detect_by_banner_fragmented_smtp_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                stream.write_all(b"220 mail.example.com").await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                stream.write_all(b" ESMTP Postfix\r\n").await.unwrap();
            }
        });

        let detected = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::SmtpStartTls);
        assert!(detected.banner.as_deref().unwrap_or("").contains("Postfix"));
    }

    #[tokio::test]
    async fn test_detect_by_banner_uses_partial_banner_on_timeout() {
        let port = spawn_mysql_banner_without_newline().await;

        let detected = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .expect("partial banner should be analyzed after read timeout");

        assert_eq!(detected.protocol, ApplicationProtocol::Mysql);
        assert!(detected.banner.is_some());
    }

    #[tokio::test]
    async fn test_detect_by_banner_http_port_without_banner_falls_back_to_http() {
        let listener = TcpListener::bind(("127.0.0.1", 8080)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });

        let detected = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::Http);
        assert!(
            detected
                .version
                .as_deref()
                .unwrap_or("")
                .starts_with("HTTP/")
        );
    }

    #[tokio::test]
    async fn test_detect_by_banner_read_timeout_is_error() {
        let port = spawn_stalling_server(false).await;

        let err = ProtocolDetector::detect_by_banner("127.0.0.1", port)
            .await
            .unwrap_err();

        assert!(matches!(err, crate::TlsError::Timeout { .. }));
    }

    #[tokio::test]
    async fn test_detect_http_read_timeout_is_error() {
        let port = spawn_stalling_server(true).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let err = ProtocolDetector::detect_http(&mut stream)
            .await
            .unwrap_err();

        assert!(matches!(err, crate::TlsError::Timeout { .. }));
    }

    #[test]
    fn test_application_protocol_name_unknown() {
        assert_eq!(ApplicationProtocol::Unknown.name(), "Unknown");
        assert_eq!(ApplicationProtocol::SmtpStartTls.name(), "SMTP+STARTTLS");
    }
}
