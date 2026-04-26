// Automatic Protocol Detection
// Detects HTTP, SMTP, IMAP, POP3, FTP, XMPP, LDAP, etc. automatically

mod heuristics;
mod model;

pub use model::{ApplicationProtocol, DetectedProtocol};

use crate::Result;
use heuristics::{analyze_banner, extract_version, protocol_from_port, requires_starttls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Protocol detector
pub struct ProtocolDetector;

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

        let mut banner = vec![0u8; 1024];
        let n = timeout(read_timeout, stream.read(&mut banner))
            .await
            .map_err(|_| crate::TlsError::Timeout {
                duration: read_timeout,
            })??;

        let banner_str = String::from_utf8_lossy(&banner[..n]).to_string();
        let (protocol, confidence) = analyze_banner(&banner_str);

        if protocol == ApplicationProtocol::Unknown && (port == 80 || port == 443 || port == 8080) {
            return Self::detect_http(&mut stream).await;
        }

        Ok(DetectedProtocol {
            protocol,
            version: extract_version(&banner_str, protocol),
            banner: if !banner_str.is_empty() {
                Some(banner_str)
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

        let mut response = vec![0u8; 1024];
        let read_timeout = protocol_read_timeout();
        let n = timeout(read_timeout, stream.read(&mut response))
            .await
            .map_err(|_| crate::TlsError::Timeout {
                duration: read_timeout,
            })??;

        let response_str = String::from_utf8_lossy(&response[..n]).to_string();

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
        let (protocol, confidence) = analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::SmtpStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_pop3_banner() {
        let banner = "+OK POP3 server ready";
        let (protocol, confidence) = analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::Pop3StartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_imap_banner() {
        let banner = "* OK IMAP4rev1 Server ready";
        let (protocol, confidence) = analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::ImapStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_banner_unknown() {
        let banner = "Welcome to custom service";
        let (protocol, confidence) = analyze_banner(banner);
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

    #[tokio::test]
    async fn test_detect_by_banner_smtp() {
        let port = spawn_banner_server(b"220 mail.example.com ESMTP Postfix\r\n").await;
        let detected = ProtocolDetector::detect("127.0.0.1", port)
            .await
            .expect("test assertion should succeed");

        assert_eq!(detected.protocol, ApplicationProtocol::SmtpStartTls);
        assert!(detected.banner.is_some());
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
