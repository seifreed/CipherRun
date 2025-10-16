// Automatic Protocol Detection
// Detects HTTP, SMTP, IMAP, POP3, FTP, XMPP, LDAP, etc. automatically

use crate::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Detected protocol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedProtocol {
    pub protocol: ApplicationProtocol,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub requires_starttls: bool,
    pub confidence: f64, // 0.0 - 1.0
}

/// Application layer protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicationProtocol {
    Http,
    Https,
    Smtp,
    SmtpStartTls,
    Imap,
    ImapStartTls,
    Pop3,
    Pop3StartTls,
    Ftp,
    FtpStartTls,
    Xmpp,
    XmppStartTls,
    Ldap,
    LdapStartTls,
    Mysql,
    Postgres,
    Redis,
    MongoDB,
    Unknown,
}

impl ApplicationProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            ApplicationProtocol::Http => "HTTP",
            ApplicationProtocol::Https => "HTTPS",
            ApplicationProtocol::Smtp => "SMTP",
            ApplicationProtocol::SmtpStartTls => "SMTP+STARTTLS",
            ApplicationProtocol::Imap => "IMAP",
            ApplicationProtocol::ImapStartTls => "IMAP+STARTTLS",
            ApplicationProtocol::Pop3 => "POP3",
            ApplicationProtocol::Pop3StartTls => "POP3+STARTTLS",
            ApplicationProtocol::Ftp => "FTP",
            ApplicationProtocol::FtpStartTls => "FTP+STARTTLS",
            ApplicationProtocol::Xmpp => "XMPP",
            ApplicationProtocol::XmppStartTls => "XMPP+STARTTLS",
            ApplicationProtocol::Ldap => "LDAP",
            ApplicationProtocol::LdapStartTls => "LDAP+STARTTLS",
            ApplicationProtocol::Mysql => "MySQL",
            ApplicationProtocol::Postgres => "PostgreSQL",
            ApplicationProtocol::Redis => "Redis",
            ApplicationProtocol::MongoDB => "MongoDB",
            ApplicationProtocol::Unknown => "Unknown",
        }
    }

    pub fn default_port(&self) -> Option<u16> {
        match self {
            ApplicationProtocol::Http => Some(80),
            ApplicationProtocol::Https => Some(443),
            ApplicationProtocol::Smtp | ApplicationProtocol::SmtpStartTls => Some(25),
            ApplicationProtocol::Imap | ApplicationProtocol::ImapStartTls => Some(143),
            ApplicationProtocol::Pop3 | ApplicationProtocol::Pop3StartTls => Some(110),
            ApplicationProtocol::Ftp | ApplicationProtocol::FtpStartTls => Some(21),
            ApplicationProtocol::Xmpp | ApplicationProtocol::XmppStartTls => Some(5222),
            ApplicationProtocol::Ldap | ApplicationProtocol::LdapStartTls => Some(389),
            ApplicationProtocol::Mysql => Some(3306),
            ApplicationProtocol::Postgres => Some(5432),
            ApplicationProtocol::Redis => Some(6379),
            ApplicationProtocol::MongoDB => Some(27017),
            ApplicationProtocol::Unknown => None,
        }
    }
}

/// Protocol detector
pub struct ProtocolDetector;

impl ProtocolDetector {
    /// Detect protocol automatically
    pub async fn detect(host: &str, port: u16) -> Result<DetectedProtocol> {
        // First, try to infer from port
        let port_hint = Self::protocol_from_port(port);

        // Then, try to detect by connecting and reading banner
        let detected = Self::detect_by_banner(host, port).await?;

        // Combine port hint with banner detection
        let protocol = if detected.protocol != ApplicationProtocol::Unknown {
            detected.protocol
        } else {
            port_hint
        };

        Ok(DetectedProtocol {
            protocol,
            version: detected.version,
            banner: detected.banner,
            requires_starttls: Self::requires_starttls(protocol),
            confidence: detected.confidence,
        })
    }

    /// Infer protocol from port number
    fn protocol_from_port(port: u16) -> ApplicationProtocol {
        match port {
            21 => ApplicationProtocol::Ftp,
            22 => ApplicationProtocol::Unknown, // SSH
            25 | 587 => ApplicationProtocol::SmtpStartTls,
            80 | 8080 | 8000 => ApplicationProtocol::Http,
            110 => ApplicationProtocol::Pop3StartTls,
            143 => ApplicationProtocol::ImapStartTls,
            389 => ApplicationProtocol::LdapStartTls,
            443 | 8443 => ApplicationProtocol::Https,
            465 => ApplicationProtocol::Smtp, // SMTPS
            993 => ApplicationProtocol::Imap, // IMAPS
            995 => ApplicationProtocol::Pop3, // POP3S
            3306 => ApplicationProtocol::Mysql,
            5222 => ApplicationProtocol::XmppStartTls,
            5269 => ApplicationProtocol::Xmpp, // XMPP server-to-server
            5432 => ApplicationProtocol::Postgres,
            6379 => ApplicationProtocol::Redis,
            27017 => ApplicationProtocol::MongoDB,
            _ => ApplicationProtocol::Unknown,
        }
    }

    /// Detect protocol by connecting and reading banner
    async fn detect_by_banner(host: &str, port: u16) -> Result<DetectedProtocol> {
        let connect_timeout = Duration::from_secs(5);
        let read_timeout = Duration::from_secs(3);

        let mut stream = timeout(connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        // Read initial banner
        let mut banner = vec![0u8; 1024];
        let n = timeout(read_timeout, stream.read(&mut banner))
            .await
            .unwrap_or(Ok(0))?;

        let banner_str = String::from_utf8_lossy(&banner[..n]).to_string();

        // Try to detect protocol from banner
        let (protocol, confidence) = Self::analyze_banner(&banner_str);

        // For HTTP, we need to send a request first
        if protocol == ApplicationProtocol::Unknown && (port == 80 || port == 443 || port == 8080) {
            return Self::detect_http(&mut stream).await;
        }

        Ok(DetectedProtocol {
            protocol,
            version: Self::extract_version(&banner_str, protocol),
            banner: if !banner_str.is_empty() {
                Some(banner_str)
            } else {
                None
            },
            requires_starttls: Self::requires_starttls(protocol),
            confidence,
        })
    }

    /// Analyze banner to detect protocol
    fn analyze_banner(banner: &str) -> (ApplicationProtocol, f64) {
        let lower = banner.to_lowercase();

        // SMTP detection
        if lower.starts_with("220")
            && (lower.contains("smtp") || lower.contains("mail") || lower.contains("esmtp"))
        {
            return (ApplicationProtocol::SmtpStartTls, 0.95);
        }

        // POP3 detection
        if lower.starts_with("+ok") && lower.contains("pop") {
            return (ApplicationProtocol::Pop3StartTls, 0.95);
        }

        // IMAP detection
        if lower.contains("* ok") && lower.contains("imap") {
            return (ApplicationProtocol::ImapStartTls, 0.95);
        }

        // FTP detection
        if lower.starts_with("220")
            && (lower.contains("ftp") || lower.contains("filezilla") || lower.contains("proftpd"))
        {
            return (ApplicationProtocol::FtpStartTls, 0.90);
        }

        // XMPP detection
        if lower.contains("<stream:stream") || lower.contains("<?xml") && lower.contains("jabber") {
            return (ApplicationProtocol::XmppStartTls, 0.90);
        }

        // MySQL detection
        if banner.len() > 10 && banner.as_bytes()[4] == 0x0a {
            // MySQL protocol version byte
            return (ApplicationProtocol::Mysql, 0.85);
        }

        // PostgreSQL detection
        if lower.contains("postgresql") {
            return (ApplicationProtocol::Postgres, 0.90);
        }

        // Redis detection
        if lower.starts_with("-err") || lower.starts_with("+pong") {
            return (ApplicationProtocol::Redis, 0.85);
        }

        // MongoDB detection
        if banner.len() > 16 && banner.as_bytes()[0..4] == [0x3a, 0x00, 0x00, 0x00] {
            return (ApplicationProtocol::MongoDB, 0.80);
        }

        (ApplicationProtocol::Unknown, 0.0)
    }

    /// Detect HTTP specifically
    async fn detect_http(stream: &mut TcpStream) -> Result<DetectedProtocol> {
        // Send HTTP request
        let request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        stream.write_all(request).await?;

        // Read response
        let mut response = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut response))
            .await
            .unwrap_or(Ok(0))?;

        let response_str = String::from_utf8_lossy(&response[..n]).to_string();

        if response_str.starts_with("HTTP/") {
            let version = response_str
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .map(|v| v.to_string());

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

    /// Extract version from banner
    fn extract_version(banner: &str, protocol: ApplicationProtocol) -> Option<String> {
        match protocol {
            ApplicationProtocol::Smtp | ApplicationProtocol::SmtpStartTls => {
                // Extract SMTP version (e.g., "220 mail.example.com ESMTP Postfix")
                banner.lines().next().map(|s| s.to_string())
            }
            ApplicationProtocol::Imap | ApplicationProtocol::ImapStartTls => {
                // Extract IMAP version
                banner.lines().next().map(|s| s.to_string())
            }
            ApplicationProtocol::Pop3 | ApplicationProtocol::Pop3StartTls => {
                // Extract POP3 version
                banner.lines().next().map(|s| s.to_string())
            }
            ApplicationProtocol::Ftp | ApplicationProtocol::FtpStartTls => {
                // Extract FTP version
                banner.lines().next().map(|s| s.to_string())
            }
            _ => None,
        }
    }

    /// Check if protocol requires STARTTLS
    fn requires_starttls(protocol: ApplicationProtocol) -> bool {
        matches!(
            protocol,
            ApplicationProtocol::SmtpStartTls
                | ApplicationProtocol::ImapStartTls
                | ApplicationProtocol::Pop3StartTls
                | ApplicationProtocol::FtpStartTls
                | ApplicationProtocol::XmppStartTls
                | ApplicationProtocol::LdapStartTls
        )
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
            ApplicationProtocol::LdapStartTls => None, // LDAP uses extended operation
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_port() {
        assert_eq!(
            ProtocolDetector::protocol_from_port(443),
            ApplicationProtocol::Https
        );
        assert_eq!(
            ProtocolDetector::protocol_from_port(25),
            ApplicationProtocol::SmtpStartTls
        );
        assert_eq!(
            ProtocolDetector::protocol_from_port(143),
            ApplicationProtocol::ImapStartTls
        );
        assert_eq!(
            ProtocolDetector::protocol_from_port(110),
            ApplicationProtocol::Pop3StartTls
        );
    }

    #[test]
    fn test_analyze_smtp_banner() {
        let banner = "220 mail.example.com ESMTP Postfix";
        let (protocol, confidence) = ProtocolDetector::analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::SmtpStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_pop3_banner() {
        let banner = "+OK POP3 server ready";
        let (protocol, confidence) = ProtocolDetector::analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::Pop3StartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_analyze_imap_banner() {
        let banner = "* OK IMAP4rev1 Server ready";
        let (protocol, confidence) = ProtocolDetector::analyze_banner(banner);
        assert_eq!(protocol, ApplicationProtocol::ImapStartTls);
        assert!(confidence > 0.9);
    }

    #[test]
    fn test_requires_starttls() {
        assert!(ProtocolDetector::requires_starttls(
            ApplicationProtocol::SmtpStartTls
        ));
        assert!(ProtocolDetector::requires_starttls(
            ApplicationProtocol::ImapStartTls
        ));
        assert!(!ProtocolDetector::requires_starttls(
            ApplicationProtocol::Https
        ));
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
}
