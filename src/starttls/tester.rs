// STARTTLS Tester - Test STARTTLS support on various protocols

use super::ftp::FtpNegotiator;
use super::imap::ImapNegotiator;
use super::pop3::Pop3Negotiator;
use super::protocols::{StarttlsNegotiator, StarttlsProtocol, StarttlsTestResult};
use super::smtp::SmtpNegotiator;
use super::xmpp::XmppNegotiator;
use crate::Result;
use crate::utils::network::Target;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// STARTTLS tester
pub struct StarttlsTester {
    target: Target,
    connect_timeout: Duration,
}

impl StarttlsTester {
    /// Create new STARTTLS tester
    pub fn new(target: Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Test STARTTLS for a specific protocol
    pub async fn test_protocol(&self, protocol: StarttlsProtocol) -> StarttlsTestResult {
        let port = protocol.default_port();

        // Create negotiator for the protocol
        let negotiator: Arc<dyn StarttlsNegotiator> = match protocol {
            StarttlsProtocol::SMTP | StarttlsProtocol::SMTPS => {
                Arc::new(SmtpNegotiator::new(self.target.hostname.clone()))
            }
            StarttlsProtocol::IMAP | StarttlsProtocol::IMAPS => Arc::new(ImapNegotiator::new()),
            StarttlsProtocol::POP3 | StarttlsProtocol::POP3S => Arc::new(Pop3Negotiator::new()),
            StarttlsProtocol::FTP | StarttlsProtocol::FTPS => Arc::new(FtpNegotiator::new()),
            StarttlsProtocol::XMPP | StarttlsProtocol::XMPPS => {
                Arc::new(XmppNegotiator::new(self.target.hostname.clone()))
            }
            _ => {
                // Protocols not yet implemented
                return StarttlsTestResult {
                    protocol,
                    port,
                    starttls_supported: false,
                    error: Some("Protocol not yet implemented".to_string()),
                };
            }
        };

        // For implicit TLS protocols (SMTPS, IMAPS, etc.), we don't test STARTTLS
        if protocol.is_implicit_tls() {
            return StarttlsTestResult {
                protocol,
                port,
                starttls_supported: false,
                error: Some("Implicit TLS protocol (no STARTTLS negotiation)".to_string()),
            };
        }

        // Test STARTTLS
        match self.test_starttls_with_negotiator(port, negotiator).await {
            Ok(_) => StarttlsTestResult {
                protocol,
                port,
                starttls_supported: true,
                error: None,
            },
            Err(e) => StarttlsTestResult {
                protocol,
                port,
                starttls_supported: false,
                error: Some(e.to_string()),
            },
        }
    }

    /// Test STARTTLS with a specific negotiator
    async fn test_starttls_with_negotiator(
        &self,
        port: u16,
        negotiator: Arc<dyn StarttlsNegotiator>,
    ) -> Result<()> {
        // Connect to target
        let addr = format!("{}:{}", self.target.hostname, port);
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(&addr)).await??;

        // Negotiate STARTTLS
        negotiator.negotiate_starttls(&mut stream).await?;

        Ok(())
    }

    /// Test common STARTTLS protocols
    pub async fn test_common_protocols(&self) -> Vec<StarttlsTestResult> {
        let protocols = vec![
            StarttlsProtocol::SMTP,
            StarttlsProtocol::IMAP,
            StarttlsProtocol::POP3,
            StarttlsProtocol::FTP,
            StarttlsProtocol::XMPP,
        ];

        let mut results = Vec::new();
        for protocol in protocols {
            results.push(self.test_protocol(protocol).await);
        }

        results
    }

    /// Test all supported STARTTLS protocols
    pub async fn test_all_protocols(&self) -> Vec<StarttlsTestResult> {
        let protocols = vec![
            StarttlsProtocol::SMTP,
            StarttlsProtocol::IMAP,
            StarttlsProtocol::POP3,
            StarttlsProtocol::FTP,
            StarttlsProtocol::XMPP,
            StarttlsProtocol::LDAP,
            StarttlsProtocol::IRC,
            StarttlsProtocol::POSTGRES,
            StarttlsProtocol::MYSQL,
            StarttlsProtocol::NNTP,
            StarttlsProtocol::SIEVE,
        ];

        let mut results = Vec::new();
        for protocol in protocols {
            results.push(self.test_protocol(protocol).await);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tester_creation() {
        let target = Target::with_ips(
            "example.com".to_string(),
            25,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = StarttlsTester::new(target);
        assert_eq!(tester.connect_timeout, Duration::from_secs(10));
    }
}
