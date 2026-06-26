// STARTTLS Tester - Test STARTTLS support on various protocols

use super::protocols::{StarttlsNegotiator, StarttlsProtocol, StarttlsTestResult, get_negotiator};
use crate::Result;
use crate::utils::network::Target;
use std::sync::Arc;
use std::time::Duration;

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
        // Use the target's configured port if it differs from the default TLS port (443),
        // otherwise fall back to the protocol's default STARTTLS port
        let port = if self.target.port != 443 {
            self.target.port
        } else {
            protocol.default_port()
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

        // Build the negotiator via the canonical dispatcher so every protocol
        // with an implementation (SMTP, IMAP, POP3, FTP, XMPP, LDAP, IRC,
        // PostgreSQL, MySQL, NNTP, Sieve, LMTP, Telnet) is exercised.
        let negotiator: Arc<dyn StarttlsNegotiator> =
            Arc::from(get_negotiator(protocol, self.target.hostname.clone()));

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
        let addr = std::net::SocketAddr::new(self.target.primary_ip()?, port);
        let mut stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

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
    use std::net::IpAddr;

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

    #[test]
    fn test_tester_default_timeouts() {
        let target = Target::with_ips(
            "example.com".to_string(),
            110,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = StarttlsTester::new(target);
        assert!(tester.connect_timeout.as_secs() > 0);
    }

    #[tokio::test]
    async fn test_protocol_implicit_tls_returns_error() {
        let target = Target::with_ips(
            "example.com".to_string(),
            993,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = StarttlsTester::new(target);
        let result = tester.test_protocol(StarttlsProtocol::IMAPS).await;
        assert!(!result.starttls_supported);
        assert!(result.error.unwrap_or_default().contains("Implicit TLS"));
    }

    #[tokio::test]
    async fn test_protocol_ldap_is_dispatched_not_stubbed() {
        // LDAP has a real negotiator; test_protocol must dispatch it rather than
        // return the old "not yet implemented" stub. Against a closed local port
        // it fails to connect, but the error must NOT be the stub message.
        let target = Target::with_ips(
            "example.com".to_string(),
            389,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = StarttlsTester {
            target,
            connect_timeout: Duration::from_millis(50),
        };
        let result = tester.test_protocol(StarttlsProtocol::LDAP).await;
        assert!(!result.starttls_supported);
        assert!(
            !result
                .error
                .unwrap_or_default()
                .contains("not yet implemented")
        );
    }

    #[tokio::test]
    async fn test_protocol_irc_resolves_default_port() {
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            6667,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = StarttlsTester {
            target,
            connect_timeout: Duration::from_millis(50),
        };
        let result = tester.test_protocol(StarttlsProtocol::IRC).await;
        assert!(!result.starttls_supported);
        assert_eq!(result.port, StarttlsProtocol::IRC.default_port());
    }

    #[tokio::test]
    async fn test_protocol_implicit_tls_uses_default_port() {
        let target = Target::with_ips(
            "example.com".to_string(),
            465,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = StarttlsTester::new(target);
        let result = tester.test_protocol(StarttlsProtocol::SMTPS).await;
        assert!(!result.starttls_supported);
        assert_eq!(result.port, 465);
    }

    #[tokio::test]
    async fn test_protocol_connection_failure_sets_error() {
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            143,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = StarttlsTester {
            target,
            connect_timeout: Duration::from_millis(50),
        };

        let result = tester.test_protocol(StarttlsProtocol::IMAP).await;
        assert!(!result.starttls_supported);
        assert!(result.error.is_some());
    }
}
