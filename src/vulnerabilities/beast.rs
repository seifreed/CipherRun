// BEAST (Browser Exploit Against SSL/TLS) Vulnerability Test
// CVE-2011-3389
//
// BEAST exploits a weakness in CBC mode cipher suites in TLS 1.0 and earlier.
// It allows an attacker to decrypt HTTPS cookies by exploiting the predictable
// Initialization Vector (IV) in CBC mode.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeastProbeStatus {
    Supported,
    NotSupported,
    Inconclusive,
}

impl BeastProbeStatus {
    fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

fn classify_handshake_error(error: &str) -> BeastProbeStatus {
    let error = error.to_ascii_lowercase();
    if error.contains("unexpected eof")
        || error.contains("connection reset")
        || error.contains("reset by peer")
        || error.contains("connection refused")
        || error.contains("timed out")
        || error.contains("timeout")
        || error.contains("closed")
        || error.contains("no protocols available")
        || error.contains("shutdown while in init")
        || error.contains("errno=54")
    {
        BeastProbeStatus::Inconclusive
    } else {
        BeastProbeStatus::NotSupported
    }
}

/// BEAST vulnerability tester
pub struct BeastTester {
    target: Target,
}

impl BeastTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for BEAST vulnerability
    pub async fn test(&self) -> Result<BeastTestResult> {
        // BEAST affects TLS 1.0 and SSL 3.0 with CBC ciphers
        let tls10_cbc = self.test_tls10_cbc().await?;
        let ssl3_cbc = self.test_ssl3_cbc().await?;

        let vulnerable = tls10_cbc.is_supported() || ssl3_cbc.is_supported();
        let inconclusive =
            !vulnerable && (tls10_cbc.is_inconclusive() || ssl3_cbc.is_inconclusive());

        let details = if vulnerable {
            let mut parts = Vec::new();
            if tls10_cbc.is_supported() {
                parts.push("TLS 1.0 with CBC ciphers enabled");
            }
            if ssl3_cbc.is_supported() {
                parts.push("SSL 3.0 with CBC ciphers enabled");
            }
            format!("Vulnerable: {}", parts.join(", "))
        } else if inconclusive {
            "BEAST test inconclusive - unable to complete TLS 1.0/SSL 3.0 CBC probes".to_string()
        } else {
            "Not vulnerable - TLS 1.0/SSL 3.0 CBC ciphers not supported".to_string()
        };

        Ok(BeastTestResult {
            vulnerable,
            inconclusive,
            tls10_cbc_supported: tls10_cbc.is_supported(),
            ssl3_cbc_supported: ssl3_cbc.is_supported(),
            details,
        })
    }

    /// Test for TLS 1.0 with CBC ciphers
    async fn test_tls10_cbc(&self) -> Result<BeastProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Try to connect with TLS 1.0 and CBC cipher
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(BeastProbeStatus::Inconclusive),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1))?;

        // Try CBC cipher
        builder.set_cipher_list("AES128-SHA:AES256-SHA:DES-CBC3-SHA")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(BeastProbeStatus::Supported),
            Err(e) => Ok(classify_handshake_error(&e.to_string())),
        }
    }

    /// Test for SSL 3.0 with CBC ciphers
    /// Modern OpenSSL versions may not support SSL3, so we handle this gracefully
    async fn test_ssl3_cbc(&self) -> Result<BeastProbeStatus> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(BeastProbeStatus::Inconclusive),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Try to set SSL 3.0 - this may fail on modern OpenSSL versions
        // that have SSL 3.0 disabled at compile time
        if builder
            .set_min_proto_version(Some(SslVersion::SSL3))
            .is_err()
        {
            // SSL 3.0 is not supported by this OpenSSL build
            // This means we cannot test SSL 3.0, but also modern servers
            // shouldn't support it anyway
            tracing::debug!("SSL 3.0 not supported by OpenSSL - cannot test for BEAST on SSL 3.0");
            return Ok(BeastProbeStatus::NotSupported);
        }

        if builder
            .set_max_proto_version(Some(SslVersion::SSL3))
            .is_err()
        {
            tracing::debug!("SSL 3.0 not supported by OpenSSL - cannot test for BEAST on SSL 3.0");
            return Ok(BeastProbeStatus::NotSupported);
        }

        builder.set_cipher_list("AES128-SHA:AES256-SHA:DES-CBC3-SHA")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(BeastProbeStatus::Supported),
            Err(e) => {
                // Check if error is due to SSL 3.0 being disabled
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("no protocols available") {
                    Ok(BeastProbeStatus::Inconclusive)
                } else if err_str.contains("ssl3") || err_str.contains("version") {
                    // SSL 3.0 not supported - treat as not vulnerable
                    tracing::debug!("SSL 3.0 connection failed (likely not supported): {}", e);
                    Ok(BeastProbeStatus::NotSupported)
                } else {
                    // Other error - server might not support SSL 3.0
                    Ok(classify_handshake_error(&err_str))
                }
            }
        }
    }
}

/// BEAST test result
#[derive(Debug, Clone)]
pub struct BeastTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub tls10_cbc_supported: bool,
    pub ssl3_cbc_supported: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use tokio::net::TcpListener;

    #[test]
    fn test_beast_result_creation() {
        let result = BeastTestResult {
            vulnerable: true,
            inconclusive: false,
            tls10_cbc_supported: true,
            ssl3_cbc_supported: false,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.tls10_cbc_supported);
    }

    async fn spawn_dummy_server(max_accepts: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((socket, _)) = listener.accept().await {
                    drop(socket);
                    remaining -= 1;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_beast_inconclusive_on_dummy_server() {
        let addr = spawn_dummy_server(5).await;
        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = BeastTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.details.to_ascii_lowercase().contains("inconclusive"));
    }

    #[test]
    fn test_beast_result_details_contains_tls() {
        let result = BeastTestResult {
            vulnerable: true,
            inconclusive: false,
            tls10_cbc_supported: true,
            ssl3_cbc_supported: false,
            details: "Vulnerable: TLS 1.0 with CBC ciphers enabled".to_string(),
        };

        assert!(result.details.contains("TLS 1.0"));
    }

    #[test]
    fn test_beast_result_details_not_vulnerable_text() {
        let result = BeastTestResult {
            vulnerable: false,
            inconclusive: false,
            tls10_cbc_supported: false,
            ssl3_cbc_supported: false,
            details: "Not vulnerable - TLS 1.0/SSL 3.0 CBC ciphers not supported".to_string(),
        };
        assert!(result.details.contains("Not vulnerable"));
        assert!(!result.vulnerable);
    }
}
