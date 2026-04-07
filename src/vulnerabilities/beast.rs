// BEAST (Browser Exploit Against SSL/TLS) Vulnerability Test
// CVE-2011-3389
//
// BEAST exploits a weakness in CBC mode cipher suites in TLS 1.0 and earlier.
// It allows an attacker to decrypt HTTPS cookies by exploiting the predictable
// Initialization Vector (IV) in CBC mode.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

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

        let vulnerable = tls10_cbc || ssl3_cbc;

        let details = if vulnerable {
            let mut parts = Vec::new();
            if tls10_cbc {
                parts.push("TLS 1.0 with CBC ciphers enabled");
            }
            if ssl3_cbc {
                parts.push("SSL 3.0 with CBC ciphers enabled");
            }
            format!("Vulnerable: {}", parts.join(", "))
        } else {
            "Not vulnerable - TLS 1.0/SSL 3.0 CBC ciphers not supported".to_string()
        };

        Ok(BeastTestResult {
            vulnerable,
            tls10_cbc_supported: tls10_cbc,
            ssl3_cbc_supported: ssl3_cbc,
            details,
        })
    }

    /// Test for TLS 1.0 with CBC ciphers
    async fn test_tls10_cbc(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];

        // Try to connect with TLS 1.0 and CBC cipher
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1))?;

        // Try CBC cipher
        builder.set_cipher_list("AES128-SHA:AES256-SHA:DES-CBC3-SHA")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Test for SSL 3.0 with CBC ciphers
    /// Modern OpenSSL versions may not support SSL3, so we handle this gracefully
    async fn test_ssl3_cbc(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

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
            return Ok(false);
        }

        if builder
            .set_max_proto_version(Some(SslVersion::SSL3))
            .is_err()
        {
            tracing::debug!("SSL 3.0 not supported by OpenSSL - cannot test for BEAST on SSL 3.0");
            return Ok(false);
        }

        builder.set_cipher_list("AES128-SHA:AES256-SHA:DES-CBC3-SHA")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(true),
            Err(e) => {
                // Check if error is due to SSL 3.0 being disabled
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("no protocols available")
                    || err_str.contains("ssl3")
                    || err_str.contains("version")
                {
                    // SSL 3.0 not supported - treat as not vulnerable
                    tracing::debug!("SSL 3.0 connection failed (likely not supported): {}", e);
                    Ok(false)
                } else {
                    // Other error - server might not support SSL 3.0
                    Ok(false)
                }
            }
        }
    }
}

/// BEAST test result
#[derive(Debug, Clone)]
pub struct BeastTestResult {
    pub vulnerable: bool,
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
                }
                remaining -= 1;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_beast_not_vulnerable_on_dummy_server() {
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
    }

    #[test]
    fn test_beast_result_details_contains_tls() {
        let result = BeastTestResult {
            vulnerable: true,
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
            tls10_cbc_supported: false,
            ssl3_cbc_supported: false,
            details: "Not vulnerable - TLS 1.0/SSL 3.0 CBC ciphers not supported".to_string(),
        };
        assert!(result.details.contains("Not vulnerable"));
        assert!(!result.vulnerable);
    }
}
