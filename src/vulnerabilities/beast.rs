// BEAST (Browser Exploit Against SSL/TLS) Vulnerability Test
// CVE-2011-3389
//
// BEAST exploits a weakness in CBC mode cipher suites in TLS 1.0 and earlier.
// It allows an attacker to decrypt HTTPS cookies by exploiting the predictable
// Initialization Vector (IV) in CBC mode.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

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
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
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
            _ => Ok(false),
        }
    }

    /// Test for SSL 3.0 with CBC ciphers
    async fn test_ssl3_cbc(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;
                builder.set_min_proto_version(Some(SslVersion::SSL3))?;
                builder.set_max_proto_version(Some(SslVersion::SSL3))?;

                builder.set_cipher_list("AES128-SHA:AES256-SHA:DES-CBC3-SHA")?;

                let connector = builder.build();
                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
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
}
