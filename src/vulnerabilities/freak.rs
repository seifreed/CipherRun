// FREAK (Factoring RSA Export Keys) Vulnerability Test
// CVE-2015-0204
//
// FREAK allows attackers to force the use of weak 512-bit RSA export keys
// by manipulating the TLS handshake, making it possible to factor the key
// and decrypt the connection.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// FREAK vulnerability tester
pub struct FreakTester {
    target: Target,
}

impl FreakTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for FREAK vulnerability
    pub async fn test(&self) -> Result<FreakTestResult> {
        let export_ciphers = self.test_export_ciphers().await?;
        let vulnerable = !export_ciphers.is_empty();

        let details = if vulnerable {
            format!(
                "Vulnerable to FREAK (CVE-2015-0204) - Server supports {} RSA export cipher(s): {}",
                export_ciphers.len(),
                export_ciphers.join(", ")
            )
        } else {
            "Not vulnerable - No RSA export ciphers supported".to_string()
        };

        Ok(FreakTestResult {
            vulnerable,
            export_ciphers,
            details,
        })
    }

    /// Test for RSA export cipher support
    async fn test_export_ciphers(&self) -> Result<Vec<String>> {
        let mut supported = Vec::new();

        // List of RSA export ciphers
        let export_ciphers = vec![
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "EXP-DES-CBC-SHA",
            "EXP-RC4-MD5",
            "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA",
            "EXP-ADH-RC4-MD5",
            "EXP-ADH-DES-CBC-SHA",
            "EXP1024-DES-CBC-SHA",
            "EXP1024-RC4-SHA",
            "EXP1024-RC4-MD5",
            "EXP1024-RC2-CBC-MD5",
            "EXP1024-DHE-DSS-DES-CBC-SHA",
            "EXP1024-DHE-DSS-RC4-SHA",
        ];

        for cipher in export_ciphers {
            if self.test_cipher(cipher).await? {
                supported.push(cipher.to_string());
            }
        }

        Ok(supported)
    }

    /// Test if a specific export cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Allow older TLS versions that might support export ciphers
                builder.set_min_proto_version(Some(SslVersion::SSL3))?;

                // Try to set the specific export cipher
                match builder.set_cipher_list(cipher) {
                    Ok(_) => {
                        let connector = builder.build();
                        match connector.connect(&self.target.hostname, std_stream) {
                            Ok(_) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    }
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }
}

/// FREAK test result
#[derive(Debug, Clone)]
pub struct FreakTestResult {
    pub vulnerable: bool,
    pub export_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freak_result_not_vulnerable() {
        let result = FreakTestResult {
            vulnerable: false,
            export_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.export_ciphers.is_empty());
    }

    #[test]
    fn test_freak_result_vulnerable() {
        let result = FreakTestResult {
            vulnerable: true,
            export_ciphers: vec!["EXP-RC4-MD5".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.export_ciphers.len(), 1);
    }
}
