// Sweet32 Vulnerability Test
// CVE-2016-2183 (3DES), CVE-2016-6329 (Blowfish)
//
// Sweet32 is a birthday attack against 64-bit block ciphers like 3DES and Blowfish.
// After 2^32 blocks, collisions become likely, allowing attackers to recover plaintext.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Sweet32 vulnerability tester
pub struct Sweet32Tester {
    target: Target,
}

impl Sweet32Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Sweet32 vulnerability
    pub async fn test(&self) -> Result<Sweet32TestResult> {
        let des3_ciphers = self.test_3des_ciphers().await?;
        let blowfish_ciphers = self.test_blowfish_ciphers().await?;

        let vulnerable = !des3_ciphers.is_empty() || !blowfish_ciphers.is_empty();

        let details = if vulnerable {
            let mut parts = Vec::new();
            if !des3_ciphers.is_empty() {
                parts.push(format!("3DES ciphers supported: {}", des3_ciphers.len()));
            }
            if !blowfish_ciphers.is_empty() {
                parts.push(format!(
                    "Blowfish ciphers supported: {}",
                    blowfish_ciphers.len()
                ));
            }
            format!(
                "Vulnerable to Sweet32 (CVE-2016-2183): {}",
                parts.join(", ")
            )
        } else {
            "Not vulnerable - No 64-bit block ciphers (3DES, Blowfish) supported".to_string()
        };

        Ok(Sweet32TestResult {
            vulnerable,
            des3_ciphers,
            blowfish_ciphers,
            details,
        })
    }

    /// Test for 3DES cipher support
    async fn test_3des_ciphers(&self) -> Result<Vec<String>> {
        let mut supported = Vec::new();
        let des3_ciphers = vec![
            "DES-CBC3-SHA",
            "DES-CBC3-MD5",
            "EDH-RSA-DES-CBC3-SHA",
            "EDH-DSS-DES-CBC3-SHA",
            "ECDHE-RSA-DES-CBC3-SHA",
            "ECDHE-ECDSA-DES-CBC3-SHA",
            "PSK-3DES-EDE-CBC-SHA",
            "KRB5-DES-CBC3-SHA",
            "KRB5-DES-CBC3-MD5",
        ];

        for cipher in des3_ciphers {
            if self.test_cipher(cipher).await? {
                supported.push(cipher.to_string());
            }
        }

        Ok(supported)
    }

    /// Test for Blowfish cipher support
    async fn test_blowfish_ciphers(&self) -> Result<Vec<String>> {
        let mut supported = Vec::new();
        let blowfish_ciphers = vec![
            "BF-CBC",
            "BF-CFB",
            "BF-ECB",
            "BF-OFB",
            "BF-SHA",
            "EDH-RSA-BF-CBC-SHA",
            "EDH-DSS-BF-CBC-SHA",
        ];

        for cipher in blowfish_ciphers {
            if self.test_cipher(cipher).await? {
                supported.push(cipher.to_string());
            }
        }

        Ok(supported)
    }

    /// Test if a specific cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Try to set the specific cipher
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

/// Sweet32 test result
#[derive(Debug, Clone)]
pub struct Sweet32TestResult {
    pub vulnerable: bool,
    pub des3_ciphers: Vec<String>,
    pub blowfish_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweet32_result_not_vulnerable() {
        let result = Sweet32TestResult {
            vulnerable: false,
            des3_ciphers: vec![],
            blowfish_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.des3_ciphers.is_empty());
        assert!(result.blowfish_ciphers.is_empty());
    }

    #[test]
    fn test_sweet32_result_vulnerable() {
        let result = Sweet32TestResult {
            vulnerable: true,
            des3_ciphers: vec!["DES-CBC3-SHA".to_string()],
            blowfish_ciphers: vec![],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.des3_ciphers.len(), 1);
    }
}
