// RC4 Cipher Testing
// RC4 is considered insecure due to statistical biases (Appelbaum attack, etc.)
// RFC 7465 prohibits RC4 in TLS

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// RC4 cipher tester
pub struct Rc4Tester {
    target: Target,
}

impl Rc4Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for RC4 cipher support
    pub async fn test(&self) -> Result<Rc4TestResult> {
        let rc4_ciphers = self.test_rc4_ciphers().await?;
        let vulnerable = !rc4_ciphers.is_empty();

        let details = if vulnerable {
            format!(
                "INSECURE: {} RC4 cipher(s) supported (RFC 7465 prohibits RC4): {}",
                rc4_ciphers.len(),
                rc4_ciphers.join(", ")
            )
        } else {
            "Good: No RC4 ciphers supported".to_string()
        };

        Ok(Rc4TestResult {
            vulnerable,
            rc4_ciphers,
            details,
        })
    }

    /// Test for RC4 cipher support
    async fn test_rc4_ciphers(&self) -> Result<Vec<String>> {
        let mut supported = Vec::new();

        // List of RC4 ciphers to test
        let rc4_ciphers = vec![
            // RC4-MD5
            "RC4-MD5",
            "RC4-SHA",
            "EXP-RC4-MD5",
            "EXP1024-RC4-MD5",
            "EXP1024-RC4-SHA",
            // ECDHE with RC4
            "ECDHE-RSA-RC4-SHA",
            "ECDHE-ECDSA-RC4-SHA",
            // ECDH with RC4
            "ECDH-RSA-RC4-SHA",
            "ECDH-ECDSA-RC4-SHA",
            // PSK with RC4
            "PSK-RC4-SHA",
            "ECDHE-PSK-RC4-SHA",
            // Anonymous RC4
            "ADH-RC4-MD5",
            "AECDH-RC4-SHA",
        ];

        for cipher in rc4_ciphers {
            if self.test_cipher(cipher).await? {
                supported.push(cipher.to_string());
            }
        }

        Ok(supported)
    }

    /// Test if a specific RC4 cipher is supported
    async fn test_cipher(&self, cipher: &str) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Allow older protocols that might support RC4
                if cipher.starts_with("EXP") {
                    builder.set_min_proto_version(Some(SslVersion::SSL3))?;
                } else {
                    builder.set_min_proto_version(Some(SslVersion::TLS1))?;
                }

                // Try to set the specific RC4 cipher
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

    /// Test if RC4 is preferred (worst case scenario)
    pub async fn test_rc4_preferred(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;

                // Set cipher list with RC4 first, then strong ciphers
                match builder.set_cipher_list("RC4-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256") {
                    Ok(_) => {
                        let connector = builder.build();
                        match connector.connect(&self.target.hostname, std_stream) {
                            Ok(ssl_stream) => {
                                // Check which cipher was selected
                                if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                                    let cipher_name = cipher.name();
                                    Ok(cipher_name.contains("RC4"))
                                } else {
                                    Ok(false)
                                }
                            }
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

/// RC4 test result
#[derive(Debug, Clone)]
pub struct Rc4TestResult {
    pub vulnerable: bool,
    pub rc4_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_result_not_vulnerable() {
        let result = Rc4TestResult {
            vulnerable: false,
            rc4_ciphers: vec![],
            details: "Good".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.rc4_ciphers.is_empty());
    }

    #[test]
    fn test_rc4_result_vulnerable() {
        let result = Rc4TestResult {
            vulnerable: true,
            rc4_ciphers: vec!["RC4-SHA".to_string(), "RC4-MD5".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert_eq!(result.rc4_ciphers.len(), 2);
    }
}
