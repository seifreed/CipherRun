// LOGJAM Vulnerability Test
// CVE-2015-4000
//
// LOGJAM allows attackers to downgrade TLS connections to use weak 512-bit
// Diffie-Hellman parameters, making it possible to break the encryption through
// precomputation attacks.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// LOGJAM vulnerability tester
pub struct LogjamTester {
    target: Target,
}

impl LogjamTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for LOGJAM vulnerability
    pub async fn test(&self) -> Result<LogjamTestResult> {
        let export_dh = self.test_export_dh().await?;
        let weak_dh = self.test_weak_dh_params().await?;
        let dhe_ciphers = self.test_dhe_ciphers().await?;

        let vulnerable = export_dh || weak_dh;

        let details = if vulnerable {
            let mut parts = Vec::new();
            if export_dh {
                parts.push("Export-grade DH supported");
            }
            if weak_dh {
                parts.push("Weak DH parameters (≤1024 bits)");
            }
            format!("Vulnerable to LOGJAM (CVE-2015-4000): {}", parts.join(", "))
        } else if !dhe_ciphers.is_empty() {
            "Not vulnerable - DHE supported with strong parameters".to_string()
        } else {
            "Not vulnerable - DHE not supported".to_string()
        };

        Ok(LogjamTestResult {
            vulnerable,
            export_dh_supported: export_dh,
            weak_dh_params: weak_dh,
            dhe_ciphers,
            details,
        })
    }

    /// Test for export-grade DH cipher support
    async fn test_export_dh(&self) -> Result<bool> {
        let export_dh_ciphers = vec![
            "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA",
            "EXP1024-DHE-DSS-DES-CBC-SHA",
            "EXP1024-DHE-DSS-RC4-SHA",
        ];

        for cipher in export_dh_ciphers {
            if self.test_cipher(cipher).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Test for weak DH parameters
    ///
    /// Performance optimization: Wraps blocking OpenSSL operations in spawn_blocking
    /// to prevent blocking the async runtime.
    async fn test_weak_dh_params(&self) -> Result<bool> {
        use openssl::pkey::Id;
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];
        let hostname = self.target.hostname.clone();

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // Convert to std stream for OpenSSL
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                // Wrap blocking SSL operations in spawn_blocking
                let result = tokio::task::spawn_blocking(move || -> crate::Result<bool> {
                    let mut builder = SslConnector::builder(SslMethod::tls())?;

                    // Set DHE ciphers only
                    builder.set_cipher_list("DHE:EDH:!aNULL:!eNULL")?;

                    let connector = builder.build();
                    match connector.connect(&hostname, std_stream) {
                        Ok(ssl_stream) => match ssl_stream.ssl().peer_tmp_key() {
                            Ok(tmp_key) => {
                                if tmp_key.id() == Id::DH {
                                    Ok(tmp_key.bits() <= 1024)
                                } else {
                                    Ok(false)
                                }
                            }
                            Err(_) => Ok(false),
                        },
                        Err(_) => Ok(false),
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("Spawn blocking failed: {}", e))??;

                Ok(result)
            }
            _ => Ok(false),
        }
    }

    /// Test for DHE cipher support
    async fn test_dhe_ciphers(&self) -> Result<Vec<String>> {
        let mut supported = Vec::new();

        let dhe_ciphers = vec![
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA",
            "DHE-RSA-CAMELLIA256-SHA",
            "DHE-RSA-CAMELLIA128-SHA",
            "DHE-DSS-AES256-GCM-SHA384",
            "DHE-DSS-AES128-GCM-SHA256",
            "DHE-DSS-AES256-SHA256",
            "DHE-DSS-AES128-SHA256",
            "DHE-DSS-AES256-SHA",
            "DHE-DSS-AES128-SHA",
        ];

        for cipher in dhe_ciphers {
            if self.test_cipher(cipher).await? {
                supported.push(cipher.to_string());
            }
        }

        Ok(supported)
    }

    /// Test if a specific cipher is supported
    ///
    /// Performance optimization: Wraps blocking OpenSSL operations in spawn_blocking
    async fn test_cipher(&self, cipher: &str) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = self.target.socket_addrs()[0];
        let hostname = self.target.hostname.clone();
        let cipher = cipher.to_string();

        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // Convert to std stream for OpenSSL
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                // Wrap blocking SSL operations in spawn_blocking
                let result = tokio::task::spawn_blocking(move || -> Result<bool> {
                    let mut builder = SslConnector::builder(SslMethod::tls())?;

                    // Allow SSL 3.0 for export ciphers
                    if cipher.starts_with("EXP") {
                        builder.set_min_proto_version(Some(SslVersion::SSL3))?;
                    }

                    // Try to set the specific cipher
                    match builder.set_cipher_list(&cipher) {
                        Ok(_) => {
                            let connector = builder.build();
                            match connector.connect(&hostname, std_stream) {
                                Ok(_) => Ok(true),
                                Err(_) => Ok(false),
                            }
                        }
                        Err(_) => Ok(false),
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("Spawn blocking failed: {}", e))??;

                Ok(result)
            }
            _ => Ok(false),
        }
    }
}

/// LOGJAM test result
#[derive(Debug, Clone)]
pub struct LogjamTestResult {
    pub vulnerable: bool,
    pub export_dh_supported: bool,
    pub weak_dh_params: bool,
    pub dhe_ciphers: Vec<String>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logjam_result_not_vulnerable() {
        let result = LogjamTestResult {
            vulnerable: false,
            export_dh_supported: false,
            weak_dh_params: false,
            dhe_ciphers: vec![],
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.export_dh_supported);
        assert!(!result.weak_dh_params);
    }

    #[test]
    fn test_logjam_result_vulnerable() {
        let result = LogjamTestResult {
            vulnerable: true,
            export_dh_supported: true,
            weak_dh_params: false,
            dhe_ciphers: vec!["DHE-RSA-AES256-SHA".to_string()],
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.export_dh_supported);
    }
}
