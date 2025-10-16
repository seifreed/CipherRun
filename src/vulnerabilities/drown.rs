// DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) Vulnerability Test
// CVE-2016-0800
//
// DROWN allows attackers to decrypt TLS sessions by exploiting SSLv2 on the same
// server or another server using the same private key. Even if the server doesn't
// support SSLv2 on HTTPS, if it supports SSLv2 on another port (like SMTP), it's vulnerable.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// DROWN vulnerability tester
pub struct DrownTester {
    target: Target,
}

impl DrownTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for DROWN vulnerability
    pub async fn test(&self) -> Result<DrownTestResult> {
        let sslv2_supported = self.test_sslv2().await?;
        let sslv2_export = if sslv2_supported {
            self.test_sslv2_export_ciphers().await?
        } else {
            false
        };

        let vulnerable = sslv2_supported;

        let details = if vulnerable {
            if sslv2_export {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 with export ciphers enabled (highly vulnerable)".to_string()
            } else {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 enabled".to_string()
            }
        } else {
            "Not vulnerable - SSLv2 not supported".to_string()
        };

        Ok(DrownTestResult {
            vulnerable,
            sslv2_supported,
            sslv2_export_ciphers: sslv2_export,
            details,
        })
    }

    /// Test if SSLv2 is supported
    async fn test_sslv2(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send SSLv2 ClientHello
                let client_hello = self.build_sslv2_client_hello();
                stream.write_all(&client_hello).await?;

                // Read response
                let mut buffer = vec![0u8; 4096];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check for SSLv2 ServerHello response
                        // SSLv2 ServerHello starts with 0x80 or 0x00 (2-byte length)
                        let is_sslv2_response =
                            n >= 2 && (buffer[0] & 0x80 != 0 || buffer[0] == 0x00);
                        Ok(is_sslv2_response)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test for SSLv2 export ciphers (makes DROWN easier to exploit)
    async fn test_sslv2_export_ciphers(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send SSLv2 ClientHello with export ciphers only
                let client_hello = self.build_sslv2_client_hello_export();
                stream.write_all(&client_hello).await?;

                // Read response
                let mut buffer = vec![0u8; 4096];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server accepted export cipher
                        let is_sslv2_response =
                            n >= 2 && (buffer[0] & 0x80 != 0 || buffer[0] == 0x00);
                        Ok(is_sslv2_response)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build SSLv2 ClientHello
    fn build_sslv2_client_hello(&self) -> Vec<u8> {
        let mut hello = vec![
            0x80, 0x31, // SSLv2 record header (high bit set, length: 49 bytes)
            0x01, // Message type: CLIENT-HELLO
            0x00, 0x02, // Version: SSL 2.0
        ];

        // Cipher specs length: 15 bytes (5 ciphers * 3 bytes)
        hello.push(0x00);
        hello.push(0x0f);

        // Session ID length: 0
        hello.push(0x00);
        hello.push(0x00);

        // Challenge length: 16 bytes
        hello.push(0x00);
        hello.push(0x10);

        // Cipher specs (3-byte cipher codes)
        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        hello.push(0x01);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC4_128_WITH_MD5
        hello.push(0x01);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC2_128_CBC_WITH_MD5
        hello.push(0x03);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_DES_64_CBC_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        hello.push(0x04);
        hello.push(0x00);
        hello.push(0x80);

        // Challenge (random 16 bytes)
        for i in 0..16 {
            hello.push((i * 13) as u8);
        }

        hello
    }

    /// Build SSLv2 ClientHello with export ciphers only
    fn build_sslv2_client_hello_export(&self) -> Vec<u8> {
        let mut hello = vec![
            0x80, 0x2b, // SSLv2 record header (high bit set, length: 43 bytes)
            0x01, // Message type: CLIENT-HELLO
            0x00, 0x02, // Version: SSL 2.0
        ];

        // Cipher specs length: 9 bytes (3 export ciphers * 3 bytes)
        hello.push(0x00);
        hello.push(0x09);

        // Session ID length: 0
        hello.push(0x00);
        hello.push(0x00);

        // Challenge length: 16 bytes
        hello.push(0x00);
        hello.push(0x10);

        // Export cipher specs
        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        hello.push(0x04);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

        // SSL_CK_DES_64_CBC_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

        // Challenge (random 16 bytes)
        for i in 0..16 {
            hello.push((i * 17) as u8);
        }

        hello
    }
}

/// DROWN test result
#[derive(Debug, Clone)]
pub struct DrownTestResult {
    pub vulnerable: bool,
    pub sslv2_supported: bool,
    pub sslv2_export_ciphers: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drown_result_not_vulnerable() {
        let result = DrownTestResult {
            vulnerable: false,
            sslv2_supported: false,
            sslv2_export_ciphers: false,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
    }

    #[test]
    fn test_drown_result_vulnerable() {
        let result = DrownTestResult {
            vulnerable: true,
            sslv2_supported: true,
            sslv2_export_ciphers: false,
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.sslv2_supported);
    }

    #[test]
    fn test_sslv2_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x80); // SSLv2 record
        assert_eq!(hello[2], 0x01); // CLIENT-HELLO
        assert_eq!(hello[3], 0x00); // SSL 2.0 version
        assert_eq!(hello[4], 0x02);
    }
}
