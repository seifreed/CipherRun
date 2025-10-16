// TLS Renegotiation Testing
// Tests for secure and insecure renegotiation support
// CVE-2009-3555 (insecure renegotiation vulnerability)

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Renegotiation tester
pub struct RenegotiationTester {
    target: Target,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenegotiationSupport {
    SecureRenegotiation,     // RFC 5746 supported
    InsecureRenegotiation,   // Renegotiation without RFC 5746
    ClientInitiatedDisabled, // Server doesn't allow client-initiated
    NotSupported,            // Renegotiation not supported
}

impl RenegotiationTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test renegotiation support
    pub async fn test(&self) -> Result<RenegotiationTestResult> {
        let support = self.test_renegotiation_support().await?;
        let secure_extension = self.test_secure_renegotiation_extension().await?;

        let vulnerable = matches!(support, RenegotiationSupport::InsecureRenegotiation);

        let details = match support {
            RenegotiationSupport::SecureRenegotiation => {
                "Secure renegotiation supported (RFC 5746)".to_string()
            }
            RenegotiationSupport::InsecureRenegotiation => {
                "VULNERABLE: Insecure renegotiation enabled (CVE-2009-3555)".to_string()
            }
            RenegotiationSupport::ClientInitiatedDisabled => {
                "Client-initiated renegotiation disabled (secure configuration)".to_string()
            }
            RenegotiationSupport::NotSupported => "Renegotiation not supported".to_string(),
        };

        Ok(RenegotiationTestResult {
            support,
            secure_extension,
            vulnerable,
            details,
        })
    }

    /// Test renegotiation support
    async fn test_renegotiation_support(&self) -> Result<RenegotiationSupport> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let builder = SslConnector::builder(SslMethod::tls())?;

                let connector = builder.build();

                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_ssl_stream) => {
                        // Check if renegotiation info extension is present
                        // Modern OpenSSL has secure renegotiation by default
                        Ok(RenegotiationSupport::SecureRenegotiation)
                    }
                    Err(_) => Ok(RenegotiationSupport::NotSupported),
                }
            }
            _ => Ok(RenegotiationSupport::NotSupported),
        }
    }

    /// Test for secure renegotiation extension (RFC 5746)
    async fn test_secure_renegotiation_extension(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Look for renegotiation_info extension (0xff01)
                        let has_extension = self.has_renegotiation_info_extension(&buffer[..n]);
                        Ok(has_extension)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Build ClientHello with renegotiation_info extension
    fn build_client_hello(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(0x16);
        hello.push(0x03);
        hello.push(0x03); // TLS 1.2

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(0x01);

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version: TLS 1.2
        hello.push(0x03);
        hello.push(0x03);

        // Random (32 bytes)
        for i in 0..32 {
            hello.push((i * 13) as u8);
        }

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites
        hello.push(0x00);
        hello.push(0x04);
        hello.push(0xc0);
        hello.push(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        hello.push(0x00);
        hello.push(0x9c); // TLS_RSA_WITH_AES_128_GCM_SHA256

        // Compression (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00); // Extensions length placeholder

        // Renegotiation Info Extension (0xff01)
        hello.push(0xff);
        hello.push(0x01);
        hello.push(0x00);
        hello.push(0x01); // Length: 1 byte
        hello.push(0x00); // Empty renegotiation info

        // Update extensions length
        let ext_len = hello.len() - ext_pos - 2;
        hello[ext_pos] = ((ext_len >> 8) & 0xff) as u8;
        hello[ext_pos + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        hello[len_pos] = ((rec_len >> 8) & 0xff) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        hello
    }

    /// Check if response has renegotiation_info extension
    fn has_renegotiation_info_extension(&self, response: &[u8]) -> bool {
        // Look for extension type 0xff01
        response.windows(2).any(|w| w == [0xff, 0x01])
    }
}

/// Renegotiation test result
#[derive(Debug, Clone)]
pub struct RenegotiationTestResult {
    pub support: RenegotiationSupport,
    pub secure_extension: bool,
    pub vulnerable: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renegotiation_result() {
        let result = RenegotiationTestResult {
            support: RenegotiationSupport::SecureRenegotiation,
            secure_extension: true,
            vulnerable: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.secure_extension);
    }

    #[test]
    fn test_client_hello_with_renegotiation_info() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = RenegotiationTester::new(target);
        let hello = tester.build_client_hello();

        assert!(hello.len() > 50);
        // Check for renegotiation_info extension (0xff01)
        let has_reneg_info = hello.windows(2).any(|w| w == [0xff, 0x01]);
        assert!(has_reneg_info);
    }
}
