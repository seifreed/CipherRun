// Lucky13 Vulnerability Test
// CVE-2013-0169
//
// Lucky13 is a timing attack against CBC mode ciphers in TLS.
// It exploits timing differences in MAC verification to recover plaintext.

use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

/// Lucky13 vulnerability tester
pub struct Lucky13Tester {
    target: Target,
}

impl Lucky13Tester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for Lucky13 vulnerability
    pub async fn test(&self) -> Result<Lucky13TestResult> {
        let cbc_supported = self.test_cbc_ciphers().await?;
        let timing_oracle = if cbc_supported {
            self.test_timing_oracle().await?
        } else {
            false
        };

        let vulnerable = cbc_supported && timing_oracle;

        let details = if vulnerable {
            "Vulnerable to Lucky13 (CVE-2013-0169) - CBC ciphers with timing oracle detected"
                .to_string()
        } else if cbc_supported {
            "Partially vulnerable - CBC ciphers supported but no clear timing oracle detected"
                .to_string()
        } else {
            "Not vulnerable - CBC ciphers not supported".to_string()
        };

        Ok(Lucky13TestResult {
            vulnerable,
            cbc_supported,
            timing_oracle,
            details,
        })
    }

    /// Test if CBC ciphers are supported
    async fn test_cbc_ciphers(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        // Test with various CBC ciphers
        let cbc_ciphers = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA";

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let mut builder = SslConnector::builder(SslMethod::tls())?;
                builder.set_cipher_list(cbc_ciphers)?;

                let connector = builder.build();
                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test for timing oracle by sending malformed MAC
    async fn test_timing_oracle(&self) -> Result<bool> {
        // Run multiple tests to detect timing differences
        let mut short_padding_times = Vec::new();
        let mut long_padding_times = Vec::new();

        for _ in 0..5 {
            if let Ok(time) = self.test_mac_timing(true).await {
                short_padding_times.push(time);
            }
            if let Ok(time) = self.test_mac_timing(false).await {
                long_padding_times.push(time);
            }
        }

        if short_padding_times.is_empty() || long_padding_times.is_empty() {
            return Ok(false);
        }

        // Calculate average times
        let avg_short: f64 =
            short_padding_times.iter().sum::<u128>() as f64 / short_padding_times.len() as f64;
        let avg_long: f64 =
            long_padding_times.iter().sum::<u128>() as f64 / long_padding_times.len() as f64;

        // If there's a significant timing difference (>10%), timing oracle exists
        let diff_percent = ((avg_short - avg_long).abs() / avg_long) * 100.0;
        Ok(diff_percent > 10.0)
    }

    /// Test MAC timing with different padding lengths
    async fn test_mac_timing(&self, short_padding: bool) -> Result<u128> {
        let addr = self.target.socket_addrs()[0];

        let start = Instant::now();

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello, Certificate, ServerHelloDone
                let mut buffer = vec![0u8; 8192];
                timeout(Duration::from_secs(3), stream.read(&mut buffer)).await??;

                // Send ClientKeyExchange
                let client_key_exchange = self.build_client_key_exchange();
                stream.write_all(&client_key_exchange).await?;

                // Send ChangeCipherSpec
                let ccs = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                stream.write_all(&ccs).await?;

                // Send Finished with invalid MAC (different padding)
                let finished = self.build_malformed_finished(short_padding);
                stream.write_all(&finished).await?;

                // Measure time until server responds with alert
                let mut response = vec![0u8; 1024];
                let _ = timeout(Duration::from_secs(2), stream.read(&mut response)).await;

                let elapsed = start.elapsed().as_micros();
                Ok(elapsed)
            }
            _ => Err(crate::error::TlsError::Other(
                "Connection failed".to_string(),
            )),
        }
    }

    /// Build ClientHello with CBC cipher preference using ClientHelloBuilder
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_cbc_ciphers();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
    }

    /// Build ClientKeyExchange
    fn build_client_key_exchange(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x86, // Record header
            0x10, // ClientKeyExchange
            0x00, 0x00, 0x82, // Length
            0x00,
            0x80, // Encrypted PMS length
                  // 128 bytes of encrypted premaster secret (dummy data)
        ]
        .into_iter()
        .chain(vec![0xaa; 128])
        .collect()
    }

    /// Build Finished message with malformed MAC
    fn build_malformed_finished(&self, short_padding: bool) -> Vec<u8> {
        let padding_len = if short_padding { 1 } else { 15 };
        let mut finished = vec![
            0x16, 0x03, 0x01, 0x00, 0x40, // Record header (will update)
            0x14, // Finished
            0x00, 0x00, 0x0c, // Length
        ];

        // Verify data (12 bytes, invalid)
        finished.extend_from_slice(&[0x00; 12]);

        // MAC (20 bytes for SHA1, invalid)
        finished.extend_from_slice(&[0xff; 20]);

        // Padding
        for _ in 0..padding_len {
            finished.push(padding_len as u8 - 1);
        }

        // Update record length
        let rec_len = finished.len() - 5;
        finished[3] = ((rec_len >> 8) & 0xff) as u8;
        finished[4] = (rec_len & 0xff) as u8;

        finished
    }
}

/// Lucky13 test result
#[derive(Debug, Clone)]
pub struct Lucky13TestResult {
    pub vulnerable: bool,
    pub cbc_supported: bool,
    pub timing_oracle: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lucky13_result() {
        let result = Lucky13TestResult {
            vulnerable: false,
            cbc_supported: true,
            timing_oracle: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.cbc_supported);
    }
}
