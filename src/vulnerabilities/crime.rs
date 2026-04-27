// CRIME (Compression Ratio Info-leak Made Easy) Vulnerability Test
// CVE-2012-4929
//
// CRIME exploits TLS/SSL compression to extract secrets (like session cookies)
// by observing changes in compression ratios when injecting known data.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// CRIME vulnerability tester
pub struct CrimeTester<'a> {
    target: &'a Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionProbeStatus {
    Enabled,
    Disabled,
    Inconclusive,
}

impl CompressionProbeStatus {
    fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }
}

impl<'a> CrimeTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self { target }
    }

    /// Test for CRIME vulnerability
    pub async fn test(&self) -> Result<CrimeTestResult> {
        let tls_compression = self.test_tls_compression().await?;
        let spdy_compression = self.test_spdy_compression().await?;

        let tls_compression_enabled = tls_compression.is_enabled();
        let spdy_compression_enabled = spdy_compression.is_enabled();
        let vulnerable = tls_compression_enabled || spdy_compression_enabled;
        let inconclusive = !vulnerable
            && (tls_compression.is_inconclusive() || spdy_compression.is_inconclusive());

        let details = if vulnerable {
            let mut parts = Vec::new();
            if tls_compression_enabled {
                parts.push("TLS compression enabled");
            }
            if spdy_compression_enabled {
                parts.push("SPDY compression enabled");
            }
            format!("Vulnerable to CRIME (CVE-2012-4929): {}", parts.join(", "))
        } else if inconclusive {
            "CRIME test inconclusive - unable to determine TLS/SPDY compression status".to_string()
        } else {
            "Not vulnerable - TLS/SPDY compression disabled".to_string()
        };

        Ok(CrimeTestResult {
            vulnerable,
            inconclusive,
            tls_compression_enabled,
            spdy_compression_enabled,
            details,
        })
    }

    /// Test if TLS compression is enabled
    ///
    /// Checks whether TLS-level compression (DEFLATE) was negotiated.
    /// Modern OpenSSL disables compression by default due to CRIME vulnerability.
    /// This test attempts to negotiate compression and checks if it was enabled.
    async fn test_tls_compression(&self) -> Result<CompressionProbeStatus> {
        // Modern OpenSSL (1.1.0+) disables compression by default.
        // OpenSSL 3.x removes it entirely. Most servers will have compression disabled.
        //
        // For legacy systems, we attempt to detect compression via the handshake.
        // We send a ClientHello offering DEFLATE compression and check if the
        // server accepts it by looking at the compression method in ServerHello.

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(CompressionProbeStatus::Inconclusive),
            };

        // Send ClientHello with compression method DEFLATE (0x01)
        let client_hello = self.build_client_hello_with_compression();
        stream.write_all(&client_hello).await?;

        // Read ServerHello
        let mut buffer = vec![0u8; 4096];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 11 => {
                // Validate the TLS record length so we only parse within the first record
                let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                if record_len + 5 > n {
                    // Truncated ServerHello split across reads; the probe cannot decide.
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                if buffer[0] == 0x16 && buffer[5] == 0x02 && n > 43 {
                    let session_id_len = buffer[43] as usize;
                    if session_id_len > 32 {
                        // Malformed ServerHello — cannot determine compression status
                        return Ok(CompressionProbeStatus::Inconclusive);
                    }
                    let cipher_offset = 44 + session_id_len;
                    // Ensure cipher_offset is within the first TLS record body (5+record_len)
                    if cipher_offset + 2 < 5 + record_len && n > cipher_offset + 2 {
                        let compression_method = buffer[cipher_offset + 2];
                        tracing::debug!("Server compression method: {}", compression_method);
                        return Ok(if compression_method == 0x01 {
                            CompressionProbeStatus::Enabled
                        } else {
                            CompressionProbeStatus::Disabled
                        });
                    }
                }
                Ok(CompressionProbeStatus::Disabled)
            }
            _ => Ok(CompressionProbeStatus::Inconclusive),
        }
    }

    /// Build ClientHello offering DEFLATE compression
    fn build_client_hello_with_compression(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_rsa_key_exchange().with_compression(true);
        builder.build().unwrap_or_else(|_| Vec::new())
    }

    /// Test if SPDY compression is enabled
    ///
    /// SPDY uses header compression (DEFLATE-based) which is vulnerable to CRIME.
    /// HTTP/2 uses HPACK which is specifically designed to resist CRIME-style attacks,
    /// so HTTP/2 is NOT flagged as vulnerable.
    ///
    /// Detection approach: Parse the ServerHello extensions to find NPN (0x3374),
    /// then check if any negotiated protocol is SPDY (not h2/HTTP2).
    async fn test_spdy_compression(&self) -> Result<CompressionProbeStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(CompressionProbeStatus::Inconclusive),
            };

        // Send ClientHello with NPN extension advertising SPDY support
        let client_hello = self.build_client_hello_with_npn();
        stream.write_all(&client_hello).await?;

        // Read ServerHello
        let mut buffer = vec![0u8; 8192];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 43 => {
                // Parse ServerHello structurally to find NPN extension
                let data = &buffer[..n];

                // Verify it's a handshake ServerHello
                if data.len() < 6 || data[0] != 0x16 || data[5] != 0x02 {
                    return Ok(CompressionProbeStatus::Disabled);
                }

                // Parse to extensions: skip record header (5) + handshake header (4)
                // + version (2) + random (32) + session_id
                let sid_offset = 43;
                if sid_offset >= n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                let sid_len = data[sid_offset] as usize;
                // cipher suite (2) + compression (1) + extensions_length (2)
                let ext_len_offset = sid_offset + 1 + sid_len + 2 + 1;
                if ext_len_offset + 2 > n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }

                // Validate TLS record length before parsing extensions
                let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if record_len + 5 > n {
                    return Ok(CompressionProbeStatus::Inconclusive);
                }
                let record_end = 5 + record_len;

                let ext_total =
                    u16::from_be_bytes([data[ext_len_offset], data[ext_len_offset + 1]]) as usize;
                let ext_start = ext_len_offset + 2;
                let ext_end = (ext_start + ext_total).min(record_end);

                // Walk extensions structurally looking for NPN (0x3374)
                let mut pos = ext_start;
                while pos + 4 <= ext_end {
                    let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    pos += 4;
                    if pos + ext_len > ext_end {
                        break;
                    }

                    if ext_type == 0x3374 {
                        // Parse NPN protocol list within this extension
                        let mut proto_pos = pos;
                        let proto_end = pos + ext_len;
                        while proto_pos < proto_end {
                            let proto_len = data[proto_pos] as usize;
                            proto_pos += 1;
                            if proto_pos + proto_len > proto_end {
                                break;
                            }
                            if let Ok(proto) =
                                std::str::from_utf8(&data[proto_pos..proto_pos + proto_len])
                            {
                                // Only flag SPDY protocols as CRIME-vulnerable
                                // HTTP/2 (h2, h2c) uses HPACK which is CRIME-resistant
                                if proto.starts_with("spdy/") {
                                    return Ok(CompressionProbeStatus::Enabled);
                                }
                            }
                            proto_pos += proto_len;
                        }
                        break;
                    }

                    pos += ext_len;
                }

                Ok(CompressionProbeStatus::Disabled)
            }
            _ => Ok(CompressionProbeStatus::Inconclusive),
        }
    }

    /// Build ClientHello with NPN extension for SPDY using ClientHelloBuilder
    fn build_client_hello_with_npn(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder
            .for_rsa_key_exchange()
            .with_compression(true) // Enable DEFLATE for CRIME testing
            .add_npn(); // Add NPN extension for SPDY
        builder.build().unwrap_or_else(|_| Vec::new())
    }
}

/// CRIME test result
#[derive(Debug, Clone)]
pub struct CrimeTestResult {
    pub vulnerable: bool,
    pub inconclusive: bool,
    pub tls_compression_enabled: bool,
    pub spdy_compression_enabled: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_crime_result_creation() {
        let result = CrimeTestResult {
            vulnerable: true,
            inconclusive: false,
            tls_compression_enabled: true,
            spdy_compression_enabled: false,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.tls_compression_enabled);
        assert!(!result.spdy_compression_enabled);
    }

    #[test]
    fn test_client_hello_with_npn() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester.build_client_hello_with_npn();

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for compression methods (DEFLATE = 0x01)
        let has_deflate = hello.windows(2).any(|w| w == [0x02, 0x01]);
        assert!(has_deflate);
    }

    #[test]
    fn test_crime_result_debug_contains_details() {
        let result = CrimeTestResult {
            vulnerable: false,
            inconclusive: false,
            tls_compression_enabled: false,
            spdy_compression_enabled: false,
            details: "No compression".to_string(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("No compression"));
    }

    #[test]
    fn test_crime_result_not_vulnerable_text() {
        let result = CrimeTestResult {
            vulnerable: false,
            inconclusive: false,
            tls_compression_enabled: false,
            spdy_compression_enabled: false,
            details: "Not vulnerable - TLS/SPDY compression disabled".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_client_hello_with_npn_contains_extension_id() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester.build_client_hello_with_npn();

        // NPN extension type is 0x3374
        assert!(hello.windows(2).any(|w| w == [0x33, 0x74]));
    }

    #[test]
    fn test_client_hello_with_compression() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let hello = tester.build_client_hello_with_compression();

        assert!(hello.len() > 50);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello

        // Check for compression methods (should include DEFLATE = 0x01)
        let has_deflate = hello.windows(2).any(|w| w == [0x02, 0x01]);
        assert!(has_deflate, "ClientHello should offer DEFLATE compression");
    }

    #[tokio::test]
    async fn test_crime_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let tester = CrimeTester::new(&target);
        let result = tester.test().await.unwrap();
        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(!result.tls_compression_enabled);
        assert!(!result.spdy_compression_enabled);
        assert!(
            result.details.to_ascii_lowercase().contains("inconclusive"),
            "inactive target must not be reported as a clean CRIME pass: {}",
            result.details
        );
    }
}
