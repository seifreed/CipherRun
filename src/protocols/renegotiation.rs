// TLS Renegotiation Testing
// Tests for secure and insecure renegotiation support
// CVE-2009-3555 (insecure renegotiation vulnerability)

use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, DEFAULT_READ_TIMEOUT, EXTENSION_RENEGOTIATION_INFO,
    HANDSHAKE_TYPE_CLIENT_HELLO, SHORT_TIMEOUT, VERSION_TLS_1_2, VULNERABILITY_CHECK_BUFFER_SIZE,
};
use crate::utils::network::Target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Renegotiation tester
pub struct RenegotiationTester<'a> {
    target: &'a Target,
}

/// Result of insecure renegotiation detection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InsecureRenegotiationResult {
    /// Server appears vulnerable to insecure renegotiation
    Detected,
    /// Server responded without renegotiation_info extension - inconclusive
    /// Manual verification needed to determine if CVE-2009-3555 vulnerable
    Inconclusive,
    /// Server properly rejected or has secure renegotiation
    NotDetected,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenegotiationSupport {
    SecureRenegotiation,     // RFC 5746 supported
    InsecureRenegotiation,   // Renegotiation without RFC 5746
    ClientInitiatedDisabled, // Server doesn't allow client-initiated
    NotSupported,            // Renegotiation not supported
}

impl<'a> RenegotiationTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self { target }
    }

    /// Test renegotiation support
    pub async fn test(&self) -> Result<RenegotiationTestResult> {
        // Test for secure renegotiation extension (RFC 5746)
        let secure_extension_probe = self.test_secure_renegotiation_extension().await?;

        // Test for insecure renegotiation (CVE-2009-3555)
        let insecure_result = self.test_insecure_renegotiation().await?;

        if secure_extension_probe.is_none()
            && matches!(insecure_result, InsecureRenegotiationResult::Inconclusive)
        {
            return Ok(RenegotiationTestResult {
                support: RenegotiationSupport::NotSupported,
                secure_extension: false,
                vulnerable: false,
                needs_verification: true,
                inconclusive: true,
                details: "Renegotiation support unclear - baseline TLS probes inconclusive"
                    .to_string(),
            });
        }

        let secure_extension = secure_extension_probe.unwrap_or(false);

        // Determine if manual verification is needed
        let needs_verification =
            matches!(insecure_result, InsecureRenegotiationResult::Inconclusive);

        // Determine support level
        let support = if secure_extension {
            RenegotiationSupport::SecureRenegotiation
        } else if matches!(insecure_result, InsecureRenegotiationResult::Detected) {
            RenegotiationSupport::InsecureRenegotiation
        } else {
            // secure_extension is false: server didn't echo RFC 5746 in ServerHello.
            // test_renegotiation_support() uses OpenSSL (which always includes RFC 5746)
            // and returns SecureRenegotiation whenever TLS works — but a successful TLS
            // handshake here doesn't imply the server truly supports RFC 5746 (we already
            // know it didn't echo the extension). Cap SecureRenegotiation to NotSupported.
            match self.test_renegotiation_support().await? {
                RenegotiationSupport::SecureRenegotiation => RenegotiationSupport::NotSupported,
                other => other,
            }
        };

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
            RenegotiationSupport::NotSupported => {
                if needs_verification {
                    "Renegotiation support unclear - server responded without renegotiation_info extension. \
                     Manual verification recommended for CVE-2009-3555.".to_string()
                } else {
                    "Renegotiation not supported".to_string()
                }
            }
        };

        Ok(RenegotiationTestResult {
            support,
            secure_extension,
            vulnerable,
            needs_verification,
            inconclusive: needs_verification,
            details,
        })
    }

    /// Test renegotiation support
    ///
    /// Note: This tests if the server supports renegotiation at all.
    /// To detect INSECURE renegotiation (CVE-2009-3555), we need to check
    /// if the server accepts connections WITHOUT the renegotiation_info extension.
    ///
    /// The current implementation uses OpenSSL's SslConnector which ALWAYS
    /// includes the renegotiation_info extension (RFC 5746). This means
    /// we can only detect:
    /// - SecureRenegotiation: Server accepts connection with RFC 5746
    /// - NotSupported: Connection fails
    ///
    /// To detect InsecureRenegotiation, we would need to:
    /// 1. Send ClientHello WITHOUT renegotiation_info extension
    /// 2. See if server accepts (vulnerable) or rejects (secure)
    ///
    /// This is implemented in test_insecure_renegotiation() below.
    async fn test_renegotiation_support(&self) -> Result<RenegotiationSupport> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, DEFAULT_READ_TIMEOUT, None).await {
            Ok(stream) => {
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;

                let builder = SslConnector::builder(SslMethod::tls())?;

                let connector = builder.build();

                match connector.connect(&self.target.hostname, std_stream) {
                    Ok(_ssl_stream) => {
                        // OpenSSL client with RFC 5746 connected successfully
                        // Server supports secure renegotiation
                        Ok(RenegotiationSupport::SecureRenegotiation)
                    }
                    Err(_) => Ok(RenegotiationSupport::NotSupported),
                }
            }
            _ => Ok(RenegotiationSupport::NotSupported),
        }
    }

    /// Test for insecure renegotiation (CVE-2009-3555)
    ///
    /// Send ClientHello WITHOUT renegotiation_info extension.
    /// If server accepts, it may be vulnerable to insecure renegotiation.
    ///
    /// Returns:
    /// - `Detected`: Server confirmed vulnerable (rare - would require completing handshake and renegotiating)
    /// - `Inconclusive`: Server responded without renegotiation_info extension - manual verification needed
    /// - `NotDetected`: Server has secure renegotiation or doesn't support renegotiation
    async fn test_insecure_renegotiation(&self) -> Result<InsecureRenegotiationResult> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, DEFAULT_READ_TIMEOUT, None).await {
            Ok(mut stream) => {
                // Send ClientHello WITHOUT renegotiation_info extension
                let client_hello = self.build_client_hello_without_reneg_info();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; VULNERABILITY_CHECK_BUFFER_SIZE];
                match timeout(SHORT_TIMEOUT, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server responded with a valid ServerHello
                        // If server responds but WITHOUT renegotiation_info,
                        // it may be vulnerable
                        if buffer[0] == CONTENT_TYPE_HANDSHAKE && n > 5 {
                            // Check if server's ServerHello includes renegotiation_info
                            let has_reneg_info =
                                self.has_renegotiation_info_extension(&buffer[..n]);

                            // Detection analysis:
                            // - Server sends ServerHello WITHOUT renegotiation_info extension:
                            //   This COULD indicate insecure renegotiation support, but it's NOT
                            //   conclusive proof of CVE-2009-3555 vulnerability.
                            //
                            // - To fully confirm insecure renegotiation vulnerability, we would need to:
                            //   1. Complete the initial handshake without RFC 5746 extension
                            //   2. Attempt a renegotiation request
                            //   3. Observe if server accepts it (vulnerable) or rejects (secure)
                            //
                            // - Current detection is a heuristic that produces false positives:
                            //   Many modern servers simply don't support renegotiation at all.
                            //
                            // Result interpretation:
                            // - When extension is missing, return Inconclusive to indicate manual verification needed
                            // - The secure_renegotiation_extension test provides RFC 5746 compliance info.
                            if !has_reneg_info {
                                // Server responded with ServerHello WITHOUT renegotiation_info extension.
                                // This is inconclusive - server may:
                                // 1. Be vulnerable to insecure renegotiation (CVE-2009-3555)
                                // 2. Simply not support renegotiation at all (modern, secure behavior)
                                // Mark as inconclusive and recommend manual verification.
                                tracing::warn!(
                                    "Server responded without renegotiation_info extension - \
                                     inconclusive for CVE-2009-3555. Manual verification recommended."
                                );
                                return Ok(InsecureRenegotiationResult::Inconclusive);
                            }
                        }
                        Ok(InsecureRenegotiationResult::NotDetected)
                    }
                    _ => Ok(InsecureRenegotiationResult::Inconclusive),
                }
            }
            _ => Ok(InsecureRenegotiationResult::Inconclusive),
        }
    }

    /// Test for secure renegotiation extension (RFC 5746)
    async fn test_secure_renegotiation_extension(&self) -> Result<Option<bool>> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match crate::utils::network::connect_with_timeout(addr, DEFAULT_READ_TIMEOUT, None).await {
            Ok(mut stream) => {
                // Send ClientHello
                let client_hello = self.build_client_hello();
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; VULNERABILITY_CHECK_BUFFER_SIZE];
                match timeout(SHORT_TIMEOUT, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Look for renegotiation_info extension (0xff01)
                        let has_extension = self.has_renegotiation_info_extension(&buffer[..n]);
                        Ok(Some(has_extension))
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    /// Build ClientHello with renegotiation_info extension
    fn build_client_hello(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.push((VERSION_TLS_1_2 >> 8) as u8);
        hello.push((VERSION_TLS_1_2 & 0xff) as u8);

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version: TLS 1.2
        hello.push((VERSION_TLS_1_2 >> 8) as u8);
        hello.push((VERSION_TLS_1_2 & 0xff) as u8);

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

        // Renegotiation Info Extension
        hello.push((EXTENSION_RENEGOTIATION_INFO >> 8) as u8);
        hello.push((EXTENSION_RENEGOTIATION_INFO & 0xff) as u8);
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

    /// Build ClientHello WITHOUT renegotiation_info extension
    /// Used to test for insecure renegotiation (CVE-2009-3555)
    fn build_client_hello_without_reneg_info(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.push((VERSION_TLS_1_2 >> 8) as u8);
        hello.push((VERSION_TLS_1_2 & 0xff) as u8);

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version: TLS 1.2
        hello.push((VERSION_TLS_1_2 >> 8) as u8);
        hello.push((VERSION_TLS_1_2 & 0xff) as u8);

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

        // NO extensions - ClientHello without renegotiation_info

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

    /// Check if ServerHello response contains renegotiation_info extension (0xff01).
    ///
    /// Parses the TLS record structure to search only within the extensions section,
    /// avoiding false positives from matching bytes in random/certificate data.
    fn has_renegotiation_info_extension(&self, response: &[u8]) -> bool {
        const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

        // Minimum ServerHello: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) + 1 (sid len) = 44
        if response.len() < 44
            || response[0] != CONTENT_TYPE_HANDSHAKE
            || response[5] != HANDSHAKE_TYPE_SERVER_HELLO
        {
            return false;
        }

        // Skip TLS record header (5 bytes) + handshake header (4 bytes)
        // ServerHello: version(2) + random(32) + session_id_length(1)
        let sid_len_offset = 5 + 4 + 2 + 32;
        if sid_len_offset >= response.len() {
            return false;
        }
        let sid_len = response[sid_len_offset] as usize;

        // After session_id: cipher_suite(2) + compression(1) + extensions_length(2)
        let ext_len_offset = sid_len_offset + 1 + sid_len + 2 + 1;
        if ext_len_offset + 2 > response.len() {
            return false;
        }
        let ext_total =
            u16::from_be_bytes([response[ext_len_offset], response[ext_len_offset + 1]]) as usize;

        // Search only within the extensions section
        let ext_start = ext_len_offset + 2;
        let ext_end = (ext_start + ext_total).min(response.len());
        if ext_start >= ext_end {
            return false;
        }

        // Parse extensions structurally instead of using byte pattern scan
        // to avoid false positives from extension data containing 0xff01
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let ext_len = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
            if ext_type == EXTENSION_RENEGOTIATION_INFO {
                return true;
            }
            if pos + 4 + ext_len > ext_end {
                break;
            }
            pos += 4 + ext_len;
        }
        false
    }
}

/// Renegotiation test result
#[derive(Debug, Clone)]
pub struct RenegotiationTestResult {
    pub support: RenegotiationSupport,
    pub secure_extension: bool,
    pub vulnerable: bool,
    pub inconclusive: bool,
    /// Indicates the test result is inconclusive and requires manual verification.
    /// This is set when the server does not include renegotiation_info extension,
    /// which could mean either:
    /// - The server is vulnerable to CVE-2009-3555 (insecure renegotiation)
    /// - The server simply doesn't support renegotiation (modern, secure behavior)
    pub needs_verification: bool,
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
            inconclusive: false,
            needs_verification: false,
            details: "Test".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.secure_extension);
        assert!(!result.needs_verification);
    }

    #[test]
    fn test_renegotiation_result_insecure_details() {
        let result = RenegotiationTestResult {
            support: RenegotiationSupport::InsecureRenegotiation,
            secure_extension: false,
            vulnerable: true,
            inconclusive: false,
            needs_verification: false,
            details: "VULNERABLE: Insecure renegotiation enabled".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.details.contains("VULNERABLE"));
        assert!(!result.needs_verification);
    }

    #[test]
    fn test_renegotiation_result_needs_verification() {
        let result = RenegotiationTestResult {
            support: RenegotiationSupport::NotSupported,
            secure_extension: false,
            vulnerable: false,
            inconclusive: true,
            needs_verification: true,
            details: "Server does not include renegotiation_info extension".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.needs_verification);
    }

    #[tokio::test]
    async fn test_renegotiation_closed_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let target = Target::with_ips(
            "example.com".to_string(),
            addr.port(),
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");

        let tester = RenegotiationTester::new(&target);
        let result = tester.test().await.expect("test assertion should succeed");

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.needs_verification);
    }

    #[test]
    fn test_client_hello_with_renegotiation_info() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = RenegotiationTester::new(&target);
        let hello = tester.build_client_hello();

        assert!(hello.len() > 50);
        // Check for renegotiation_info extension (0xff01)
        let has_reneg_info = hello.windows(2).any(|w| w == [0xff, 0x01]);
        assert!(has_reneg_info);
    }

    #[test]
    fn test_has_renegotiation_info_extension_detects_absent() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);
        let response = vec![0x01, 0x02, 0x03, 0x04];
        assert!(!tester.has_renegotiation_info_extension(&response));
    }

    #[test]
    fn test_has_renegotiation_info_extension_detects_present() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        // Build a minimal valid ServerHello with renegotiation_info extension
        let mut response = vec![0u8; 0];
        // TLS record header: type=handshake(0x16), version=TLS1.2, length placeholder
        response.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        // Handshake header: type=ServerHello(0x02), length placeholder
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        // Server version: TLS 1.2
        response.extend_from_slice(&[0x03, 0x03]);
        // Server random: 32 bytes
        response.extend_from_slice(&[0x00; 32]);
        // Session ID length: 0
        response.push(0x00);
        // Cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256
        response.extend_from_slice(&[0x00, 0x9c]);
        // Compression method: none
        response.push(0x00);
        // Extensions length: 5 bytes (renegotiation_info ext)
        response.extend_from_slice(&[0x00, 0x05]);
        // Extension: renegotiation_info (0xff01), length=1, data=0x00
        response.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        // Patch record length
        let rec_len = (response.len() - 5) as u16;
        response[3] = (rec_len >> 8) as u8;
        response[4] = (rec_len & 0xff) as u8;
        // Patch handshake length
        let hs_len = (response.len() - 9) as u32;
        response[6] = ((hs_len >> 16) & 0xff) as u8;
        response[7] = ((hs_len >> 8) & 0xff) as u8;
        response[8] = (hs_len & 0xff) as u8;

        assert!(tester.has_renegotiation_info_extension(&response));
    }

    #[test]
    fn test_client_hello_record_length_matches() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);
        let hello = tester.build_client_hello();
        assert!(hello.len() > 10);

        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(rec_len, hello.len() - 5);
    }

    #[test]
    fn test_has_renegotiation_info_extension_partial_bytes() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);
        let response = vec![0xff];
        assert!(!tester.has_renegotiation_info_extension(&response));
    }
}
