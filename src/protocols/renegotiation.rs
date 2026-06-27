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
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
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
    fn parse_error(message: &str) -> crate::TlsError {
        crate::TlsError::ParseError {
            message: message.to_string(),
        }
    }

    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| Self::parse_error(context))
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let end = offset
            .checked_add(2)
            .ok_or_else(|| Self::parse_error(context))?;
        let bytes = data
            .get(offset..end)
            .ok_or_else(|| Self::parse_error(context))?;
        let bytes: [u8; 2] = bytes.try_into().map_err(|_| Self::parse_error(context))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn slice_range<'b>(
        data: &'b [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'b [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| Self::parse_error(context))?;
        data.get(start..end)
            .ok_or_else(|| Self::parse_error(context))
    }

    fn write_u16_at(data: &mut [u8], offset: usize, value: u16, context: &str) -> Result<()> {
        let bytes = value.to_be_bytes();
        Self::slice_range_mut(data, offset, 2, context)?.copy_from_slice(&bytes);
        Ok(())
    }

    fn u16_len(value: usize, context: &str) -> Result<u16> {
        u16::try_from(value).map_err(|_| Self::parse_error(context))
    }

    fn write_u24_at(data: &mut [u8], offset: usize, value: usize, context: &str) -> Result<()> {
        let value = u32::try_from(value).map_err(|_| Self::parse_error(context))?;
        if value > 0x00ff_ffff {
            return Err(Self::parse_error(context));
        }
        let bytes = value.to_be_bytes();
        Self::slice_range_mut(data, offset, 3, context)?.copy_from_slice(&bytes[1..]);
        Ok(())
    }

    fn slice_range_mut<'b>(
        data: &'b mut [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'b mut [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| Self::parse_error(context))?;
        data.get_mut(start..end)
            .ok_or_else(|| Self::parse_error(context))
    }

    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each renegotiation probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
    }

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        crate::utils::network::connect_with_starttls(addr, timeout, self.starttls, &hostname).await
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
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(stream) => {
                let std_stream =
                    crate::utils::network::into_blocking_std_stream(stream, DEFAULT_READ_TIMEOUT)?;

                let hostname = self.target.hostname.clone();
                tokio::task::spawn_blocking(move || -> Result<RenegotiationSupport> {
                    let mut builder = SslConnector::builder(SslMethod::tls())?;
                    // Certificate validity is irrelevant to RFC 5746 secure
                    // renegotiation support; a verifying connector would fail the
                    // handshake at cert validation on bad-cert hosts and falsely
                    // report NotSupported.
                    builder.set_verify(SslVerifyMode::NONE);

                    let connector = builder.build();

                    match connector.connect(&hostname, std_stream) {
                        Ok(_ssl_stream) => {
                            // OpenSSL client with RFC 5746 connected successfully
                            // Server supports secure renegotiation
                            Ok(RenegotiationSupport::SecureRenegotiation)
                        }
                        Err(_) => Ok(RenegotiationSupport::NotSupported),
                    }
                })
                .await
                .map_err(|e| crate::TlsError::Other(format!("renegotiation task failed: {}", e)))?
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

        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(mut stream) => {
                // Send ClientHello WITHOUT renegotiation_info extension
                let client_hello = self.build_client_hello_without_reneg_info()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; VULNERABILITY_CHECK_BUFFER_SIZE];
                match timeout(SHORT_TIMEOUT, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = Self::slice_range(&buffer, 0, n, "renegotiation response")?;
                        // Check if server responded with a valid ServerHello
                        // If server responds but WITHOUT renegotiation_info,
                        // it may be vulnerable
                        if response.first() == Some(&CONTENT_TYPE_HANDSHAKE) && response.len() > 5 {
                            // Check if server's ServerHello includes renegotiation_info
                            let has_reneg_info = self.has_renegotiation_info_extension(response)?;

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

        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(mut stream) => {
                // Send ClientHello
                let client_hello = self.build_client_hello()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello
                let mut buffer = vec![0u8; VULNERABILITY_CHECK_BUFFER_SIZE];
                match timeout(SHORT_TIMEOUT, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Look for renegotiation_info extension (0xff01)
                        let response = Self::slice_range(&buffer, 0, n, "renegotiation response")?;
                        let has_extension = self.has_renegotiation_info_extension(response)?;
                        Ok(Some(has_extension))
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    /// Build ClientHello with renegotiation_info extension
    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

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
        hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

        // Random (32 bytes)
        let mut random_byte = 0_u8;
        for _ in 0..32 {
            hello.push(random_byte);
            random_byte = random_byte.wrapping_add(13);
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
        hello.extend_from_slice(&EXTENSION_RENEGOTIATION_INFO.to_be_bytes());
        hello.push(0x00);
        hello.push(0x01); // Length: 1 byte
        hello.push(0x00); // Empty renegotiation info

        // Update extensions length
        let ext_len = hello.len() - ext_pos - 2;
        Self::write_u16_at(
            &mut hello,
            ext_pos,
            Self::u16_len(ext_len, "ClientHello extensions length")?,
            "ClientHello extensions length placeholder",
        )?;

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        Self::write_u24_at(
            &mut hello,
            hs_len_pos,
            hs_len,
            "ClientHello handshake length placeholder",
        )?;

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        Self::write_u16_at(
            &mut hello,
            len_pos,
            Self::u16_len(rec_len, "ClientHello record length")?,
            "ClientHello record length placeholder",
        )?;

        Ok(hello)
    }

    /// Build ClientHello WITHOUT renegotiation_info extension
    /// Used to test for insecure renegotiation (CVE-2009-3555)
    fn build_client_hello_without_reneg_info(&self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();

        // TLS Record: Handshake
        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

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
        hello.extend_from_slice(&VERSION_TLS_1_2.to_be_bytes());

        // Random (32 bytes)
        let mut random_byte = 0_u8;
        for _ in 0..32 {
            hello.push(random_byte);
            random_byte = random_byte.wrapping_add(13);
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
        Self::write_u24_at(
            &mut hello,
            hs_len_pos,
            hs_len,
            "ClientHello handshake length placeholder",
        )?;

        // Update record length
        let rec_len = hello.len() - len_pos - 2;
        Self::write_u16_at(
            &mut hello,
            len_pos,
            Self::u16_len(rec_len, "ClientHello record length")?,
            "ClientHello record length placeholder",
        )?;

        Ok(hello)
    }

    /// Check if ServerHello response contains renegotiation_info extension (0xff01).
    ///
    /// Parses the TLS record structure to search only within the extensions section,
    /// avoiding false positives from matching bytes in random/certificate data.
    fn has_renegotiation_info_extension(&self, response: &[u8]) -> Result<bool> {
        const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

        // Minimum ServerHello: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) + 1 (sid len) = 44
        if response.len() < 44
            || response.first() != Some(&CONTENT_TYPE_HANDSHAKE)
            || Self::read_u8_at(response, 5, "ServerHello handshake type")?
                != HANDSHAKE_TYPE_SERVER_HELLO
        {
            return Ok(false);
        }

        let record_len = Self::read_u16_at(response, 3, "TLS record length")? as usize;
        let record_end = 5 + record_len;
        if record_end > response.len() {
            return Err(crate::TlsError::ParseError {
                message: "TLS record length exceeds available data".to_string(),
            });
        }

        // Skip TLS record header (5 bytes) + handshake header (4 bytes)
        // ServerHello: version(2) + random(32) + session_id_length(1)
        let sid_len_offset = 5 + 4 + 2 + 32;
        if sid_len_offset >= record_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before session_id_len".to_string(),
            });
        }
        let sid_len =
            Self::read_u8_at(response, sid_len_offset, "ServerHello session_id_len")? as usize;

        // After session_id: cipher_suite(2) + compression(1) + extensions_length(2)
        let ext_len_offset = sid_len_offset + 1 + sid_len + 2 + 1;
        if ext_len_offset + 2 > record_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before extensions length".to_string(),
            });
        }
        let ext_total =
            Self::read_u16_at(response, ext_len_offset, "ServerHello extensions length")? as usize;

        // Search only within the extensions section
        let ext_start = ext_len_offset + 2;
        let ext_end = ext_start + ext_total;
        if ext_end > record_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension block extends beyond declared length".to_string(),
            });
        }
        if ext_end != record_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension block contains trailing bytes".to_string(),
            });
        }
        if ext_start >= ext_end {
            return Ok(false);
        }

        // Parse extensions structurally instead of using byte pattern scan
        // to avoid false positives from extension data containing 0xff01
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let ext_type = Self::read_u16_at(response, pos, "ServerHello extension type")?;
            let ext_len =
                Self::read_u16_at(response, pos + 2, "ServerHello extension length")? as usize;
            if pos + 4 + ext_len > ext_end {
                return Err(crate::TlsError::ParseError {
                    message: "ServerHello truncated in renegotiation extension data".to_string(),
                });
            }
            if ext_type == EXTENSION_RENEGOTIATION_INFO {
                return Ok(true);
            }
            pos += 4 + ext_len;
        }
        if pos != ext_end {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello extension block contains trailing bytes".to_string(),
            });
        }
        Ok(false)
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

    fn patch_test_server_hello_lengths(response: &mut [u8]) {
        let rec_len = u16::try_from(response.len() - 5)
            .expect("test ServerHello record length must fit in u16");
        RenegotiationTester::write_u16_at(
            response,
            3,
            rec_len,
            "test ServerHello record length placeholder",
        )
        .expect("test ServerHello should contain record length placeholder");

        let hs_len = response.len() - 9;
        RenegotiationTester::write_u24_at(
            response,
            6,
            hs_len,
            "test ServerHello handshake length placeholder",
        )
        .expect("test ServerHello should contain handshake length placeholder");
    }

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
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");

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
        assert!(!tester.has_renegotiation_info_extension(&response).unwrap());
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

        patch_test_server_hello_lengths(&mut response);

        assert!(tester.has_renegotiation_info_extension(&response).unwrap());
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
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");
        assert!(hello.len() > 10);

        let rec_len = RenegotiationTester::read_u16_at(&hello, 3, "ClientHello record length")
            .unwrap() as usize;
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
        assert!(!tester.has_renegotiation_info_extension(&response).unwrap());
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncated_extension_data() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        let mut response = vec![0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x2f]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x05, 0xff, 0x01, 0x00, 0x02, 0x01]);

        patch_test_server_hello_lengths(&mut response);

        let err = tester
            .has_renegotiation_info_extension(&response)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("truncated in renegotiation extension data")
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncated_extension_block() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record
            0x02, 0x00, 0x00, 0x00, // ServerHello
            0x03, 0x03,
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x06]); // claims 6 bytes of extensions
        response.extend_from_slice(&[0xff, 0x01, 0x00, 0x01]); // missing final data byte

        patch_test_server_hello_lengths(&mut response);

        let err = tester
            .has_renegotiation_info_extension(&response)
            .expect_err("truncated extension block should fail");
        assert!(
            err.to_string()
                .contains("extension block extends beyond declared length")
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_trailing_bytes_in_record() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record
            0x02, 0x00, 0x00, 0x00, // ServerHello
            0x03, 0x03,
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x00]); // no extensions
        response.push(0xff); // trailing byte inside the record

        patch_test_server_hello_lengths(&mut response);

        let err = tester
            .has_renegotiation_info_extension(&response)
            .expect_err("trailing bytes in ServerHello record should fail");
        assert!(
            err.to_string()
                .contains("ServerHello extension block contains trailing bytes")
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_partial_extension_header() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record
            0x02, 0x00, 0x00, 0x00, // ServerHello
            0x03, 0x03,
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x03, 0x00, 0x01, 0x00]); // partial extension header

        patch_test_server_hello_lengths(&mut response);

        let err = tester
            .has_renegotiation_info_extension(&response)
            .expect_err("partial extension header should fail");
        assert!(
            err.to_string()
                .contains("ServerHello extension block contains trailing bytes")
        );
    }
}
