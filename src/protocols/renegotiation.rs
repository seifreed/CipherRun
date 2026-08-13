// TLS Renegotiation Testing
// Tests for secure and insecure renegotiation support
// CVE-2009-3555 (insecure renegotiation vulnerability)

use crate::Result;
use crate::constants::{CONTENT_TYPE_HANDSHAKE, DEFAULT_READ_TIMEOUT, SHORT_TIMEOUT};
use crate::utils::network::Target;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

mod bytes;
mod client_hello;
mod model;
mod record;
mod result_analysis;
mod server_hello;

pub use model::{InsecureRenegotiationResult, RenegotiationSupport, RenegotiationTestResult};

/// Renegotiation tester
pub struct RenegotiationTester<'a> {
    target: &'a Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    starttls_server_mode: bool,
    test_all_ips: bool,
}

impl<'a> RenegotiationTester<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before each renegotiation probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
        server_mode: bool,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(self.target, self.test_all_ips)
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
        crate::utils::network::connect_with_starttls(
            addr,
            timeout,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
    }

    /// Test renegotiation support
    pub async fn test(&self) -> Result<RenegotiationTestResult> {
        // Test for secure renegotiation extension (RFC 5746)
        let secure_extension_probe = self.test_secure_renegotiation_extension().await?;

        // Test for insecure renegotiation (CVE-2009-3555)
        let insecure_result = self.test_insecure_renegotiation().await?;

        if secure_extension_probe.is_none() {
            return Ok(result_analysis::failed_secure_extension_probe(
                insecure_result,
            ));
        }

        let secure_extension = secure_extension_probe.unwrap_or(false);

        // Determine support level
        let support = if secure_extension {
            RenegotiationSupport::SecureRenegotiation
        } else {
            // secure_extension is false: server didn't echo RFC 5746 in ServerHello.
            // test_renegotiation_support() uses OpenSSL (which always includes RFC 5746)
            // and returns SecureRenegotiation whenever TLS works — but a successful TLS
            // handshake here doesn't imply the server truly supports RFC 5746 (we already
            // know it didn't echo the extension). Cap SecureRenegotiation to NotSupported.
            result_analysis::support_without_secure_extension(
                insecure_result,
                self.test_renegotiation_support().await?,
            )
        };

        Ok(result_analysis::final_result(
            support,
            secure_extension,
            insecure_result,
        ))
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
        let mut result = RenegotiationSupport::NotSupported;
        for addr in self.probe_addrs()? {
            result = result.merge(self.test_renegotiation_support_addr(addr).await?);
            if matches!(
                result,
                RenegotiationSupport::SecureRenegotiation
                    | RenegotiationSupport::InsecureRenegotiation
            ) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_renegotiation_support_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<RenegotiationSupport> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(stream) => {
                let std_stream =
                    crate::utils::network::into_blocking_std_stream(stream, DEFAULT_READ_TIMEOUT)?;

                let (hostname, use_sni) =
                    crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
                tokio::task::spawn_blocking(move || -> Result<RenegotiationSupport> {
                    let mut builder = SslConnector::builder(SslMethod::tls())?;
                    // Certificate validity is irrelevant to RFC 5746 secure
                    // renegotiation support; a verifying connector would fail the
                    // handshake at cert validation on bad-cert hosts and falsely
                    // report NotSupported.
                    builder.set_verify(SslVerifyMode::NONE);

                    let connector = builder.build();

                    match connector
                        .configure()?
                        .use_server_name_indication(use_sni)
                        .connect(&hostname, std_stream)
                    {
                        Ok(_ssl_stream) => {
                            // OpenSSL client with RFC 5746 connected successfully
                            // Server supports secure renegotiation
                            Ok(RenegotiationSupport::SecureRenegotiation)
                        }
                        Err(err) => {
                            if crate::utils::network::is_transport_anomaly_error(&err.to_string()) {
                                Ok(RenegotiationSupport::Inconclusive)
                            } else {
                                Ok(RenegotiationSupport::NotSupported)
                            }
                        }
                    }
                })
                .await
                .map_err(|e| crate::TlsError::Other(format!("renegotiation task failed: {}", e)))?
            }
            _ => Ok(RenegotiationSupport::Inconclusive),
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
        let mut result = InsecureRenegotiationResult::NotDetected;
        for addr in self.probe_addrs()? {
            result = result.merge(self.test_insecure_renegotiation_addr(addr).await?);
            if matches!(result, InsecureRenegotiationResult::Detected) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_insecure_renegotiation_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<InsecureRenegotiationResult> {
        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(mut stream) => {
                // Send ClientHello WITHOUT renegotiation_info extension
                let client_hello = client_hello::without_renegotiation_info()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello as a complete TLS record before parsing.
                match timeout(SHORT_TIMEOUT, record::read_tls_record(&mut stream)).await {
                    Ok(Ok(Some(response))) => {
                        // Check if server responded with a valid ServerHello
                        // If server responds but WITHOUT renegotiation_info,
                        // it may be vulnerable
                        if response.first() == Some(&CONTENT_TYPE_HANDSHAKE) && response.len() > 5 {
                            // Check if server's ServerHello includes renegotiation_info
                            let has_reneg_info =
                                match server_hello::has_renegotiation_info_extension(&response) {
                                    Ok(value) => value,
                                    Err(_) => return Ok(InsecureRenegotiationResult::Inconclusive),
                                };

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
        let mut result = Some(false);
        for addr in self.probe_addrs()? {
            result = model::merge_secure_extension_probe(
                result,
                self.test_secure_renegotiation_extension_addr(addr).await?,
            );
            if result == Some(true) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_secure_renegotiation_extension_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<Option<bool>> {
        match self.starttls_connect(addr, DEFAULT_READ_TIMEOUT).await {
            Ok(mut stream) => {
                // Send ClientHello
                let client_hello = client_hello::with_renegotiation_info()?;
                stream.write_all(&client_hello).await?;

                // Read ServerHello as a complete TLS record before parsing.
                match timeout(SHORT_TIMEOUT, record::read_tls_record(&mut stream)).await {
                    Ok(Ok(Some(buffer))) => {
                        // Look for renegotiation_info extension (0xff01)
                        let has_extension =
                            match server_hello::has_renegotiation_info_extension(&buffer) {
                                Ok(value) => value,
                                Err(_) => return Ok(None),
                            };
                        Ok(Some(has_extension))
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_support::example_com_loopback_target;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_tls_record_total_len_rejects_oversized_record() {
        let max_record_len = crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD
            - crate::constants::TLS_RECORD_HEADER_SIZE;
        let allowed = max_record_len as u16;
        let rejected = (max_record_len + 1) as u16;

        let allowed_header = [0x16, 0x03, 0x03, (allowed >> 8) as u8, allowed as u8];
        assert_eq!(
            record::total_len(&allowed_header).expect("length should parse"),
            Some(crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD)
        );

        let rejected_header = [0x16, 0x03, 0x03, (rejected >> 8) as u8, rejected as u8];
        assert_eq!(
            record::total_len(&rejected_header).expect("length should parse"),
            None
        );
    }

    #[test]
    fn test_renegotiation_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
        )
        .unwrap();

        let first = RenegotiationTester::new(&target).probe_addrs().unwrap();
        assert_eq!(first.len(), 1);

        let all = RenegotiationTester::new(&target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_renegotiation_merges_preserve_uncertainty() {
        assert_eq!(model::merge_secure_extension_probe(Some(false), None), None);
        assert_eq!(
            InsecureRenegotiationResult::NotDetected
                .merge(InsecureRenegotiationResult::Inconclusive),
            InsecureRenegotiationResult::Inconclusive
        );
        assert_eq!(
            RenegotiationSupport::NotSupported.merge(RenegotiationSupport::Inconclusive),
            RenegotiationSupport::Inconclusive
        );
    }

    fn patch_test_server_hello_lengths(response: &mut [u8]) {
        let rec_len = u16::try_from(response.len() - 5)
            .expect("test ServerHello record length must fit in u16");
        bytes::write_u16_at(
            response,
            3,
            rec_len,
            "test ServerHello record length placeholder",
        )
        .expect("test ServerHello should contain record length placeholder");

        let hs_len = response.len() - 9;
        bytes::write_u24_at(
            response,
            6,
            hs_len,
            "test ServerHello handshake length placeholder",
        )
        .expect("test ServerHello should contain handshake length placeholder");
    }

    fn test_server_hello(extensions: &[u8]) -> Vec<u8> {
        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record
            0x02, 0x00, 0x00, 0x00, // ServerHello
            0x03, 0x03,
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        response.extend_from_slice(extensions);
        patch_test_server_hello_lengths(&mut response);
        response
    }

    fn assert_renegotiation_info_error_contains(response: &[u8], expected: &str) {
        let err = server_hello::has_renegotiation_info_extension(response).expect_err(expected);
        assert!(err.to_string().contains(expected), "{err}");
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

        let target = example_com_loopback_target(addr.port());

        let tester = RenegotiationTester::new(&target);
        let result = tester.test().await.expect("test assertion should succeed");

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(result.needs_verification);
    }

    #[cfg_attr(windows, ignore = "transport error classification differs on Windows")]
    #[tokio::test]
    async fn test_renegotiation_support_transport_anomaly_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let target = example_com_loopback_target(addr.port());

        let tester = RenegotiationTester::new(&target);
        let support = tester
            .test_renegotiation_support()
            .await
            .expect("test assertion should succeed");

        assert_eq!(support, RenegotiationSupport::Inconclusive);
    }

    #[test]
    fn test_client_hello_with_renegotiation_info() {
        let hello = client_hello::with_renegotiation_info().expect("ClientHello should build");

        assert!(hello.len() > 50);
        // Check for renegotiation_info extension (0xff01)
        let has_reneg_info = hello.windows(2).any(|w| w == [0xff, 0x01]);
        assert!(has_reneg_info);
    }

    #[test]
    fn test_has_renegotiation_info_extension_detects_absent() {
        let response = vec![0x01, 0x02, 0x03, 0x04];
        assert!(server_hello::has_renegotiation_info_extension(&response).is_err());
    }

    #[test]
    fn test_has_renegotiation_info_extension_detects_present() {
        // Build a minimal valid ServerHello with renegotiation_info extension
        let response = test_server_hello(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        assert!(server_hello::has_renegotiation_info_extension(&response).unwrap());
    }

    #[test]
    fn test_has_renegotiation_info_extension_ignores_bytes_after_handshake() {
        let mut response = test_server_hello(&[]);

        let handshake_len = [response[6], response[7], response[8]];
        response.extend_from_slice(&[0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00]);
        let rec_len = u16::try_from(response.len() - 5 - 7)
            .expect("test ServerHello record length must fit in u16");
        bytes::write_u16_at(
            &mut response,
            3,
            rec_len,
            "test ServerHello record length placeholder",
        )
        .expect("test ServerHello should contain record length placeholder");
        response[6..9].copy_from_slice(&handshake_len);

        assert!(!server_hello::has_renegotiation_info_extension(&response).unwrap());
    }

    #[test]
    fn test_client_hello_record_length_matches() {
        let hello = client_hello::with_renegotiation_info().expect("ClientHello should build");
        assert!(hello.len() > 10);

        let rec_len = bytes::read_u16_at(&hello, 3, "ClientHello record length").unwrap() as usize;
        assert_eq!(rec_len, hello.len() - 5);
    }

    #[test]
    fn test_has_renegotiation_info_extension_partial_bytes() {
        let response = vec![0xff];
        assert!(server_hello::has_renegotiation_info_extension(&response).is_err());
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncated_serverhello() {
        let response = vec![
            0x16, 0x03, 0x03, 0x00, 0x1a, // handshake record claims 26 bytes
            0x02, 0x00, 0x00, 0x16, // ServerHello, handshake length 22
            0x03, 0x03, // version
            0x00, 0x00, 0x00, 0x00, // truncated before random/session_id
        ];

        assert_renegotiation_info_error_contains(
            &response,
            "truncated before minimum renegotiation extension length",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncated_extension_data() {
        let response = test_server_hello(&[0xff, 0x01, 0x00, 0x02, 0x01]);

        assert_renegotiation_info_error_contains(
            &response,
            "truncated in renegotiation extension data",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncated_extension_block() {
        let mut response = test_server_hello(&[0xff, 0x01, 0x00, 0x01]);
        response[48] = 0x06; // claims 6 bytes of extensions

        assert_renegotiation_info_error_contains(
            &response,
            "extension block extends beyond declared length",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_trailing_bytes_in_record() {
        let mut response = test_server_hello(&[]);
        response.push(0xff); // trailing byte inside the record

        patch_test_server_hello_lengths(&mut response);

        assert_renegotiation_info_error_contains(
            &response,
            "ServerHello extension block contains trailing bytes",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_partial_extension_header() {
        let response = test_server_hello(&[0x00, 0x01, 0x00]); // partial extension header

        assert_renegotiation_info_error_contains(
            &response,
            "ServerHello extension block contains trailing bytes",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_non_serverhello() {
        assert_renegotiation_info_error_contains(
            &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
            "handshake type",
        );
    }

    #[test]
    fn test_has_renegotiation_info_extension_rejects_truncation_before_extensions_length() {
        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record
            0x02, 0x00, 0x00, 0x00, // ServerHello
            0x03, 0x03,
        ];
        response.extend_from_slice(&[0x00; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        let record_len = (response.len() - 5) as u16;
        bytes::write_u16_at(
            &mut response,
            3,
            record_len,
            "test ServerHello record length placeholder",
        )
        .expect("test ServerHello should contain record length placeholder");
        let handshake_len = (response.len() - 9) as u32;
        response[6] = ((handshake_len >> 16) & 0xff) as u8;
        response[7] = ((handshake_len >> 8) & 0xff) as u8;
        response[8] = (handshake_len & 0xff) as u8;

        assert_renegotiation_info_error_contains(&response, "truncated before extensions length");
    }

    #[tokio::test]
    async fn test_renegotiation_probe_inconclusive_when_secure_extension_probe_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket1, _) = listener.accept().await.expect("accept first");
            let mut buf = vec![0u8; 4096];
            let _ = socket1.read(&mut buf).await.expect("read first hello");
            let malformed = [0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
            socket1
                .write_all(&malformed)
                .await
                .expect("write malformed");

            let (mut socket2, _) = listener.accept().await.expect("accept second");
            let _ = socket2.read(&mut buf).await.expect("read second hello");

            let response = test_server_hello(&[]);
            socket2
                .write_all(&response)
                .await
                .expect("write server hello");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = RenegotiationTester::new(&target);

        let result = tester.test().await.expect("probe should succeed");
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(result.inconclusive);
        assert!(matches!(result.support, RenegotiationSupport::Inconclusive));
        assert!(
            result
                .details
                .contains("secure extension probe did not complete")
        );
    }

    #[tokio::test]
    async fn test_secure_renegotiation_extension_handles_fragmented_server_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await.expect("read client hello");

            let response = test_server_hello(&[0xff, 0x01, 0x00, 0x01, 0x00]);

            socket
                .write_all(&response[..8])
                .await
                .expect("write first fragment");
            socket.flush().await.expect("flush first fragment");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            socket
                .write_all(&response[8..])
                .await
                .expect("write second fragment");
            socket.flush().await.expect("flush second fragment");
        });

        let target = example_com_loopback_target(addr.port());
        let tester = RenegotiationTester::new(&target);

        let secure = tester
            .test_secure_renegotiation_extension()
            .await
            .expect("probe should succeed");

        assert_eq!(secure, Some(true));
        server.await.expect("server task should complete");
    }
}
