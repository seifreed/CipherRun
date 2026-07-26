// BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
// CVE-2013-3587
//
// BREACH exploits HTTP compression to extract secrets from HTTPS responses
// by observing changes in response sizes when injecting known data.
// Similar to CRIME but targets HTTP-level compression instead of TLS compression.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

mod http_analysis;
mod result;

pub use result::BreachTestResult;

const BREACH_HTTP_RESPONSE_LIMIT: usize = 1024 * 1024;

/// BREACH vulnerability tester
pub struct BreachTester {
    target: Target,
    test_all_ips: bool,
}

impl BreachTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            test_all_ips: false,
        }
    }

    pub fn with_test_all_ips(mut self, test_all_ips: bool) -> Self {
        self.test_all_ips = test_all_ips;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(&self.target, self.test_all_ips)
    }

    /// Test for BREACH vulnerability
    pub async fn test(&self) -> Result<BreachTestResult> {
        // V11 fix: each sub-test returns an Option so the caller can distinguish
        // "probe completed and observed X" from "probe could not run". A single
        // TCP/TLS failure previously collapsed to `false` in every axis, making
        // an unreachable server report as "not vulnerable" (a false negative for
        // compliance dashboards).
        let compression = self.test_http_compression().await?;
        let dynamic = self.test_dynamic_content().await?;
        let sensitive = self.test_sensitive_data_reflection().await?;

        Ok(BreachTestResult::from_probe_results(
            compression,
            dynamic,
            sensitive,
        ))
    }

    /// Test if HTTP compression is enabled. Returns `None` when the probe could
    /// not complete (TCP/TLS error, empty response) — the caller treats this as
    /// inconclusive rather than "compression disabled".
    async fn test_http_compression(&self) -> Result<Option<bool>> {
        let mut result = Some(false);
        for addr in self.probe_addrs()? {
            result = result::merge_probe_bool(result, self.test_http_compression_addr(addr).await?);
            if result == Some(true) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_http_compression_addr(&self, addr: std::net::SocketAddr) -> Result<Option<bool>> {
        // First establish TLS connection
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || -> Result<Option<bool>> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::io::Write;

            // Certificate validity is irrelevant to whether the server enables HTTP
            // response compression; a verifying connector would fail the handshake
            // on bad-cert hosts and leave BREACH undetectable.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(mut ssl_stream) => {
                    // Send HTTP request with Accept-Encoding header
                    let request = format!(
                        "GET / HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Accept-Encoding: gzip, deflate\r\n\
                         User-Agent: Mozilla/5.0\r\n\
                         Connection: close\r\n\
                         \r\n",
                        hostname
                    );

                    ssl_stream.write_all(request.as_bytes())?;

                    // Read as much of the HTTP response as is available so a
                    // fragmented header block does not get misclassified.
                    let mut buffer = vec![0u8; 8192];
                    let n = Self::read_http_response(&mut ssl_stream, &mut buffer)?;

                    if n > 0 {
                        let bytes = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                            message: "BREACH compression response read length exceeded buffer"
                                .to_string(),
                        })?;
                        let response = String::from_utf8_lossy(bytes);
                        // Check for Content-Encoding header
                        let compressed = response
                            .lines()
                            .any(http_analysis::is_compressed_encoding_header);
                        Ok(Some(compressed))
                    } else {
                        Ok(None)
                    }
                }
                Err(_) => Ok(None),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("BREACH test blocking task failed: {}", e)))?
    }

    /// Test if server reflects user input (dynamic content)
    async fn test_dynamic_content(&self) -> Result<Option<bool>> {
        let mut result = Some(false);
        for addr in self.probe_addrs()? {
            result = result::merge_probe_bool(result, self.test_dynamic_content_addr(addr).await?);
            if result == Some(true) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_dynamic_content_addr(&self, addr: std::net::SocketAddr) -> Result<Option<bool>> {
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            // Certificate validity is irrelevant to HTTP response compression; a
            // verifying connector would leave BREACH undetectable on bad-cert hosts.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(mut ssl_stream) => {
                    use std::io::Write;

                    // Send request with unique marker in query string
                    let marker = "BREACH_TEST_MARKER_12345";
                    let request = format!(
                        "GET /?test={} HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Accept-Encoding: gzip, deflate\r\n\
                         Connection: close\r\n\
                         \r\n",
                        marker, hostname
                    );

                    ssl_stream.write_all(request.as_bytes())?;

                    // Read as much of the HTTP response as is available so a
                    // fragmented body does not get misclassified.
                    let mut buffer = vec![0u8; BREACH_HTTP_RESPONSE_LIMIT];
                    let n = Self::read_http_response(&mut ssl_stream, &mut buffer)?;

                    if n > 0 {
                        let bytes = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                            message: "BREACH dynamic response read length exceeded buffer"
                                .to_string(),
                        })?;
                        let response = String::from_utf8_lossy(bytes);
                        Ok(http_analysis::classify_dynamic_content_response(
                            &response, marker,
                        ))
                    } else {
                        Ok(None)
                    }
                }
                Err(_) => Ok(None),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("BREACH test blocking task failed: {}", e)))?
    }

    /// Test if sensitive data might be reflected in responses
    async fn test_sensitive_data_reflection(&self) -> Result<Option<bool>> {
        let mut result = Some(false);
        for addr in self.probe_addrs()? {
            result = result::merge_probe_bool(
                result,
                self.test_sensitive_data_reflection_addr(addr).await?,
            );
            if result == Some(true) {
                break;
            }
        }
        Ok(result)
    }

    async fn test_sensitive_data_reflection_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<Option<bool>> {
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let (hostname, use_sni) =
            crate::utils::network::openssl_hostname_and_sni(&self.target.hostname, None);
        tokio::task::spawn_blocking(move || -> Result<Option<bool>> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::io::Write;

            // Certificate validity is irrelevant to whether the server enables HTTP
            // response compression; a verifying connector would fail the handshake
            // on bad-cert hosts and leave BREACH undetectable.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector
                .configure()?
                .use_server_name_indication(use_sni)
                .connect(&hostname, std_stream)
            {
                Ok(mut ssl_stream) => {
                    // Send request with Cookie header
                    let request = format!(
                        "GET / HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Cookie: sessionid=test123; csrftoken=abc456\r\n\
                         Accept-Encoding: gzip, deflate\r\n\
                         Connection: close\r\n\
                         \r\n",
                        hostname
                    );

                    ssl_stream.write_all(request.as_bytes())?;

                    // Read as much of the HTTP response as is available so a
                    // fragmented body does not get misclassified.
                    let mut buffer = vec![0u8; BREACH_HTTP_RESPONSE_LIMIT];
                    let n = Self::read_http_response(&mut ssl_stream, &mut buffer)?;

                    if n > 0 {
                        let bytes = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                            message: "BREACH sensitive response read length exceeded buffer"
                                .to_string(),
                        })?;
                        let response = String::from_utf8_lossy(bytes);
                        // Check for sensitive data with more precise matching
                        let has_sensitive = http_analysis::detect_sensitive_patterns(&response);
                        Ok(Some(has_sensitive))
                    } else {
                        Ok(None)
                    }
                }
                Err(_) => Ok(None),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("BREACH test blocking task failed: {}", e)))?
    }

    fn read_http_response(
        ssl_stream: &mut openssl::ssl::SslStream<std::net::TcpStream>,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::io::{ErrorKind, Read};

        let mut total = 0;
        while total < buffer.len() {
            match ssl_stream.read(&mut buffer[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(err)
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Err(err)
                    if total > 0
                        && matches!(
                            err.kind(),
                            ErrorKind::TimedOut
                                | ErrorKind::WouldBlock
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Err(err) => return Err(err),
            }
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};
    use tokio_rustls::TlsAcceptor;

    fn localhost_target(port: u16) -> Target {
        Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .expect("target should build")
    }

    #[test]
    fn test_breach_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let single = BreachTester::new(target.clone()).probe_addrs().unwrap();
        let all = BreachTester::new(target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_breach_merge_keeps_inconclusive_over_false() {
        assert_eq!(result::merge_probe_bool(Some(false), None), None);
    }

    async fn spawn_fragmented_https_server() -> u16 {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().as_ref().to_vec());
        let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(key_der);

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls_stream) = acceptor.accept(stream).await
            {
                let mut request = [0u8; 4096];
                let _ = tls_stream.read(&mut request).await;
                let _ = tls_stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: g")
                    .await;
                sleep(Duration::from_millis(50)).await;
                let _ = tls_stream
                    .write_all(b"zip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = tls_stream.shutdown().await;
            }
        });

        port
    }

    #[test]
    fn test_detect_sensitive_patterns_is_case_insensitive() {
        assert!(http_analysis::detect_sensitive_patterns(
            r#"<input NAME="CSRFToken" value="abc">"#
        ));
        assert!(http_analysis::detect_sensitive_patterns(
            "HTTP/1.1 200 OK\r\nX-API-Key: abc\r\n\r\n"
        ));
        assert!(http_analysis::detect_sensitive_patterns(
            r#"<form><input Name='SessionId' value='abc'></form>"#
        ));
        assert!(http_analysis::detect_sensitive_patterns(
            "https://example.test/callback?Access_Token=abc"
        ));
    }

    #[test]
    fn test_detect_sensitive_patterns_ignores_header_names_in_body_text() {
        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDocs mention Set-Cookie: here";
        assert!(!http_analysis::detect_sensitive_patterns(response));
    }

    #[test]
    fn test_compression_header_requires_exact_encoding_token() {
        assert!(http_analysis::is_compressed_encoding_header(
            "Content-Encoding: gzip, br"
        ));
        assert!(http_analysis::is_compressed_encoding_header(
            "content-Encoding: gzip"
        ));
        assert!(!http_analysis::is_compressed_encoding_header(
            "Content-Encoding: bravo"
        ));
    }

    #[test]
    fn test_breach_inconclusive_when_probes_fail() {
        // V11 regression: an unreachable server must not be classified as
        // confirmed-not-vulnerable. Probe failures on all three axes surface
        // via `inconclusive=true`.
        let target = localhost_target(1);

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let result = rt.block_on(async {
            BreachTester::new(target)
                .test()
                .await
                .expect("probe should not error")
        });
        assert!(!result.vulnerable);
        assert!(
            result.inconclusive,
            "unreachable target must yield inconclusive BREACH verdict; got details={}",
            result.details
        );
    }

    #[test]
    fn test_dynamic_content_response_requires_http_status() {
        assert_eq!(
            http_analysis::classify_dynamic_content_response("not http", "marker"),
            None
        );
        assert_eq!(
            http_analysis::classify_dynamic_content_response(
                "HTTP/1.1 404 Not Found\r\n\r\n",
                "marker"
            ),
            Some(false)
        );
        assert_eq!(
            http_analysis::classify_dynamic_content_response(
                "HTTP/1.1 200 OK\r\n\r\nmarker",
                "marker"
            ),
            Some(true)
        );
    }

    #[test]
    fn test_dynamic_content_detects_marker_after_legacy_short_read_limit() {
        let marker = "BREACH_TEST_MARKER_12345";
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{}{}", "a".repeat(20_000), marker);

        assert_eq!(
            http_analysis::classify_dynamic_content_response(&response, marker),
            Some(true)
        );
    }

    #[test]
    fn test_sensitive_patterns_detect_token_after_legacy_short_read_limit() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}<input name=\"csrf\" value=\"abc\">",
            "a".repeat(20_000)
        );

        assert!(http_analysis::detect_sensitive_patterns(&response));
    }

    #[tokio::test]
    async fn test_http_compression_reads_fragmented_header_block() {
        let port = spawn_fragmented_https_server().await;
        let target = localhost_target(port);

        let tester = BreachTester::new(target);
        let compression = tester
            .test_http_compression()
            .await
            .expect("compression probe should not error");

        assert_eq!(compression, Some(true));
    }
}
