// BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
// CVE-2013-3587
//
// BREACH exploits HTTP compression to extract secrets from HTTPS responses
// by observing changes in response sizes when injecting known data.
// Similar to CRIME but targets HTTP-level compression instead of TLS compression.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

/// BREACH vulnerability tester
pub struct BreachTester {
    target: Target,
}

impl BreachTester {
    pub fn new(target: Target) -> Self {
        Self { target }
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

        let inconclusive = compression.is_none() || dynamic.is_none() || sensitive.is_none();
        let compression_enabled = compression.unwrap_or(false);
        let dynamic_content = dynamic.unwrap_or(false);
        let sensitive_data = sensitive.unwrap_or(false);

        // BREACH requires all three conditions simultaneously:
        // 1. HTTP compression enabled
        // 2. Dynamic content (user input reflected)
        // 3. Sensitive data in responses
        let vulnerable = !inconclusive && compression_enabled && dynamic_content && sensitive_data;

        let details = if inconclusive {
            "Inconclusive - one or more BREACH probes could not complete (TCP/TLS error or empty HTTP response)".to_string()
        } else if vulnerable {
            "Vulnerable to BREACH (CVE-2013-3587): HTTP compression enabled with dynamic content containing secrets".to_string()
        } else if compression_enabled {
            let mut reasons = Vec::new();
            if !dynamic_content {
                reasons.push("no dynamic content detected");
            }
            if !sensitive_data {
                reasons.push("no sensitive data reflection detected");
            }
            format!(
                "Partially vulnerable - HTTP compression enabled but {}",
                reasons.join(" and ")
            )
        } else {
            "Not vulnerable - HTTP compression not enabled".to_string()
        };

        Ok(BreachTestResult {
            vulnerable,
            inconclusive,
            compression_enabled,
            dynamic_content,
            sensitive_data_reflection: sensitive_data,
            details,
        })
    }

    /// Test if HTTP compression is enabled. Returns `None` when the probe could
    /// not complete (TCP/TLS error, empty response) — the caller treats this as
    /// inconclusive rather than "compression disabled".
    async fn test_http_compression(&self) -> Result<Option<bool>> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

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

        let hostname = self.target.hostname.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<bool>> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::io::Write;

            // Certificate validity is irrelevant to whether the server enables HTTP
            // response compression; a verifying connector would fail the handshake
            // on bad-cert hosts and leave BREACH undetectable.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector.connect(&hostname, std_stream) {
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
                        let compressed = response.lines().any(Self::is_compressed_encoding_header);
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
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let hostname = self.target.hostname.clone();
        tokio::task::spawn_blocking(move || {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            // Certificate validity is irrelevant to HTTP response compression; a
            // verifying connector would leave BREACH undetectable on bad-cert hosts.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector.connect(&hostname, std_stream) {
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
                    let mut buffer = vec![0u8; 16384];
                    let n = Self::read_http_response(&mut ssl_stream, &mut buffer)?;

                    if n > 0 {
                        let bytes = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                            message: "BREACH dynamic response read length exceeded buffer"
                                .to_string(),
                        })?;
                        let response = String::from_utf8_lossy(bytes);
                        Ok(Self::classify_dynamic_content_response(&response, marker))
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
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, TLS_HANDSHAKE_TIMEOUT)?;

        let hostname = self.target.hostname.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<bool>> {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            use std::io::Write;

            // Certificate validity is irrelevant to whether the server enables HTTP
            // response compression; a verifying connector would fail the handshake
            // on bad-cert hosts and leave BREACH undetectable.
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();

            match connector.connect(&hostname, std_stream) {
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
                    let mut buffer = vec![0u8; 16384];
                    let n = Self::read_http_response(&mut ssl_stream, &mut buffer)?;

                    if n > 0 {
                        let bytes = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                            message: "BREACH sensitive response read length exceeded buffer"
                                .to_string(),
                        })?;
                        let response = String::from_utf8_lossy(bytes);
                        // Check for sensitive data with more precise matching
                        let has_sensitive = Self::detect_sensitive_patterns(&response);
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

    /// Detect sensitive data patterns in HTTP response
    /// Uses precise matching to reduce false positives from comments/irrelevant text
    fn detect_sensitive_patterns(response: &str) -> bool {
        let response_lower = response.to_lowercase();
        let headers_lower = response_lower
            .split_once("\r\n\r\n")
            .or_else(|| response_lower.split_once("\n\n"))
            .map_or(response_lower.as_str(), |(headers, _)| headers);

        // Check Set-Cookie header (definitive indicator)
        if headers_lower.contains("set-cookie:") {
            return true;
        }

        // Check for CSRF tokens in HTML attributes (more precise)
        // Look for actual HTML attributes, not just the word "csrf"
        if response_lower.contains("csrf-token=")
            || response_lower.contains("csrf_token=")
            || response_lower.contains("_csrf=")
            || response_lower.contains("name=\"csrf")
            || response_lower.contains("name='csrf")
            || response_lower.contains("csrfmiddlewaretoken")
        {
            return true;
        }

        // Check for session tokens in specific contexts
        // Avoid matching "session" word in comments or unrelated text
        if response_lower.contains("phpsessid=")
            || response_lower.contains("jsessionid=")
            || response_lower.contains("asp.net_sessionid=")
            || response_lower.contains("sessionid=")
            || response_lower.contains("session_id=")
            || response_lower.contains("name=\"session")
            || response_lower.contains("name='session")
        {
            return true;
        }

        // Check for API tokens in headers or meta tags
        if headers_lower.contains("authorization:")
            || headers_lower.contains("x-auth-token:")
            || headers_lower.contains("x-api-key:")
            || response_lower.contains("api_key=")
            || response_lower.contains("access_token=")
            || response_lower.contains("name=\"token")
            || response_lower.contains("name='token")
        {
            return true;
        }

        false
    }

    fn is_compressed_encoding_header(line: &str) -> bool {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if !name.eq_ignore_ascii_case("Content-Encoding") {
            return false;
        }

        value.split(',').map(str::trim).any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "gzip" | "deflate" | "br" | "zstd" | "compress"
            )
        })
    }

    fn classify_dynamic_content_response(response: &str, marker: &str) -> Option<bool> {
        let status_line = response.strip_prefix("HTTP/")?;
        let status_code = status_line
            .split_once(' ')
            .map(|x| x.1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|code| code.parse::<u16>().ok())?;

        if (200..300).contains(&status_code) {
            Some(response.contains(marker))
        } else {
            Some(false)
        }
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

/// BREACH test result
#[derive(Debug, Clone)]
pub struct BreachTestResult {
    pub vulnerable: bool,
    /// True when one or more sub-probes could not complete (TCP/TLS failure
    /// or empty HTTP response). Prevents reporting unreachable servers as
    /// confirmed-not-vulnerable.
    pub inconclusive: bool,
    pub compression_enabled: bool,
    pub dynamic_content: bool,
    pub sensitive_data_reflection: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};
    use tokio_rustls::TlsAcceptor;

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
    fn test_breach_result_creation() {
        let result = BreachTestResult {
            vulnerable: true,
            compression_enabled: true,
            dynamic_content: true,
            sensitive_data_reflection: true,
            inconclusive: false,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.compression_enabled);
        assert!(result.dynamic_content);
        assert!(result.sensitive_data_reflection);
    }

    #[test]
    fn test_breach_not_vulnerable_no_compression() {
        let result = BreachTestResult {
            vulnerable: false,
            compression_enabled: false,
            dynamic_content: true,
            sensitive_data_reflection: true,
            inconclusive: false,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        // Even with dynamic content and sensitive data, not vulnerable without compression
    }

    #[test]
    fn test_breach_partial_vulnerability() {
        let result = BreachTestResult {
            vulnerable: false,
            compression_enabled: true,
            dynamic_content: false,
            sensitive_data_reflection: true,
            inconclusive: false,
            details: "Partial".to_string(),
        };
        // Needs all three conditions for full vulnerability
        assert!(!result.vulnerable);
        assert!(result.compression_enabled);
    }

    #[test]
    fn test_detect_sensitive_patterns_is_case_insensitive() {
        assert!(BreachTester::detect_sensitive_patterns(
            r#"<input NAME="CSRFToken" value="abc">"#
        ));
        assert!(BreachTester::detect_sensitive_patterns(
            "HTTP/1.1 200 OK\r\nX-API-Key: abc\r\n\r\n"
        ));
        assert!(BreachTester::detect_sensitive_patterns(
            r#"<form><input Name='SessionId' value='abc'></form>"#
        ));
        assert!(BreachTester::detect_sensitive_patterns(
            "https://example.test/callback?Access_Token=abc"
        ));
    }

    #[test]
    fn test_detect_sensitive_patterns_ignores_header_names_in_body_text() {
        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDocs mention Set-Cookie: here";
        assert!(!BreachTester::detect_sensitive_patterns(response));
    }

    #[test]
    fn test_compression_header_requires_exact_encoding_token() {
        assert!(BreachTester::is_compressed_encoding_header(
            "Content-Encoding: gzip, br"
        ));
        assert!(BreachTester::is_compressed_encoding_header(
            "content-Encoding: gzip"
        ));
        assert!(!BreachTester::is_compressed_encoding_header(
            "Content-Encoding: bravo"
        ));
    }

    #[test]
    fn test_breach_inconclusive_when_probes_fail() {
        // V11 regression: an unreachable server must not be classified as
        // confirmed-not-vulnerable. Probe failures on all three axes surface
        // via `inconclusive=true`.
        use std::net::{IpAddr, Ipv4Addr};
        let target = Target::with_ips(
            "localhost".to_string(),
            1,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .expect("target should build");

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
            BreachTester::classify_dynamic_content_response("not http", "marker"),
            None
        );
        assert_eq!(
            BreachTester::classify_dynamic_content_response(
                "HTTP/1.1 404 Not Found\r\n\r\n",
                "marker"
            ),
            Some(false)
        );
        assert_eq!(
            BreachTester::classify_dynamic_content_response(
                "HTTP/1.1 200 OK\r\n\r\nmarker",
                "marker"
            ),
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_http_compression_reads_fragmented_header_block() {
        let port = spawn_fragmented_https_server().await;
        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .expect("target should build");

        let tester = BreachTester::new(target);
        let compression = tester
            .test_http_compression()
            .await
            .expect("compression probe should not error");

        assert_eq!(compression, Some(true));
    }
}
