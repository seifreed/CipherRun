use super::{
    RevocationChecker, RevocationStatus, http::ValidatedRevocationHttp,
    http::validate_revocation_http_url, parse_x509_der_exact,
};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use tokio::time::timeout;
use x509_parser::prelude::*;
use x509_parser::revocation_list::CertificateRevocationList;

fn log_crl_completed(status: RevocationStatus, duration_ms: u64) {
    let outcome = match status {
        RevocationStatus::Good => "good",
        RevocationStatus::Revoked => "revoked",
        RevocationStatus::Unknown => "unknown",
        RevocationStatus::Error => "error",
        RevocationStatus::NotChecked => "not_checked",
    };

    if status == RevocationStatus::Revoked {
        tracing::warn!(
            event_name = "certificate.revocation.crl.completed",
            outcome,
            duration_ms,
            "CRL revocation check completed"
        );
    } else {
        tracing::debug!(
            event_name = "certificate.revocation.crl.completed",
            outcome,
            duration_ms,
            "CRL revocation check completed"
        );
    }
}

fn parse_crl_der_exact(der: &[u8]) -> Result<CertificateRevocationList<'_>> {
    let (rest, crl) = CertificateRevocationList::from_der(der).map_err(|e| {
        crate::error::TlsError::ParseError {
            message: format!("Failed to parse CRL: {:?}", e),
        }
    })?;
    if !rest.is_empty() {
        return Err(crate::error::TlsError::ParseError {
            message: format!("CRL DER contains {} trailing byte(s)", rest.len()),
        });
    }
    Ok(crl)
}

fn is_http_crl_url(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
    })
}

impl RevocationChecker {
    /// Extract CRL distribution point URL from certificate
    pub(crate) fn extract_crl_url(&self, cert: &CertificateInfo) -> Result<Option<String>> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(None);
        }

        let parsed_cert = parse_x509_der_exact(&cert.der_bytes, "certificate")?;

        // Look for CRL Distribution Points extension
        if let Some(ext) = parsed_cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            .map_err(|error| crate::TlsError::ParseError {
                message: format!("Failed to parse CRL Distribution Points extension: {error}"),
            })?
        {
            match ext.parsed_extension() {
                ParsedExtension::CRLDistributionPoints(crl_dp) => {
                    for point in &crl_dp.points {
                        if let Some(dist_point) = &point.distribution_point
                            && let x509_parser::extensions::DistributionPointName::FullName(names) =
                                dist_point
                        {
                            for name in names {
                                if let GeneralName::URI(uri) = name
                                    && is_http_crl_url(uri)
                                {
                                    return Ok(Some(uri.to_string()));
                                }
                            }
                        }
                    }
                }
                other => {
                    return Err(crate::TlsError::ParseError {
                        message: format!(
                            "Failed to parse CRL Distribution Points extension: {other:?}"
                        ),
                    });
                }
            }
        }

        Ok(None)
    }

    /// Check CRL revocation status
    pub(crate) async fn check_crl(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
        crl_url: &str,
    ) -> Result<RevocationStatus> {
        let started = std::time::Instant::now();
        // Download CRL. The URL comes from the untrusted certificate, so validate
        // and pin resolution before making the request.
        let validated = validate_revocation_http_url(crl_url, self.check_timeout).await?;
        self.check_crl_with_validated_http(cert, issuer, validated, started)
            .await
    }

    async fn check_crl_with_validated_http(
        &self,
        cert: &CertificateInfo,
        issuer: Option<&CertificateInfo>,
        validated: ValidatedRevocationHttp,
        started: std::time::Instant,
    ) -> Result<RevocationStatus> {
        let response = timeout(
            self.check_timeout,
            validated.client.get(validated.url).send(),
        )
        .await??;

        if !response.status().is_success() {
            return Err(crate::error::TlsError::Other(format!(
                "CRL download failed: {}",
                response.status()
            )));
        }

        // Cap the body: the CRL distribution point URL comes from the (untrusted)
        // certificate being scanned, so an unbounded read is an OOM vector. Large
        // CAs publish multi-MB CRLs, so the limit is generous but finite.
        const MAX_CRL_BYTES: u64 = 64 * 1024 * 1024;
        let crl_bytes =
            crate::utils::http::read_response_body_capped(response, MAX_CRL_BYTES, "CRL").await?;

        // Parse CRL
        let crl = parse_crl_der_exact(&crl_bytes)?;

        // SECURITY: verify the CRL signature against the issuing CA before trusting
        // its revoked-serial list. Over the plain-HTTP CRL distribution point a
        // forged/MITM'd CRL could omit a revoked serial and yield a false "Good".
        let issuer = issuer.ok_or_else(|| {
            crate::error::TlsError::Other(
                "Issuer certificate required to verify CRL signature".into(),
            )
        })?;
        let issuer_cert = parse_x509_der_exact(&issuer.der_bytes, "issuer certificate")?;
        if crl.verify_signature(issuer_cert.public_key()).is_err() {
            tracing::warn!(
                event_name = "certificate.revocation.crl.signature.failed",
                error_type = "signature_verification",
                "CRL signature verification failed; not trusting it"
            );
            return Err(crate::error::TlsError::Other(
                "CRL signature verification failed".into(),
            ));
        }

        // Validate CRL is not expired (check nextUpdate)
        if let Some(next_update) = crl.next_update() {
            let now = ASN1Time::now();
            if now > next_update {
                tracing::warn!(
                    event_name = "certificate.revocation.crl.expired",
                    error_type = "expired_crl",
                    "CRL has expired; not trusting it"
                );
                return Err(crate::error::TlsError::Other(format!(
                    "CRL has expired (nextUpdate: {:?})",
                    next_update
                )));
            }
        }

        // Check if certificate serial number is in revoked list
        let parsed_cert = parse_x509_der_exact(&cert.der_bytes, "certificate")?;

        let cert_serial = &parsed_cert.serial;

        // Check each revoked certificate
        let status = if crl
            .iter_revoked_certificates()
            .any(|revoked_cert| &revoked_cert.user_certificate == cert_serial)
        {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Good
        };
        log_crl_completed(
            status,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::revocation::cert_with_raw_extension_der;
    use std::time::Instant;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use url::Url;

    async fn local_crl_responder(
        response: Option<Vec<u8>>,
    ) -> (ValidatedRevocationHttp, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("loopback listener should have an address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("CRL client should connect");
            let mut stream = BufReader::new(stream);
            let mut line = Vec::new();
            loop {
                line.clear();
                let read = stream
                    .read_until(b'\n', &mut line)
                    .await
                    .expect("CRL request headers should be readable");
                if read == 0 || line == b"\r\n" {
                    break;
                }
            }

            if let Some(response) = response {
                stream
                    .get_mut()
                    .write_all(&response)
                    .await
                    .expect("CRL response should be writable");
            }
        });
        let url =
            Url::parse(&format!("http://{address}/root.crl")).expect("loopback URL should parse");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client should build");
        (ValidatedRevocationHttp { url, client }, task)
    }

    fn minimal_crl_der() -> Vec<u8> {
        vec![
            0x30, 0x35, 0x30, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x00, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0',
            b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x02, 0x00, 0x00,
        ]
    }

    fn crl_distribution_points_with_uri(uri: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            assert!(
                value.len() < 128,
                "test DER helper only supports short lengths"
            );
            let mut encoded = vec![tag, value.len() as u8];
            encoded.extend_from_slice(value);
            encoded
        }

        let uri = tlv(0x86, uri);
        let full_name = tlv(0xa0, &uri);
        let distribution_point = tlv(0xa0, &full_name);
        let point = tlv(0x30, &distribution_point);
        tlv(0x30, &point)
    }

    #[test]
    fn extract_crl_url_selects_http_uri_from_distribution_point() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der(
            "2.5.29.31",
            &crl_distribution_points_with_uri(b"https://crl.example.test/root.crl"),
        );

        assert_eq!(
            checker.extract_crl_url(&cert).unwrap().as_deref(),
            Some("https://crl.example.test/root.crl")
        );
    }

    #[test]
    fn extract_crl_url_ignores_non_http_uri() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der(
            "2.5.29.31",
            &crl_distribution_points_with_uri(b"ldap://crl.example.test/root.crl"),
        );

        assert!(checker.extract_crl_url(&cert).unwrap().is_none());
    }

    #[test]
    fn crl_url_validation_accepts_only_http_without_credentials() {
        assert!(is_http_crl_url("http://crl.example.test/root.crl"));
        assert!(is_http_crl_url("https://crl.example.test/root.crl"));
        assert!(!is_http_crl_url("ldap://crl.example.test/root.crl"));
        assert!(!is_http_crl_url(
            "https://user:secret@crl.example.test/root.crl"
        ));
        assert!(!is_http_crl_url("not a URL"));
    }

    #[test]
    fn extract_crl_url_ignores_empty_certificate_der() {
        let checker = RevocationChecker::new(false);
        let certificate = CertificateInfo {
            der_bytes: Vec::new(),
            ..Default::default()
        };

        assert!(checker.extract_crl_url(&certificate).unwrap().is_none());
    }

    #[test]
    fn extract_crl_url_returns_none_when_distribution_points_are_absent() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der("1.2.3.4", b"\x05\x00");

        assert!(checker.extract_crl_url(&cert).unwrap().is_none());
    }

    #[test]
    fn crl_completion_events_report_structured_outcomes_and_duration() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct Output(Arc<Mutex<Vec<u8>>>);
        struct Writer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for Output {
            type Writer = Writer;

            fn make_writer(&'a self) -> Self::Writer {
                Writer(self.0.clone())
            }
        }

        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_crl_completed(RevocationStatus::Good, 17);
            log_crl_completed(RevocationStatus::Revoked, 23);
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["level"], "DEBUG");
        assert_eq!(
            events[0]["fields"]["event_name"],
            "certificate.revocation.crl.completed"
        );
        assert_eq!(events[0]["fields"]["outcome"], "good");
        assert_eq!(events[0]["fields"]["duration_ms"], 17);
        assert_eq!(events[1]["level"], "WARN");
        assert_eq!(events[1]["fields"]["outcome"], "revoked");
        assert_eq!(events[1]["fields"]["duration_ms"], 23);
    }

    #[test]
    fn test_extract_crl_url_empty_der() {
        let checker = RevocationChecker::new(true);
        let cert = CertificateInfo {
            der_bytes: vec![],
            ..Default::default()
        };

        assert!(checker.extract_crl_url(&cert).unwrap().is_none());
    }

    #[test]
    fn test_extract_crl_url_invalid_der_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo {
            der_bytes: vec![0x01, 0x02, 0x03],
            ..Default::default()
        };

        let err = checker.extract_crl_url(&cert).unwrap_err();
        assert!(format!("{err}").contains("Failed to parse certificate"));
    }

    #[test]
    fn test_extract_crl_url_malformed_distribution_points_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der("2.5.29.31", b"\x05\x00");

        let err = checker.extract_crl_url(&cert).unwrap_err();
        assert!(format!("{err}").contains("CRL Distribution Points extension"));
    }

    #[test]
    fn test_is_http_crl_url_rejects_http_prefix_schemes() {
        assert!(is_http_crl_url("http://example.com/root.crl"));
        assert!(is_http_crl_url("https://example.com/root.crl"));
        assert!(is_http_crl_url("HTTP://example.com/root.crl"));
        assert!(is_http_crl_url("HTTPS://example.com/root.crl"));
        assert!(!is_http_crl_url("httpx://example.com/root.crl"));
        assert!(!is_http_crl_url("ftp://example.com/root.crl"));
        assert!(!is_http_crl_url("http://"));
        assert!(!is_http_crl_url("https://user:pass@example.com/root.crl"));
    }

    #[tokio::test]
    async fn test_check_crl_rejects_private_url_before_request() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo::default();

        let err = checker
            .check_crl(&cert, None, "http://127.0.0.1/root.crl")
            .await
            .expect_err("private CRL URL should be rejected before request");

        assert!(format!("{err}").contains("private/internal IP"));
    }

    #[test]
    fn test_parse_crl_der_exact_rejects_trailing_bytes() {
        let mut crl = minimal_crl_der();
        assert!(parse_crl_der_exact(&crl).is_ok());

        crl.push(0x00);
        let err = parse_crl_der_exact(&crl).expect_err("trailing CRL bytes should fail");
        assert!(format!("{err}").contains("trailing byte"));
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_rejects_responder_status() {
        let checker = RevocationChecker::new(false);
        let (validated, responder) = local_crl_responder(Some(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        ))
        .await;

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                None,
                validated,
                Instant::now(),
            )
            .await
            .expect_err("non-success CRL status should fail");
        assert!(error.to_string().contains("CRL download failed: 503"));
        responder.await.expect("responder task should finish");
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_rejects_invalid_der() {
        let checker = RevocationChecker::new(false);
        let (validated, responder) = local_crl_responder(Some(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\xff".to_vec(),
        ))
        .await;

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                None,
                validated,
                Instant::now(),
            )
            .await
            .expect_err("malformed CRL body should fail parsing");
        assert!(error.to_string().contains("Failed to parse CRL"));
        responder.await.expect("responder task should finish");
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_rejects_oversized_body() {
        let checker = RevocationChecker::new(false);
        let (validated, responder) = local_crl_responder(Some(
            b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n".to_vec(),
        ))
        .await;

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                None,
                validated,
                Instant::now(),
            )
            .await
            .expect_err("oversized CRL body should fail");
        assert!(error.to_string().contains("CRL response too large"));
        responder.await.expect("responder task should finish");
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_requires_issuer_after_parse() {
        let checker = RevocationChecker::new(false);
        let crl = minimal_crl_der();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            crl.len()
        )
        .into_bytes();
        response.extend_from_slice(&crl);
        let (validated, responder) = local_crl_responder(Some(response)).await;

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                None,
                validated,
                Instant::now(),
            )
            .await
            .expect_err("CRL validation requires an issuer certificate");
        assert!(error.to_string().contains("Issuer certificate required"));
        responder.await.expect("responder task should finish");
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_rejects_invalid_signature() {
        let checker = RevocationChecker::new(false);
        let crl = minimal_crl_der();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            crl.len()
        )
        .into_bytes();
        response.extend_from_slice(&crl);
        let (validated, responder) = local_crl_responder(Some(response)).await;
        let issuer = cert_with_raw_extension_der("1.2.3.4", b"\x05\x00");

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                Some(&issuer),
                validated,
                Instant::now(),
            )
            .await
            .expect_err("invalid CRL signature should not be trusted");
        assert!(
            error
                .to_string()
                .contains("CRL signature verification failed")
        );
        responder.await.expect("responder task should finish");
    }

    #[tokio::test]
    async fn check_crl_with_validated_http_reports_transport_failure() {
        let checker = RevocationChecker::new(false);
        let (validated, responder) = local_crl_responder(None).await;

        let error = checker
            .check_crl_with_validated_http(
                &CertificateInfo::default(),
                None,
                validated,
                Instant::now(),
            )
            .await
            .expect_err("closed CRL connection should fail");
        assert!(error.to_string().contains("error"));
        responder.await.expect("responder task should finish");
    }
}
