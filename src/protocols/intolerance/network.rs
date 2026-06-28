use super::IntoleranceTester;
use crate::Result;
use crate::constants::{ALERT_LEVEL_FATAL, BUFFER_SIZE_MAX_TLS_RECORD, CONTENT_TYPE_ALERT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

impl IntoleranceTester {
    pub(super) async fn send_client_hello(&self, client_hello: &[u8]) -> Result<Vec<u8>> {
        use crate::TlsError;

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

        let (mut reader, mut writer) = tokio::io::split(stream);
        writer.write_all(client_hello).await?;
        writer.flush().await?;

        let mut response = vec![0u8; BUFFER_SIZE_MAX_TLS_RECORD];
        let mut total = 0usize;
        loop {
            if total >= response.len() {
                break;
            }
            let n = match timeout(self.read_timeout, reader.read(&mut response[total..])).await {
                Ok(Ok(n)) => n,
                Ok(Err(source))
                    if total > 0
                        && matches!(
                            source.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::UnexpectedEof
                        ) =>
                {
                    break;
                }
                Ok(Err(source)) => return Err(TlsError::IoError { source }),
                Err(_) if total == 0 => {
                    return Err(TlsError::Timeout {
                        duration: Some(self.read_timeout),
                    })
                }
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            total += n;
        }

        if total == 0 {
            return Err(TlsError::Timeout {
                duration: Some(self.read_timeout),
            });
        }

        response.truncate(total);
        Ok(response)
    }

    pub(super) async fn send_and_read_alert(&self, client_hello: &[u8]) -> Result<Option<u8>> {
        match self.send_client_hello(client_hello).await {
            Ok(response) => {
                if response.first() == Some(&CONTENT_TYPE_ALERT) {
                    if response.len() < 7 {
                        return Err(crate::TlsError::ParseError {
                            message: "Truncated TLS alert record".to_string(),
                        });
                    }

                    let Some(alert_record_len) = response
                        .get(3..5)
                        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                        .map(u16::from_be_bytes)
                    else {
                        return Err(crate::TlsError::ParseError {
                            message: "Truncated TLS alert record length".to_string(),
                        });
                    };
                    let alert_record_len = alert_record_len as usize;
                    if alert_record_len != 2 {
                        return Err(crate::TlsError::ParseError {
                            message: format!(
                                "Malformed TLS alert record length: {}",
                                alert_record_len
                            ),
                        });
                    }

                    if response.len() != 5 + alert_record_len {
                        return Err(crate::TlsError::ParseError {
                            message: "TLS alert record length does not match buffer length"
                                .to_string(),
                        });
                    }
                }

                if response.first() == Some(&CONTENT_TYPE_ALERT)
                    && response.get(5) == Some(&ALERT_LEVEL_FATAL)
                {
                    Ok(response.get(6).copied())
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub(super) async fn extract_dh_prime(&self) -> Result<Option<String>> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            crate::utils::network::connect_with_timeout(addr, self.connect_timeout, None).await?;

        let std_stream =
            crate::utils::network::into_blocking_std_stream(stream, self.read_timeout)?;

        let hostname = self.target.hostname.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            // Certificate validity is irrelevant to the negotiated DH prime; a
            // verifying connector would fail the handshake at cert validation on
            // bad-cert hosts and leave a weak/known DH prime undetected.
            builder.set_verify(SslVerifyMode::NONE);
            builder.set_cipher_list("DHE:EDH:!aNULL:!eNULL")?;

            let connector = builder.build();
            match connector.connect(&hostname, std_stream) {
                Ok(ssl_stream) => {
                    let cipher = ssl_stream.ssl().current_cipher();
                    if let Some(c) = cipher
                        && c.name().contains("DHE")
                    {
                        // Extract the DH prime from the negotiated connection
                        let tmp_key = ssl_stream.ssl().tmp_key().map_err(|error| {
                            crate::TlsError::Other(format!(
                                "failed to extract temporary key: {error}"
                            ))
                        })?;
                        let dh = tmp_key.dh().map_err(|error| {
                            crate::TlsError::Other(format!(
                                "failed to interpret temporary key as DH: {error}"
                            ))
                        })?;
                        let hex_str = dh.prime_p().to_hex_str().map_err(|error| {
                            crate::TlsError::Other(format!("failed to encode DH prime: {error}"))
                        })?;
                        return Ok(Some(hex_str.to_string().to_uppercase()));
                    }
                    Ok(None)
                }
                Err(error) => Err(crate::TlsError::Other(format!(
                    "DH prime extraction handshake failed: {error}"
                ))),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("DH prime extraction task failed: {}", e)))?
    }

    pub(super) fn load_common_primes() -> Result<Vec<String>> {
        let primes_data = include_str!("../../../data/common-primes.txt");
        let mut primes = Vec::new();

        for line in primes_data.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            primes.push(trimmed.to_uppercase());
        }

        Ok(primes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::network::Target;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_send_and_read_alert_rejects_truncated_alert() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket
                    .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02])
                    .await;
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = IntoleranceTester::new(target).with_sni(Some("example.test".to_string()));

        let client_hello = tester
            .build_invalid_sni_client_hello()
            .expect("hello should build");
        let err = tester
            .send_and_read_alert(&client_hello)
            .await
            .expect_err("truncated alert should fail");
        assert!(err.to_string().contains("Truncated TLS alert record"));
    }

    #[tokio::test]
    async fn test_send_and_read_alert_rejects_malformed_alert_length() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket
                    .write_all(&[0x15, 0x03, 0x03, 0x00, 0x03, 0x02, 0x46])
                    .await;
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = IntoleranceTester::new(target).with_sni(Some("example.test".to_string()));

        let client_hello = tester
            .build_invalid_sni_client_hello()
            .expect("hello should build");
        let err = tester
            .send_and_read_alert(&client_hello)
            .await
            .expect_err("malformed alert length should fail");
        assert!(
            err.to_string()
                .contains("Malformed TLS alert record length")
        );
    }

    #[tokio::test]
    async fn test_send_and_read_alert_rejects_trailing_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket
                    .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00])
                    .await;
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = IntoleranceTester::new(target).with_sni(Some("example.test".to_string()));

        let client_hello = tester
            .build_invalid_sni_client_hello()
            .expect("hello should build");
        let err = tester
            .send_and_read_alert(&client_hello)
            .await
            .expect_err("alert with trailing bytes should fail");
        assert!(
            err.to_string()
                .contains("TLS alert record length does not match buffer length")
        );
    }

    #[tokio::test]
    async fn test_send_and_read_alert_handles_fragmented_alert() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 256];
                let _ = socket.read(&mut buf).await;
                socket
                    .write_all(&[0x15, 0x03, 0x03])
                    .await
                    .expect("write alert prefix");
                tokio::time::sleep(Duration::from_millis(20)).await;
                socket
                    .write_all(&[0x00, 0x02, 0x02, 0x46])
                    .await
                    .expect("write alert body");
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = IntoleranceTester::new(target).with_sni(Some("example.test".to_string()));

        let client_hello = tester
            .build_invalid_sni_client_hello()
            .expect("hello should build");
        let alert = tester
            .send_and_read_alert(&client_hello)
            .await
            .expect("fragmented alert should parse");
        assert_eq!(alert, Some(0x46));
    }

    #[tokio::test]
    async fn test_extract_dh_prime_handshake_failure_is_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let mut tester = IntoleranceTester::new(target).with_sni(Some("example.test".to_string()));
        tester.connect_timeout = Duration::from_secs(1);
        tester.read_timeout = Duration::from_secs(1);

        let err = tester
            .extract_dh_prime()
            .await
            .expect_err("handshake failure should not be reported as no DH prime");

        assert!(err.to_string().contains("handshake failed"));
    }
}
