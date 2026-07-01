use super::{
    GREASE_CIPHER_SUITES, GREASE_EXTENSIONS, GREASE_SUPPORTED_GROUPS, GreaseTestOutcome,
    GreaseTester,
};
use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

impl GreaseTester {
    /// Send raw TLS ClientHello and check server response
    pub(super) async fn send_client_hello(&self, client_hello: &[u8]) -> Result<GreaseTestOutcome> {
        use crate::error::TlsError;

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream =
            crate::utils::network::connect_with_timeout(addr, Duration::from_secs(10), None)
                .await?;

        // Send ClientHello
        if let Err(e) = timeout(
            crate::constants::TLS_HANDSHAKE_TIMEOUT,
            stream.write_all(client_hello),
        )
        .await
        {
            return Err(TlsError::IoError { source: e.into() });
        }

        // Read the full response so fragmented ServerHello/alert records do
        // not get misclassified as inconclusive.
        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = match Self::read_complete_response(&mut stream, &mut buffer).await {
            Ok(n) => n,
            Err(e) => return Err(TlsError::IoError { source: e }),
        };

        if n == 0 {
            // Connection closed - could be rejection or timeout
            return Ok(GreaseTestOutcome::Inconclusive(
                "Server closed connection without response".to_string(),
            ));
        }

        let response = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
            message: "GREASE response read length exceeded buffer".to_string(),
        })?;
        Ok(classify_grease_response(response))
    }

    /// Build ClientHello with GREASE cipher suites interleaved with valid ciphers
    pub(super) fn build_client_hello_with_grease_ciphers(&self) -> crate::Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);

        // Add valid cipher suites interleaved with GREASE values
        let valid_ciphers = [
            0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f, 0xcca8, 0xcca9,
        ];

        for (i, cipher) in valid_ciphers.iter().enumerate() {
            builder.add_cipher(*cipher);
            // Interleave GREASE cipher suites
            if let Some(grease_cipher) = GREASE_CIPHER_SUITES.get(i).copied() {
                builder.add_cipher(grease_cipher);
            }
        }

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname)?;
        }
        builder.add_supported_groups(&[0x001d, 0x0017, 0x0018])?;
        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ])?;
        builder.add_ec_point_formats();
        builder.add_renegotiation_info();
        builder.add_extended_master_secret();
        builder.add_session_ticket();

        builder
            .build()
            .map_err(|e| crate::TlsError::Other(format!("GREASE ClientHello build failed: {}", e)))
    }

    /// Build ClientHello with GREASE extensions
    pub(super) fn build_client_hello_with_grease_extensions(&self) -> crate::Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);

        builder.add_ciphers(&[0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f]);
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname)?;
        }
        builder.add_supported_groups(&[0x001d, 0x0017, 0x0018])?;
        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ])?;
        builder.add_ec_point_formats();
        builder.add_renegotiation_info();
        builder.add_extended_master_secret();
        builder.add_session_ticket();

        // Add GREASE extensions per RFC 8701
        for grease_ext in GREASE_EXTENSIONS.iter().take(5) {
            builder.add_extension(crate::protocols::Extension::new(
                *grease_ext,
                vec![
                    0x00,
                    0x01,
                    (*grease_ext >> 8) as u8,
                    (*grease_ext & 0xff) as u8,
                ],
            ));
        }

        builder
            .build()
            .map_err(|e| crate::TlsError::Other(format!("GREASE ClientHello build failed: {}", e)))
    }

    /// Build ClientHello with GREASE supported groups
    pub(super) fn build_client_hello_with_grease_groups(&self) -> crate::Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);

        builder.add_ciphers(&[0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f]);
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname)?;
        }

        // Add valid supported groups interleaved with GREASE values per RFC 8701
        let valid_groups = [0x001d, 0x0017, 0x0018];
        let grease_groups = GREASE_SUPPORTED_GROUPS.iter().take(3);
        let mut groups = Vec::new();
        for (valid, grease) in valid_groups.iter().zip(grease_groups) {
            groups.push(*valid);
            groups.push(*grease);
        }
        builder.add_supported_groups(&groups)?;

        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ])?;
        builder.add_ec_point_formats();
        builder.add_renegotiation_info();
        builder.add_extended_master_secret();
        builder.add_session_ticket();

        builder
            .build()
            .map_err(|e| crate::TlsError::Other(format!("GREASE ClientHello build failed: {}", e)))
    }

    /// Build ClientHello with all GREASE values combined
    pub(super) fn build_client_hello_combined_grease(&self) -> crate::Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);

        // Add ciphers with GREASE interleaved
        let valid_ciphers = [0xc02f, 0xc030, 0x009e];
        for (i, cipher) in valid_ciphers.iter().enumerate() {
            builder.add_cipher(*cipher);
            if let Some(grease_cipher) = GREASE_CIPHER_SUITES.get(i).copied() {
                builder.add_cipher(grease_cipher);
            }
        }

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname)?;
        }

        // Add supported groups with GREASE
        let mut groups = vec![0x001d, 0x0017];
        groups.extend(GREASE_SUPPORTED_GROUPS.iter().take(2).copied());
        builder.add_supported_groups(&groups)?;

        builder.add_signature_algorithms(&[(0x04, 0x03), (0x05, 0x03), (0x06, 0x03)])?;
        builder.add_ec_point_formats();
        builder.add_renegotiation_info();
        builder.add_extended_master_secret();
        builder.add_session_ticket();

        // Add GREASE extensions
        for grease_ext in GREASE_EXTENSIONS.iter().take(3) {
            builder.add_extension(crate::protocols::Extension::new(
                *grease_ext,
                vec![0x00, 0x01, 0x00],
            ));
        }

        builder
            .build()
            .map_err(|e| crate::TlsError::Other(format!("GREASE ClientHello build failed: {}", e)))
    }

    async fn read_complete_response(
        stream: &mut tokio::net::TcpStream,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::io::{Error, ErrorKind};

        let mut total = 0;
        while total < buffer.len() {
            match timeout(Duration::from_secs(10), stream.read(&mut buffer[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= TLS_RECORD_HEADER_SIZE {
                        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                        let record_total = TLS_RECORD_HEADER_SIZE
                            .checked_add(record_len)
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorKind::InvalidData,
                                    "GREASE TLS record length overflow",
                                )
                            })?;
                        if record_total > buffer.len() {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "GREASE TLS record length exceeds buffer",
                            ));
                        }
                        if total >= record_total {
                            break;
                        }
                    }
                }
                Ok(Err(err))
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Ok(Err(err))
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
                Ok(Err(err)) => return Err(err),
                Err(_) if total > 0 => break,
                Err(_) => return Ok(0),
            }
        }

        Ok(total)
    }

    /// Test with GREASE cipher suites
    pub(super) async fn test_grease_cipher_suites(&self) -> Result<GreaseTestOutcome> {
        let client_hello = self.build_client_hello_with_grease_ciphers()?;
        self.send_client_hello(&client_hello).await
    }

    /// Test with GREASE extensions
    pub(super) async fn test_grease_extensions(&self) -> Result<GreaseTestOutcome> {
        let client_hello = self.build_client_hello_with_grease_extensions()?;
        self.send_client_hello(&client_hello).await
    }

    /// Test with GREASE supported groups
    pub(super) async fn test_grease_supported_groups(&self) -> Result<GreaseTestOutcome> {
        let client_hello = self.build_client_hello_with_grease_groups()?;
        self.send_client_hello(&client_hello).await
    }

    /// Test with combined GREASE values
    pub(super) async fn test_combined_grease(&self) -> Result<GreaseTestOutcome> {
        let client_hello = self.build_client_hello_combined_grease()?;
        self.send_client_hello(&client_hello).await
    }
}

fn classify_grease_response(response: &[u8]) -> GreaseTestOutcome {
    if response.first() == Some(&0x15) {
        if response.len() < 7 {
            return GreaseTestOutcome::Inconclusive("Truncated TLS alert record".to_string());
        }

        let Some(alert_record_len) = response
            .get(3..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
        else {
            return GreaseTestOutcome::Inconclusive("Truncated TLS alert record".to_string());
        };
        if alert_record_len != 2 {
            return GreaseTestOutcome::Inconclusive(
                "Malformed TLS alert record length".to_string(),
            );
        }
        if response.len() != 5 + alert_record_len {
            return GreaseTestOutcome::Inconclusive(
                "TLS alert record length does not match buffer length".to_string(),
            );
        }

        let Some((&alert_level, rest)) = response.get(5..).and_then(|tail| tail.split_first())
        else {
            return GreaseTestOutcome::Inconclusive("Truncated TLS alert record".to_string());
        };
        let Some(&alert_description) = rest.first() else {
            return GreaseTestOutcome::Inconclusive("Truncated TLS alert record".to_string());
        };
        return match alert_description {
            0x46 | 0x28 | 0x2F => GreaseTestOutcome::Rejected,
            0x32 => GreaseTestOutcome::Inconclusive("Server returned internal error".to_string()),
            _ => GreaseTestOutcome::Inconclusive(format!(
                "Server returned TLS alert {} (level {})",
                alert_description, alert_level
            )),
        };
    }

    if response.first() == Some(&0x16) {
        return match crate::protocols::handshake::ServerHelloParser::parse(response) {
            Ok(_) => GreaseTestOutcome::Tolerated,
            Err(_) => {
                GreaseTestOutcome::Inconclusive("Truncated or malformed ServerHello".to_string())
            }
        };
    }

    GreaseTestOutcome::Inconclusive(format!(
        "Unexpected response (first bytes: {:02X?})",
        response.get(..response.len().min(10)).unwrap_or(response)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_classify_grease_response_rejects_malformed_alert_length() {
        let response = [0x15, 0x03, 0x03, 0x00, 0x03, 0x02, 0x46];
        match classify_grease_response(&response) {
            GreaseTestOutcome::Inconclusive(reason) => {
                assert!(reason.contains("Malformed TLS alert record length"));
            }
            _ => panic!("expected inconclusive"),
        }
    }

    #[test]
    fn test_classify_grease_response_rejects_trailing_bytes() {
        let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        match classify_grease_response(&response) {
            GreaseTestOutcome::Inconclusive(reason) => {
                assert!(reason.contains("record length does not match buffer length"));
            }
            _ => panic!("expected inconclusive"),
        }
    }

    #[test]
    fn test_classify_grease_response_rejects_truncated_serverhello() {
        let response = [0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
        match classify_grease_response(&response) {
            GreaseTestOutcome::Inconclusive(reason) => {
                assert!(reason.contains("ServerHello"));
            }
            _ => panic!("expected inconclusive"),
        }
    }

    #[tokio::test]
    async fn test_read_complete_response_handles_fragmented_alert() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
            let _ = socket.write_all(&response[..2]).await;
            sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&response[2..]).await;
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();

        let mut buffer = [0u8; 32];
        let n = GreaseTester::read_complete_response(&mut stream, &mut buffer)
            .await
            .expect("read should succeed");
        assert_eq!(n, 7);
        match classify_grease_response(&buffer[..n]) {
            GreaseTestOutcome::Rejected => {}
            other => panic!("expected rejected, got {other:?}"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_complete_response_accepts_large_record_without_peer_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let record_len = BUFFER_SIZE_DEFAULT as u16;
            let header = [
                CONTENT_TYPE_HANDSHAKE,
                0x03,
                0x03,
                (record_len >> 8) as u8,
                record_len as u8,
            ];
            socket.write_all(&header).await.unwrap();
            socket
                .write_all(&vec![0u8; BUFFER_SIZE_DEFAULT])
                .await
                .unwrap();
            sleep(Duration::from_secs(1)).await;
        });

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();

        let mut buffer = vec![0u8; BUFFER_SIZE_MAX_WITH_OVERHEAD];
        let n = GreaseTester::read_complete_response(&mut stream, &mut buffer)
            .await
            .expect("read should succeed");

        assert_eq!(n, TLS_RECORD_HEADER_SIZE + BUFFER_SIZE_DEFAULT);
        server.await.unwrap();
    }
}
