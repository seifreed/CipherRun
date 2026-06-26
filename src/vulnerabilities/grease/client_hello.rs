use super::{
    GREASE_CIPHER_SUITES, GREASE_EXTENSIONS, GREASE_SUPPORTED_GROUPS, GreaseTestOutcome,
    GreaseTester,
};
use crate::Result;
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

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(TlsError::IoError { source: e }),
            Err(_) => {
                // Timeout could mean the server is silently dropping the connection
                return Ok(GreaseTestOutcome::Inconclusive(
                    "Connection timeout after sending ClientHello".to_string(),
                ));
            }
        };

        if n == 0 {
            // Connection closed - could be rejection or timeout
            return Ok(GreaseTestOutcome::Inconclusive(
                "Server closed connection without response".to_string(),
            ));
        }

        Ok(classify_grease_response(&buffer[..n]))
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
            if i < GREASE_CIPHER_SUITES.len() {
                builder.add_cipher(GREASE_CIPHER_SUITES[i]);
            }
        }

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname);
        }
        builder.add_supported_groups(&[0x001d, 0x0017, 0x0018]);
        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ]);
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
            builder.add_sni(&hostname);
        }
        builder.add_supported_groups(&[0x001d, 0x0017, 0x0018]);
        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ]);
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
            builder.add_sni(&hostname);
        }

        // Add valid supported groups interleaved with GREASE values per RFC 8701
        let valid_groups = [0x001d, 0x0017, 0x0018];
        let grease_groups = &GREASE_SUPPORTED_GROUPS[..3];
        let mut groups = Vec::new();
        for (i, valid) in valid_groups.iter().enumerate() {
            groups.push(*valid);
            if i < grease_groups.len() {
                groups.push(grease_groups[i]);
            }
        }
        builder.add_supported_groups(&groups);

        builder.add_signature_algorithms(&[
            (0x04, 0x03),
            (0x05, 0x03),
            (0x06, 0x03),
            (0x08, 0x04),
            (0x08, 0x05),
            (0x08, 0x06),
        ]);
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
            if i < GREASE_CIPHER_SUITES.len() {
                builder.add_cipher(GREASE_CIPHER_SUITES[i]);
            }
        }

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            builder.add_sni(&hostname);
        }

        // Add supported groups with GREASE
        let mut groups = vec![0x001d, 0x0017];
        groups.extend_from_slice(&GREASE_SUPPORTED_GROUPS[..2]);
        builder.add_supported_groups(&groups);

        builder.add_signature_algorithms(&[(0x04, 0x03), (0x05, 0x03), (0x06, 0x03)]);
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

        let alert_record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        if alert_record_len != 2 {
            return GreaseTestOutcome::Inconclusive("Malformed TLS alert record length".to_string());
        }
        if response.len() != 5 + alert_record_len {
            return GreaseTestOutcome::Inconclusive(
                "TLS alert record length does not match buffer length".to_string(),
            );
        }

        let alert_level = response[5];
        let alert_description = response[6];
        return match alert_description {
            0x46 | 0x28 | 0x2F => GreaseTestOutcome::Rejected,
            0x32 => GreaseTestOutcome::Inconclusive("Server returned internal error".to_string()),
            _ => GreaseTestOutcome::Inconclusive(format!(
                "Server returned TLS alert {} (level {})",
                alert_description, alert_level
            )),
        };
    }

    if response.len() >= 6 && response[0] == 0x16 && response[5] == 0x02 {
        return GreaseTestOutcome::Tolerated;
    }

    GreaseTestOutcome::Inconclusive(format!(
        "Unexpected response (first bytes: {:02X?})",
        &response[..response.len().min(10)]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
