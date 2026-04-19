use super::{
    BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE, CipherTester, HANDSHAKE_TYPE_SERVER_HELLO, Result,
    TlsConnectionPool, timeout,
};
use super::{CIPHER_SUITE_BASE_OFFSET, SERVER_HELLO_MIN_SIZE, SESSION_ID_LENGTH_OFFSET};
use crate::ciphers::CipherSuite;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl CipherTester {
    pub(super) async fn test_cipher_handshake_only(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
        pool: Option<&Arc<TlsConnectionPool>>,
    ) -> Result<(bool, Option<u64>)> {
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(_) => return Ok((false, None)),
        };

        let start = std::time::Instant::now();
        let supported = if let Some(pool) = pool {
            self.try_cipher_handshake_with_pool(protocol, hexcode, pool)
                .await?
        } else {
            self.try_cipher_handshake(protocol, hexcode).await?
        };

        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        Ok((supported, handshake_time_ms))
    }

    pub(super) async fn determine_server_preference(
        &self,
        protocol: Protocol,
        supported_ciphers: &[CipherSuite],
    ) -> Result<Vec<String>> {
        if supported_ciphers.is_empty() {
            return Ok(Vec::new());
        }

        let cipher_hexcodes: Vec<u16> = supported_ciphers
            .iter()
            .filter_map(|c| {
                u16::from_str_radix(&c.hexcode, 16)
                    .map_err(|e| {
                        tracing::warn!(
                            "Skipping cipher with invalid hexcode '{}': {}",
                            c.hexcode,
                            e
                        );
                    })
                    .ok()
            })
            .collect();

        if cipher_hexcodes.len() < 2 {
            return Ok(Vec::new());
        }

        let (first_choice, second_choice, third_choice, reversed, rotated) = self
            .run_preference_tests(protocol, &cipher_hexcodes)
            .await?;

        let analyzer = super::CipherPreferenceAnalyzer::new(
            first_choice,
            second_choice,
            third_choice,
            cipher_hexcodes,
            reversed,
            rotated,
        );

        if analyzer.is_server_preference() {
            Ok(analyzer.build_preference_order(supported_ciphers))
        } else {
            Ok(Vec::new())
        }
    }

    async fn run_preference_tests(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<(
        Option<u16>,
        Option<u16>,
        Option<u16>,
        Vec<u16>,
        Option<Vec<u16>>,
    )> {
        let first_choice = self
            .get_server_chosen_cipher(protocol, cipher_hexcodes)
            .await?;
        tracing::debug!(
            "Cipher preference test 1 (original order): client offered {:04x?}, server chose {:04x?}",
            cipher_hexcodes,
            first_choice
        );

        let mut reversed = cipher_hexcodes.to_vec();
        reversed.reverse();
        let second_choice = self.get_server_chosen_cipher(protocol, &reversed).await?;
        tracing::debug!(
            "Cipher preference test 2 (reversed order): client offered {:04x?}, server chose {:04x?}",
            reversed,
            second_choice
        );

        let (third_choice, rotated) = if cipher_hexcodes.len() >= 3 {
            let mut rotated = cipher_hexcodes.to_vec();
            if let Some(last) = rotated.pop() {
                rotated.insert(0, last);
            }
            let choice = self.get_server_chosen_cipher(protocol, &rotated).await?;
            tracing::debug!(
                "Cipher preference test 3 (rotated order): client offered {:04x?}, server chose {:04x?}",
                rotated,
                choice
            );
            (choice, Some(rotated))
        } else {
            (None, None)
        };

        Ok((first_choice, second_choice, third_choice, reversed, rotated))
    }

    pub(super) async fn get_server_chosen_cipher(
        &self,
        protocol: Protocol,
        cipher_hexcodes: &[u16],
    ) -> Result<Option<u16>> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        // Send RDP preamble if needed (same as perform_cipher_handshake)
        if self.use_rdp
            && crate::protocols::rdp::RdpPreamble::send(&mut stream)
                .await
                .is_err()
        {
            return Ok(None);
        }

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.starttls_negotiation_hostname(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(None);
            }
        }

        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(cipher_hexcodes);
        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );
        let client_hello = builder.build_with_defaults(sni_hostname.as_deref())?;

        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            let mut response = vec![0u8; BUFFER_SIZE_DEFAULT];
            let bytes_read = stream.read(&mut response).await?;

            Ok(Self::parse_server_hello_cipher(&response, bytes_read))
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    /// Parse the server-chosen cipher suite from a ServerHello response.
    ///
    /// Returns `None` if the response is not a valid ServerHello or lacks
    /// enough bytes to extract the cipher suite.
    fn parse_server_hello_cipher(response: &[u8], bytes_read: usize) -> Option<u16> {
        if bytes_read < SERVER_HELLO_MIN_SIZE {
            return None;
        }
        if response[0] != CONTENT_TYPE_HANDSHAKE || response[5] != HANDSHAKE_TYPE_SERVER_HELLO {
            return None;
        }

        let session_id_len = response[SESSION_ID_LENGTH_OFFSET] as usize;
        if session_id_len > 32 {
            tracing::warn!(
                "Invalid session_id_len: {} (max 32), skipping cipher extraction",
                session_id_len
            );
            return None;
        }

        let cipher_offset = CIPHER_SUITE_BASE_OFFSET + session_id_len;
        tracing::debug!(
            "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
            session_id_len,
            cipher_offset,
            bytes_read
        );

        if bytes_read >= cipher_offset + 2 {
            let cipher = u16::from_be_bytes([response[cipher_offset], response[cipher_offset + 1]]);
            tracing::debug!("Server chose cipher: 0x{:04x}", cipher);
            Some(cipher)
        } else {
            None
        }
    }
}
