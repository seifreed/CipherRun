use super::{CIPHER_SUITE_BASE_OFFSET, SERVER_HELLO_MIN_SIZE, SESSION_ID_LENGTH_OFFSET};
use super::{
    CONTENT_TYPE_HANDSHAKE, CipherTester, HANDSHAKE_TYPE_SERVER_HELLO, Result, TlsConnectionPool,
    timeout,
};
use crate::ciphers::CipherSuite;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

impl CipherTester {
    pub(super) async fn test_cipher_handshake_only(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
        pool: Option<&Arc<TlsConnectionPool>>,
    ) -> Result<(bool, Option<u64>)> {
        let hexcode = match u16::from_str_radix(&cipher.hexcode, 16) {
            Ok(h) => h,
            Err(error) => {
                return Err(crate::TlsError::ParseError {
                    message: format!("Invalid cipher hexcode '{}': {}", cipher.hexcode, error),
                });
            }
        };

        let start = std::time::Instant::now();
        let supported = if let Some(pool) = pool {
            self.try_cipher_handshake_with_pool(protocol, hexcode, pool)
                .await?
        } else {
            self.try_cipher_handshake(protocol, hexcode).await?
        };

        let handshake_time_ms = if supported {
            Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
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
            .map(|cipher| {
                u16::from_str_radix(&cipher.hexcode, 16).map_err(|error| {
                    crate::TlsError::ParseError {
                        message: format!("Invalid cipher hexcode '{}': {}", cipher.hexcode, error),
                    }
                })
            })
            .collect::<Result<_>>()?;

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

        let mut stream = crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await?;

        // Send RDP preamble if needed (same as perform_cipher_handshake)
        if self.use_rdp {
            crate::protocols::rdp::RdpPreamble::send(&mut stream).await?;
        }

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.starttls_negotiation_hostname(),
                self.target.port,
            );
            crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await?;
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
            let response = Self::read_cipher_probe_response(&mut stream).await?;
            Self::parse_server_hello_cipher(&response, response.len())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::TlsError::Timeout {
                duration: Some(self.read_timeout),
            }),
        }
    }

    /// Parse the server-chosen cipher suite from a ServerHello response.
    ///
    /// Returns `None` if the response is not a valid ServerHello or lacks
    /// enough bytes to extract the cipher suite.
    fn parse_server_hello_cipher(response: &[u8], bytes_read: usize) -> Result<Option<u16>> {
        if bytes_read < SERVER_HELLO_MIN_SIZE {
            return Ok(None);
        }
        let received = response
            .get(..bytes_read)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ServerHello read length exceeds response buffer".to_string(),
            })?;
        if received.first() != Some(&CONTENT_TYPE_HANDSHAKE)
            || received.get(5) != Some(&HANDSHAKE_TYPE_SERVER_HELLO)
        {
            return Err(crate::TlsError::ParseError {
                message: "Invalid ServerHello response".to_string(),
            });
        }

        let session_id_len = received
            .get(SESSION_ID_LENGTH_OFFSET)
            .copied()
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ServerHello truncated before session ID length".to_string(),
            })? as usize;
        if session_id_len > 32 {
            return Err(crate::TlsError::ParseError {
                message: format!("Invalid ServerHello session_id_len: {}", session_id_len),
            });
        }

        let cipher_offset = CIPHER_SUITE_BASE_OFFSET + session_id_len;
        tracing::debug!(
            "ServerHello: session_id_len={}, cipher_offset={}, response_len={}",
            session_id_len,
            cipher_offset,
            bytes_read
        );

        let cipher_bytes = received
            .get(cipher_offset..cipher_offset + 2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "ServerHello truncated before cipher_suite".to_string(),
            })?;
        let cipher = u16::from_be_bytes(cipher_bytes);
        tracing::debug!("Server chose cipher: 0x{:04x}", cipher);
        Ok(Some(cipher))
    }
}
