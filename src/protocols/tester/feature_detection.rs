use super::ProtocolTester;
use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_TLS_RECORD, BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_SERVER_HELLO, TLS_RECORD_HEADER_SIZE,
};
use crate::protocols::{
    Protocol,
    handshake::{ClientHelloBuilder, ServerHello, ServerHelloParser},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

impl ProtocolTester {
    pub(super) async fn detect_heartbeat_extension(
        &self,
        protocol: Protocol,
    ) -> Result<Option<bool>> {
        match self.fetch_server_hello(protocol).await? {
            Some(server_hello) => Ok(server_hello.supports_heartbeat()),
            None => Ok(None),
        }
    }

    pub(super) async fn detect_session_resumption(
        &self,
        protocol: Protocol,
    ) -> Result<(Option<bool>, Option<bool>)> {
        // Session resumption is a server-level property negotiated by OpenSSL at
        // its highest supported protocol, so the probed `protocol` is
        // informational only. Delegate to the resumption tester's single-shot
        // probe, which reports (session-id caching, session tickets) and yields
        // honest `None`s on connection failure instead of a false negative.
        let _ = protocol;
        let tester = crate::protocols::session_resumption::SessionResumptionTester::new(
            self.target.clone(),
        )
        .with_starttls(
            self.starttls_protocol,
            Some(self.starttls_negotiation_hostname()),
        )
        .with_starttls_server_mode(self.starttls_server_mode);
        Ok(tester.quick_probe().await)
    }

    pub(super) async fn detect_secure_renegotiation(
        &self,
        protocol: Protocol,
    ) -> Result<Option<bool>> {
        match self.fetch_server_hello(protocol).await? {
            Some(server_hello) => Ok(server_hello.supports_secure_renegotiation()),
            None => Ok(None),
        }
    }

    async fn fetch_server_hello(&self, protocol: Protocol) -> Result<Option<ServerHello>> {
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
                self.starttls_server_mode,
            );
            if crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await
            .is_err()
            {
                return Ok(None);
            }
        }

        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(&[0xc030, 0xc02f, 0x009e, 0x0035]);
        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );
        let client_hello = builder.build_with_defaults(sni_hostname.as_deref())?;

        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;
            self.read_server_hello_response(&mut stream).await
        })
        .await
        {
            Ok(Ok(Some(resp))) => resp,
            _ => return Ok(None),
        };

        // A successfully-read record that is not a parseable ServerHello (e.g. a
        // TLS alert refusing the offered ciphers, or a truncated/odd handshake)
        // means the feature (heartbeat / secure renegotiation) status is simply
        // unknown for this probe — it must NOT propagate as a fatal error. Earlier
        // this returned `ServerHelloParser::parse(..).map(Some)`, so an alert
        // response (<43 bytes) surfaced as "ServerHello too short" and, via
        // detect_heartbeat_extension -> test_protocol -> test_all_protocols
        // (which propagates the first error), aborted the ENTIRE protocol
        // enumeration and the whole vulnerability phase (0 results).
        match ServerHelloParser::parse(&response) {
            Ok(server_hello) => Ok(Some(server_hello)),
            Err(error) => {
                tracing::debug!(
                    "non-ServerHello response during feature detection ({});                      reporting feature status as unknown",
                    error
                );
                Ok(None)
            }
        }
    }

    async fn read_server_hello_response<S>(
        &self,
        stream: &mut S,
    ) -> std::io::Result<Option<Vec<u8>>>
    where
        S: AsyncRead + Unpin,
    {
        let Some(first_record) = Self::read_tls_record(stream).await? else {
            return Ok(None);
        };

        let Some(server_hello_payload_len) = Self::server_hello_payload_len(&first_record) else {
            return Ok(Some(first_record));
        };

        let first_payload = &first_record[5..];
        if first_payload.len() >= server_hello_payload_len {
            return Ok(Some(first_record));
        }
        if server_hello_payload_len > BUFFER_SIZE_MAX_TLS_RECORD {
            return Ok(None);
        }

        let mut handshake = first_payload.to_vec();
        while handshake.len() < server_hello_payload_len {
            let Some(record) = Self::read_tls_record(stream).await? else {
                return Ok(None);
            };
            if record.first() != Some(&CONTENT_TYPE_HANDSHAKE) {
                return Ok(None);
            }
            let remaining = server_hello_payload_len - handshake.len();
            let payload = &record[5..];
            handshake.extend_from_slice(&payload[..payload.len().min(remaining)]);
        }

        let record_len = u16::try_from(handshake.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ServerHello handshake length exceeds TLS record size",
            )
        })?;
        let mut response = Vec::with_capacity(5 + handshake.len());
        response.extend_from_slice(&first_record[..3]);
        response.extend_from_slice(&record_len.to_be_bytes());
        response.extend_from_slice(&handshake);
        Ok(Some(response))
    }

    async fn read_tls_record<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0u8; 5];
        if stream.read_exact(&mut header).await.is_err() {
            return Ok(None);
        }

        let Some(total_len) = Self::tls_record_total_len(&header)? else {
            return Ok(None);
        };

        let mut record = vec![0u8; total_len];
        record[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
        if stream
            .read_exact(&mut record[TLS_RECORD_HEADER_SIZE..])
            .await
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn tls_record_total_len(
        header: &[u8; TLS_RECORD_HEADER_SIZE],
    ) -> std::io::Result<Option<usize>> {
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE
            .checked_add(record_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS record length overflow",
                )
            })?;
        if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
            return Ok(None);
        }
        Ok(Some(total_len))
    }

    fn server_hello_payload_len(record: &[u8]) -> Option<usize> {
        if record.first() != Some(&CONTENT_TYPE_HANDSHAKE)
            || record.get(5) != Some(&HANDSHAKE_TYPE_SERVER_HELLO)
        {
            return None;
        }
        let bytes: [u8; 3] = record.get(6..9)?.try_into().ok()?;
        let [high, mid, low] = bytes;
        let body_len = ((high as usize) << 16) | ((mid as usize) << 8) | low as usize;
        4usize.checked_add(body_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_record_total_len_accepts_full_fragment_with_header() {
        let record_len = BUFFER_SIZE_MAX_TLS_RECORD as u16;
        let header = [
            CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        assert_eq!(
            ProtocolTester::tls_record_total_len(&header).expect("length should parse"),
            Some(TLS_RECORD_HEADER_SIZE + BUFFER_SIZE_MAX_TLS_RECORD)
        );
    }

    #[test]
    fn test_server_hello_payload_len_accepts_full_fragment() {
        let body_len = BUFFER_SIZE_MAX_TLS_RECORD - 4;
        let mut record = vec![0u8; 9];
        record[0] = CONTENT_TYPE_HANDSHAKE;
        record[5] = HANDSHAKE_TYPE_SERVER_HELLO;
        record[6] = ((body_len >> 16) & 0xff) as u8;
        record[7] = ((body_len >> 8) & 0xff) as u8;
        record[8] = (body_len & 0xff) as u8;

        assert_eq!(
            ProtocolTester::server_hello_payload_len(&record),
            Some(BUFFER_SIZE_MAX_TLS_RECORD)
        );
    }
}
