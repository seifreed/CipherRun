use super::ProtocolTester;
use crate::Result;
use crate::constants::{
    BUFFER_SIZE_MAX_TLS_RECORD, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO,
    TLS_RECORD_HEADER_SIZE,
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
        if self.test_all_ips {
            return Ok(self.detect_session_resumption_all_ips().await);
        }

        let tester = self.session_resumption_tester(self.target.clone());
        Ok(tester.quick_probe().await)
    }

    fn session_resumption_tester(
        &self,
        target: crate::utils::network::Target,
    ) -> crate::protocols::session_resumption::SessionResumptionTester {
        crate::protocols::session_resumption::SessionResumptionTester::new(target)
            .with_connect_timeout(self.connect_timeout)
            .with_retry_config(self.retry_config.clone())
            .with_sni(self.sni_hostname.clone())
            .with_starttls(
                self.starttls_protocol,
                Some(self.starttls_negotiation_hostname()),
            )
            .with_starttls_server_mode(self.starttls_server_mode)
    }

    async fn detect_session_resumption_all_ips(&self) -> (Option<bool>, Option<bool>) {
        let mut caching = ProbeAggregate::default();
        let mut tickets = ProbeAggregate::default();

        for addr in self.target.socket_addrs() {
            let Ok(target) = crate::utils::network::Target::with_ips(
                self.target.hostname.clone(),
                self.target.port,
                vec![addr.ip()],
            ) else {
                continue;
            };

            let (probe_caching, probe_tickets) =
                self.session_resumption_tester(target).quick_probe().await;
            caching.record(probe_caching);
            tickets.record(probe_tickets);

            if caching.supported && tickets.supported {
                break;
            }
        }

        (caching.result(), tickets.result())
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
        if self.test_all_ips {
            for addr in self.target.socket_addrs() {
                if let Some(server_hello) = self.fetch_server_hello_addr(protocol, addr).await? {
                    return Ok(Some(server_hello));
                }
            }
            return Ok(None);
        }

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        self.fetch_server_hello_addr(protocol, addr).await
    }

    async fn fetch_server_hello_addr(
        &self,
        protocol: Protocol,
        addr: std::net::SocketAddr,
    ) -> Result<Option<ServerHello>> {
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
            Err(_) => {
                tracing::debug!(
                    event_name = "protocol.feature_detection.parse_failed",
                    outcome = "unknown",
                    "Non-ServerHello response during feature detection"
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

        let Some(total_len) = crate::protocols::tls_record::total_len(&header)? else {
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

#[derive(Default)]
struct ProbeAggregate {
    supported: bool,
    rejected: bool,
    inconclusive: bool,
}

impl ProbeAggregate {
    fn record(&mut self, value: Option<bool>) {
        match value {
            Some(true) => self.supported = true,
            Some(false) => self.rejected = true,
            None => self.inconclusive = true,
        }
    }

    fn result(&self) -> Option<bool> {
        if self.supported {
            Some(true)
        } else if self.inconclusive {
            None
        } else if self.rejected {
            Some(false)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProbeAggregate, *};
    use std::net::SocketAddr;

    fn valid_server_hello() -> Vec<u8> {
        let mut payload = vec![HANDSHAKE_TYPE_SERVER_HELLO, 0, 0, 38, 0x03, 0x03];
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&[0, 0x13, 0x01, 0]);
        tls_record(CONTENT_TYPE_HANDSHAKE, &payload)
    }

    async fn local_server(response: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local address should exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept should succeed");
            let mut client_hello = [0; 4096];
            let bytes_read = stream
                .read(&mut client_hello)
                .await
                .expect("ClientHello should be read");
            assert!(bytes_read > 0, "ClientHello should not be empty");
            stream
                .write_all(&response)
                .await
                .expect("response should be sent");
        });
        (addr, server)
    }

    fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).expect("test record should fit TLS length");
        let mut record = vec![content_type, 0x03, 0x01];
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    async fn read_response(records: Vec<Vec<u8>>) -> std::io::Result<Option<Vec<u8>>> {
        let (mut client, mut peer) = tokio::io::duplex(BUFFER_SIZE_MAX_TLS_RECORD * 2);
        let writer = tokio::spawn(async move {
            for record in records {
                peer.write_all(&record).await?;
            }
            peer.shutdown().await
        });

        let tester =
            ProtocolTester::new(crate::utils::test_support::example_com_loopback_target(443));
        let response = tester.read_server_hello_response(&mut client).await;
        writer.await.expect("test writer should finish")?;
        response
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

    #[test]
    fn probe_aggregate_prefers_support_over_rejection() {
        let mut aggregate = ProbeAggregate::default();
        aggregate.record(Some(false));
        aggregate.record(None);
        aggregate.record(Some(true));
        assert_eq!(aggregate.result(), Some(true));
    }

    #[test]
    fn probe_aggregate_preserves_unknown_over_rejection() {
        let mut aggregate = ProbeAggregate::default();
        aggregate.record(None);
        aggregate.record(Some(false));
        assert_eq!(aggregate.result(), None);
    }

    #[test]
    fn probe_aggregate_reports_unknown_when_no_signal() {
        let aggregate = ProbeAggregate::default();
        assert_eq!(aggregate.result(), None);
    }

    #[tokio::test]
    async fn read_server_hello_response_handles_missing_and_non_server_hello_records() {
        assert_eq!(read_response(vec![]).await.unwrap(), None);

        let alert = tls_record(21, &[2, 40]);
        assert_eq!(
            read_response(vec![alert.clone()]).await.unwrap(),
            Some(alert)
        );
    }

    #[tokio::test]
    async fn read_server_hello_response_preserves_a_complete_server_hello_record() {
        let payload = [HANDSHAKE_TYPE_SERVER_HELLO, 0, 0, 0];
        let record = tls_record(CONTENT_TYPE_HANDSHAKE, &payload);

        assert_eq!(
            read_response(vec![record.clone()]).await.unwrap(),
            Some(record)
        );
    }

    #[tokio::test]
    async fn read_server_hello_response_reassembles_server_hello_fragments() {
        let payload = [HANDSHAKE_TYPE_SERVER_HELLO, 0, 0, 5, 1, 2, 3, 4, 5];
        let first = tls_record(CONTENT_TYPE_HANDSHAKE, &payload[..6]);
        let second = tls_record(CONTENT_TYPE_HANDSHAKE, &payload[6..]);

        assert_eq!(
            read_response(vec![first, second]).await.unwrap(),
            Some(tls_record(CONTENT_TYPE_HANDSHAKE, &payload))
        );
    }

    #[tokio::test]
    async fn read_server_hello_response_rejects_invalid_continuations_and_oversized_hello() {
        let partial = [HANDSHAKE_TYPE_SERVER_HELLO, 0, 0, 5, 1];
        let first = tls_record(CONTENT_TYPE_HANDSHAKE, &partial);
        assert_eq!(
            read_response(vec![first.clone(), tls_record(21, &[2, 40])])
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            read_response(vec![first, tls_record(CONTENT_TYPE_HANDSHAKE, &[2])])
                .await
                .unwrap(),
            None
        );

        let oversized_length = u32::try_from(BUFFER_SIZE_MAX_TLS_RECORD)
            .expect("record buffer limit should fit the handshake length")
            .to_be_bytes();
        let mut oversized_hello = vec![HANDSHAKE_TYPE_SERVER_HELLO];
        oversized_hello.extend_from_slice(&oversized_length[1..]);
        assert_eq!(
            read_response(vec![tls_record(CONTENT_TYPE_HANDSHAKE, &oversized_hello)])
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn read_server_hello_response_rejects_oversized_or_truncated_tls_records() {
        let record_len = u16::try_from(BUFFER_SIZE_MAX_TLS_RECORD + 1)
            .expect("oversized TLS record length should fit u16");
        let mut oversized_header = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        oversized_header.extend_from_slice(&record_len.to_be_bytes());
        assert_eq!(read_response(vec![oversized_header]).await.unwrap(), None);

        let mut truncated_record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0, 5];
        truncated_record.push(HANDSHAKE_TYPE_SERVER_HELLO);
        assert_eq!(read_response(vec![truncated_record]).await.unwrap(), None);
    }

    #[test]
    fn server_hello_payload_length_rejects_non_server_hello_and_short_headers() {
        assert_eq!(ProtocolTester::server_hello_payload_len(&[]), None);

        let mut not_handshake = [0u8; 9];
        not_handshake[0] = 21;
        not_handshake[5] = HANDSHAKE_TYPE_SERVER_HELLO;
        assert_eq!(
            ProtocolTester::server_hello_payload_len(&not_handshake),
            None
        );

        let mut not_server_hello = [0u8; 9];
        not_server_hello[0] = CONTENT_TYPE_HANDSHAKE;
        assert_eq!(
            ProtocolTester::server_hello_payload_len(&not_server_hello),
            None
        );
    }

    #[tokio::test]
    async fn fetch_server_hello_addr_parses_local_server_hello() {
        let (addr, server) = local_server(valid_server_hello()).await;
        let target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![addr.ip()],
        )
        .expect("test target should be valid");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(std::time::Duration::from_secs(1))
            .with_read_timeout(std::time::Duration::from_secs(1));

        let result = tester
            .fetch_server_hello_addr(Protocol::TLS12, addr)
            .await
            .expect("local ServerHello should be processed");
        server.await.expect("mock server should finish");

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn fetch_server_hello_addr_treats_alert_and_connect_errors_as_unknown() {
        use tokio::net::TcpListener;

        let (alert_addr, alert_server) = local_server(tls_record(21, &[2, 40])).await;
        let alert_target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            alert_addr.port(),
            vec![alert_addr.ip()],
        )
        .expect("test target should be valid");
        let alert_tester = ProtocolTester::new(alert_target)
            .with_connect_timeout(std::time::Duration::from_secs(1))
            .with_read_timeout(std::time::Duration::from_secs(1));
        let alert_result = alert_tester
            .fetch_server_hello_addr(Protocol::TLS12, alert_addr)
            .await
            .expect("alert parse failure should not abort feature detection");
        alert_server.await.expect("mock server should finish");
        assert!(alert_result.is_none());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local address should exist");
        drop(listener);
        let target = crate::utils::network::Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![addr.ip()],
        )
        .expect("test target should be valid");
        let tester =
            ProtocolTester::new(target).with_connect_timeout(std::time::Duration::from_millis(100));

        assert!(
            tester
                .fetch_server_hello_addr(Protocol::TLS12, addr)
                .await
                .expect("connect failure should be inconclusive")
                .is_none()
        );
    }
}
