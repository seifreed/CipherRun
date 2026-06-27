use super::ProtocolTester;
use crate::Result;
use crate::constants::BUFFER_SIZE_MAX_TLS_RECORD;
use crate::protocols::{
    Protocol,
    handshake::{ClientHelloBuilder, ServerHello, ServerHelloParser},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let tester =
            crate::protocols::session_resumption::SessionResumptionTester::new(self.target.clone());
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
            let mut header = [0u8; 5];
            if stream.read_exact(&mut header).await.is_err() {
                return Ok::<Option<Vec<u8>>, std::io::Error>(None);
            }

            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let total_len = 5usize
                .checked_add(record_len)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "TLS record length overflow"))?;
            if total_len > BUFFER_SIZE_MAX_TLS_RECORD {
                return Ok::<Option<Vec<u8>>, std::io::Error>(None);
            }

            let mut resp = vec![0u8; total_len];
            resp[..5].copy_from_slice(&header);
            if stream.read_exact(&mut resp[5..]).await.is_err() {
                return Ok::<Option<Vec<u8>>, std::io::Error>(None);
            }

            Ok::<Option<Vec<u8>>, std::io::Error>(Some(resp))
        })
        .await
        {
            Ok(Ok(Some(resp))) => resp,
            _ => return Ok(None),
        };

        ServerHelloParser::parse(&response).map(Some)
    }
}
