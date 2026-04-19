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
    pub(super) async fn detect_heartbeat_extension(&self, protocol: Protocol) -> Result<bool> {
        match self.fetch_server_hello(protocol).await? {
            Some(server_hello) => Ok(server_hello.supports_heartbeat().unwrap_or(false)),
            None => Ok(false),
        }
    }

    pub(super) async fn detect_session_resumption(
        &self,
        protocol: Protocol,
    ) -> Result<(Option<bool>, Option<bool>)> {
        let _ = protocol;
        Ok((None, None))
    }

    pub(super) async fn detect_secure_renegotiation(&self, protocol: Protocol) -> Result<bool> {
        match self.fetch_server_hello(protocol).await? {
            Some(server_hello) => Ok(server_hello
                .supports_secure_renegotiation()
                .unwrap_or(false)),
            None => Ok(false),
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
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
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
            let mut resp = vec![0u8; BUFFER_SIZE_MAX_TLS_RECORD];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, anyhow::Error>(resp)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return Ok(None),
        };

        match ServerHelloParser::parse(&response) {
            Ok(server_hello) => Ok(Some(server_hello)),
            Err(_) => Ok(None),
        }
    }
}
