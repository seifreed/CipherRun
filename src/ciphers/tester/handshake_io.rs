use super::{
    BUFFER_SIZE_DEFAULT, CONTENT_TYPE_HANDSHAKE, CipherTestResult, CipherTester,
    HANDSHAKE_TYPE_SERVER_HELLO, Result, TlsConnectionPool, timeout,
};
use crate::ciphers::CipherSuite;
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

impl CipherTester {
    pub async fn test_single_cipher(
        &self,
        cipher: &CipherSuite,
        protocol: Protocol,
    ) -> Result<CipherTestResult> {
        let (supported, handshake_time_ms) = self
            .test_cipher_handshake_only(cipher, protocol, None)
            .await?;

        Ok(CipherTestResult {
            cipher: cipher.clone(),
            supported,
            protocol,
            server_preference: None,
            handshake_time_ms,
        })
    }

    pub(super) async fn try_cipher_handshake_with_pool(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        pool: &Arc<TlsConnectionPool>,
    ) -> Result<bool> {
        if self.test_all_ips {
            self.try_cipher_handshake_all_ips(protocol, cipher_hexcode)
                .await
        } else {
            let addr = self
                .target
                .socket_addrs()
                .first()
                .copied()
                .ok_or(crate::TlsError::NoSocketAddresses)?;
            self.try_cipher_handshake_on_ip_with_pool(protocol, cipher_hexcode, addr, pool)
                .await
        }
    }

    pub(super) async fn try_cipher_handshake(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        if self.test_all_ips {
            self.try_cipher_handshake_all_ips(protocol, cipher_hexcode)
                .await
        } else {
            let addr = self
                .target
                .socket_addrs()
                .first()
                .copied()
                .ok_or(crate::TlsError::NoSocketAddresses)?;
            self.try_cipher_handshake_on_ip(protocol, cipher_hexcode, addr)
                .await
        }
    }

    /// Test cipher on all resolved IPs — returns true if ANY IP supports it (union semantics).
    /// This ensures per-IP cipher results are preserved for the aggregation layer,
    /// which takes the union of cipher suites across all IPs.
    ///
    /// S4 fix: previously `Ok(false)` and `Err(_)` were collapsed into the same
    /// branch, silencing transient network errors as "cipher not supported".
    /// Now, if every IP returned an `Err`, we propagate the last error so the
    /// caller can schedule the cipher for ENETDOWN retry instead of recording a
    /// false negative.
    pub(super) async fn try_cipher_handshake_all_ips(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        let addrs = self.target.socket_addrs();
        if addrs.is_empty() {
            return Ok(false);
        }

        let mut any_conclusive_negative = false;
        let mut last_error: Option<crate::TlsError> = None;
        for addr in &addrs {
            match self
                .try_cipher_handshake_on_ip(protocol, cipher_hexcode, *addr)
                .await
            {
                Ok(true) => return Ok(true),
                Ok(false) => {
                    any_conclusive_negative = true;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // If we ever got a conclusive `Ok(false)` from at least one IP we can
        // report "not supported" — the cipher genuinely failed somewhere. But if
        // every IP errored, there's no evidence and we must propagate the error.
        if !any_conclusive_negative && let Some(err) = last_error {
            return Err(err);
        }
        Ok(false)
    }

    pub(super) async fn perform_cipher_handshake(
        &self,
        stream: &mut TcpStream,
        protocol: Protocol,
        cipher_hexcode: u16,
    ) -> Result<bool> {
        if self.use_rdp
            && crate::protocols::rdp::RdpPreamble::send(stream)
                .await
                .is_err()
        {
            return Ok(false);
        }

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.starttls_negotiation_hostname(),
            );
            if negotiator.negotiate_starttls(stream).await.is_err() {
                return Ok(false);
            }
        }

        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_cipher(cipher_hexcode);
        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );
        let client_hello = builder.build_with_defaults(sni_hostname.as_deref())?;

        match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;
            let mut response = vec![0u8; BUFFER_SIZE_DEFAULT];
            let n = stream.read(&mut response).await?;

            if n == 0 {
                return Ok(false);
            }

            if n >= 6
                && response[0] == CONTENT_TYPE_HANDSHAKE
                && response[5] == HANDSHAKE_TYPE_SERVER_HELLO
            {
                return Ok(true);
            }

            Ok(false)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(false),
        }
    }

    pub(super) async fn try_cipher_handshake_on_ip_with_pool(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        _addr: std::net::SocketAddr,
        pool: &Arc<TlsConnectionPool>,
    ) -> Result<bool> {
        let mut stream = match pool.acquire().await {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        self.perform_cipher_handshake(&mut stream, protocol, cipher_hexcode)
            .await
    }

    pub(super) async fn try_cipher_handshake_on_ip(
        &self,
        protocol: Protocol,
        cipher_hexcode: u16,
        addr: std::net::SocketAddr,
    ) -> Result<bool> {
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        self.perform_cipher_handshake(&mut stream, protocol, cipher_hexcode)
            .await
    }
}
