use super::{Protocol, ProtocolTestResult, ProtocolTester};
use crate::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProtocolProbeOutcome {
    Supported,
    NotSupported,
    Inconclusive,
}

impl ProtocolProbeOutcome {
    fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }

    fn is_inconclusive(self) -> bool {
        matches!(self, Self::Inconclusive)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::NotSupported => "NOT supported",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl ProtocolTester {
    pub async fn test_all_protocols(&self) -> Result<Vec<ProtocolTestResult>> {
        use futures::stream::{self, StreamExt};

        let protocols_to_test = self.protocol_filter.clone().unwrap_or_else(Protocol::all);

        let results: Vec<ProtocolTestResult> = stream::iter(protocols_to_test)
            .map(|protocol| async move { self.test_protocol(protocol).await })
            .buffer_unordered(6)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }

    pub async fn test_protocol(&self, protocol: Protocol) -> Result<ProtocolTestResult> {
        let start = std::time::Instant::now();

        let outcome = if self.test_all_ips {
            self.test_protocol_all_ips(protocol).await?
        } else {
            let addr = self
                .target
                .socket_addrs()
                .first()
                .copied()
                .ok_or(crate::TlsError::NoSocketAddresses)?;
            self.test_protocol_on_ip(protocol, addr).await?
        };
        let supported = outcome.is_supported();
        let inconclusive = outcome.is_inconclusive();

        let handshake_time_ms = if supported {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        let heartbeat_enabled =
            if supported && !matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                self.detect_heartbeat_extension(protocol)
                    .await
                    .unwrap_or(None)
            } else {
                None
            };

        let (session_resumption_caching, session_resumption_tickets) =
            if supported && !matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                match self.detect_session_resumption(protocol).await {
                    Ok((caching, tickets)) => (caching, tickets),
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            };

        let secure_renegotiation =
            if supported && !matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                self.detect_secure_renegotiation(protocol)
                    .await
                    .unwrap_or(None)
            } else {
                None
            };

        Ok(ProtocolTestResult {
            protocol,
            supported,
            inconclusive,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms,
            heartbeat_enabled,
            session_resumption_caching,
            session_resumption_tickets,
            secure_renegotiation,
        })
    }

    /// S8 note: union semantics are intentional for protocol enumeration in
    /// security scanning. If ANY backend in a load-balanced deployment accepts
    /// a protocol, the attacker's view of the deployment includes that path —
    /// so reporting it as "supported" is the security-correct verdict. An
    /// intersection reading ("is TLS 1.3 available everywhere?") is a distinct
    /// property; the caller can read the per-IP inconsistency warnings in the
    /// log, or (future work) consume a per-IP result map.
    ///
    /// The conservative-aggregation contract documented in the architecture
    /// guards refers to the ScanResults layer (ConservativeAggregator), not to
    /// this per-protocol probe. See `test_test_all_ips_reports_supported_when_any_ip_supports`.
    pub(super) async fn test_protocol_all_ips(
        &self,
        protocol: Protocol,
    ) -> Result<ProtocolProbeOutcome> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(ProtocolProbeOutcome::Inconclusive);
        }

        tracing::info!(
            "Testing {} IPs for hostname {} (protocol: {})",
            addrs.len(),
            self.target.hostname,
            protocol
        );

        let mut any_supported = false;
        let mut any_inconclusive = false;
        let mut per_ip_results = Vec::new();

        for (idx, addr) in addrs.iter().enumerate() {
            let ip_outcome = self.test_protocol_on_ip(protocol, *addr).await?;

            tracing::debug!(
                "IP {} ({}/{}): {} {} - {}",
                addr.ip(),
                idx + 1,
                addrs.len(),
                protocol,
                ip_outcome.label(),
                match ip_outcome {
                    ProtocolProbeOutcome::Supported => "✓",
                    ProtocolProbeOutcome::NotSupported => "✗",
                    ProtocolProbeOutcome::Inconclusive => "?",
                }
            );

            per_ip_results.push((addr.ip(), ip_outcome));

            if ip_outcome.is_supported() {
                any_supported = true;
            } else if ip_outcome.is_inconclusive() {
                any_inconclusive = true;
            }
        }

        let inconsistent = per_ip_results
            .iter()
            .any(|(_, outcome)| outcome.is_supported())
            && per_ip_results
                .iter()
                .any(|(_, outcome)| !outcome.is_supported());

        if inconsistent {
            tracing::warn!(
                "WARNING: Inconsistent {} support across IPs for {}",
                protocol,
                self.target.hostname
            );
            for (ip, supported) in &per_ip_results {
                tracing::warn!(
                    "  {} {} - {}",
                    ip,
                    protocol,
                    supported.label().to_uppercase()
                );
            }
        }

        if any_supported {
            Ok(ProtocolProbeOutcome::Supported)
        } else if any_inconclusive {
            Ok(ProtocolProbeOutcome::Inconclusive)
        } else {
            Ok(ProtocolProbeOutcome::NotSupported)
        }
    }

    pub(super) async fn test_protocol_on_ip(
        &self,
        protocol: Protocol,
        addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        match protocol {
            Protocol::SSLv2 => self.test_sslv2_on_ip(addr).await,
            Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11 | Protocol::TLS12 => {
                self.test_tls_with_openssl_on_ip(protocol, addr).await
            }
            Protocol::TLS13 => self.test_tls13_on_ip(addr).await,
            Protocol::QUIC => self.test_quic_on_ip(addr).await,
        }
    }

    pub(super) async fn test_sslv2_on_ip(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        let stream_result = crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await;

        match stream_result {
            Ok(mut stream) => {
                if self.use_rdp
                    && crate::protocols::rdp::RdpPreamble::send(&mut stream)
                        .await
                        .is_err()
                {
                    return Ok(ProtocolProbeOutcome::Inconclusive);
                }

                if let Some(starttls_proto) = self.starttls_protocol {
                    let negotiator = crate::starttls::protocols::get_negotiator(
                        starttls_proto,
                        self.starttls_negotiation_hostname(),
                    );
                    if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                        return Ok(ProtocolProbeOutcome::Inconclusive);
                    }
                }

                let client_hello = self.build_sslv2_client_hello();
                let mut response = vec![0u8; 1024];

                match timeout(self.read_timeout, async {
                    stream.write_all(&client_hello).await?;
                    stream.read(&mut response).await
                })
                .await
                {
                    Ok(Ok(n)) if n >= 3 => {
                        let first = response[0];
                        let second = response[1];
                        let msg_type = response[2];
                        let is_sslv2_header = (first & 0x80) != 0;
                        let record_len = ((first & 0x7f) as usize) << 8 | second as usize;
                        let reasonable = record_len > 0 && record_len <= 16384;
                        // Only treat as SSLv2 when the message type is a known SSLv2 *non-error* type;
                        // 0x00 is SSLv2 Error — server rejected the handshake, not supporting SSLv2.
                        let known_type = matches!(msg_type, 0x02..=0x08);
                        if is_sslv2_header && reasonable && known_type {
                            Ok(ProtocolProbeOutcome::Supported)
                        } else {
                            Ok(ProtocolProbeOutcome::NotSupported)
                        }
                    }
                    Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Ok(ProtocolProbeOutcome::Inconclusive),
                }
            }
            _ => Ok(ProtocolProbeOutcome::Inconclusive),
        }
    }

    pub(super) fn build_sslv2_client_hello(&self) -> Vec<u8> {
        let mut hello = vec![0x80, 0x00, 0x01, 0x00, 0x02];
        hello.push(0x00);
        hello.push(0x09); // cipher_spec_length: 9 bytes (3 ciphers × 3 bytes each)
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x10);
        hello.extend_from_slice(&[0x01, 0x00, 0x80]);
        hello.extend_from_slice(&[0x02, 0x00, 0x80]);
        hello.extend_from_slice(&[0x03, 0x00, 0x80]);
        hello.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let len = hello.len() - 2;
        hello[1] = len as u8;
        hello
    }

    pub(super) async fn test_tls_with_openssl_on_ip(
        &self,
        protocol: Protocol,
        addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(ProtocolProbeOutcome::Inconclusive),
        };

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.starttls_negotiation_hostname(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(ProtocolProbeOutcome::Inconclusive);
            }
        }

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        // Set socket-level read/write timeouts to prevent indefinite blocking
        // on servers that accept TCP but never complete the TLS handshake
        let socket_timeout = Some(std::time::Duration::from_secs(
            self.read_timeout.as_secs().max(10),
        ));
        std_stream.set_read_timeout(socket_timeout)?;
        std_stream.set_write_timeout(socket_timeout)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);

        let (min_version, max_version) = match protocol {
            Protocol::SSLv3 => (SslVersion::SSL3, SslVersion::SSL3),
            Protocol::TLS10 => (SslVersion::TLS1, SslVersion::TLS1),
            Protocol::TLS11 => (SslVersion::TLS1_1, SslVersion::TLS1_1),
            Protocol::TLS12 => (SslVersion::TLS1_2, SslVersion::TLS1_2),
            _ => return Ok(ProtocolProbeOutcome::NotSupported),
        };

        builder.set_min_proto_version(Some(min_version))?;
        builder.set_max_proto_version(Some(max_version))?;

        if self.enable_bugs_mode {
            use openssl::ssl::SslOptions;
            builder.set_options(SslOptions::ALL);
        }

        let connector = builder.build();
        let sni_host = self.sni_hostname.as_ref().unwrap_or(&self.target.hostname);

        match connector.connect(sni_host, std_stream) {
            Ok(_) => Ok(ProtocolProbeOutcome::Supported),
            Err(_) => Ok(ProtocolProbeOutcome::NotSupported),
        }
    }

    pub(super) async fn test_tls13_on_ip(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        use rustls::{ClientConfig, RootCertStore};
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            self.connect_timeout,
            self.retry_config.as_ref(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(ProtocolProbeOutcome::Inconclusive),
        };

        if let Some(starttls_proto) = self.starttls_protocol {
            let negotiator = crate::starttls::protocols::get_negotiator(
                starttls_proto,
                self.starttls_negotiation_hostname(),
            );
            if negotiator.negotiate_starttls(&mut stream).await.is_err() {
                return Ok(ProtocolProbeOutcome::Inconclusive);
            }
        }

        let connector = if let Some(ref mtls_config) = self.mtls_config {
            match mtls_config.build_tls_connector() {
                Ok(c) => c,
                Err(_) => return Ok(ProtocolProbeOutcome::Inconclusive),
            }
        } else {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            TlsConnector::from(Arc::new(config))
        };

        let sni_host = self.sni_hostname.as_ref().unwrap_or(&self.target.hostname);
        let domain = crate::utils::network::server_name_for_hostname(sni_host)?;

        match timeout(self.read_timeout, connector.connect(domain, stream)).await {
            Ok(Ok(_)) => Ok(ProtocolProbeOutcome::Supported),
            Ok(Err(_)) => Ok(ProtocolProbeOutcome::NotSupported),
            Err(_) => Ok(ProtocolProbeOutcome::Inconclusive),
        }
    }

    pub(super) async fn test_quic_on_ip(
        &self,
        _addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        Ok(ProtocolProbeOutcome::NotSupported)
    }
}
