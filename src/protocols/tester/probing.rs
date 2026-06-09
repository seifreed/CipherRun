use super::{Protocol, ProtocolTestResult, ProtocolTester};
use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_TLS_RECORD, CONTENT_TYPE_ALERT};
use crate::protocols::handshake::{ClientHelloBuilder, ServerHelloParser};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Legacy-protocol cipher suites offered when probing SSLv3/TLS1.0/TLS1.1 by a
/// raw ClientHello. The vendored OpenSSL build cannot negotiate these protocol
/// versions at all (it answers `no protocols available`), so an OpenSSL probe
/// reports them unsupported regardless of the server — a structural false
/// negative for the very deprecated protocols the scanner must flag. Probing by
/// wire bytes is unaffected by local OpenSSL limitations. The set spans ECDHE
/// and RSA CBC, 3DES, and RC4 suites so a legacy-only server still selects one.
const LEGACY_PROBE_CIPHERS: &[u16] = &[
    0xc014, 0xc013, 0xc00a, 0xc009, 0x0035, 0x002f, 0xc012, 0xc008, 0x000a, 0x0005, 0x0004,
];

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
            Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11 => {
                self.test_tls_legacy_raw_on_ip(protocol, addr).await
            }
            Protocol::TLS12 => self.test_tls12_with_openssl_on_ip(addr).await,
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

    /// Probe SSLv3/TLS1.0/TLS1.1 support with a raw ClientHello.
    ///
    /// OpenSSL cannot be used for these versions (see `LEGACY_PROBE_CIPHERS`),
    /// so the ClientHello is assembled and classified at the byte level. Support
    /// is confirmed only when the server returns a ServerHello whose negotiated
    /// version equals the probed version.
    pub(super) async fn test_tls_legacy_raw_on_ip(
        &self,
        protocol: Protocol,
        addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
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

        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(LEGACY_PROBE_CIPHERS);
        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );
        let client_hello = match builder.build_with_defaults(sni_hostname.as_deref()) {
            Ok(hello) => hello,
            Err(_) => return Ok(ProtocolProbeOutcome::Inconclusive),
        };

        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;
            let mut resp = vec![0u8; BUFFER_SIZE_MAX_TLS_RECORD];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, std::io::Error>(resp)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return Ok(ProtocolProbeOutcome::Inconclusive),
        };

        Ok(classify_legacy_probe_response(&response, protocol))
    }

    pub(super) async fn test_tls12_with_openssl_on_ip(
        &self,
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
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

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
            // The scanner must detect TLS 1.3 support regardless of certificate
            // validity (certificate trust is assessed separately). A verifying
            // config would fail the handshake at cert validation on
            // self-signed/expired/untrusted hosts and report TLS 1.3 as
            // unsupported. The negotiated protocol version is checked below.
            TlsConnector::from(Arc::new(
                crate::utils::insecure_tls::insecure_client_config(),
            ))
        };

        let sni_host = self.sni_hostname.as_ref().unwrap_or(&self.target.hostname);
        let domain = crate::utils::network::server_name_for_hostname(sni_host)?;

        match timeout(self.read_timeout, connector.connect(domain, stream)).await {
            // The connector advertises both TLS 1.3 and TLS 1.2 (rustls default, and the
            // mTLS connector uses safe defaults too), so a successful handshake may have
            // negotiated TLS 1.2 on a server that has TLS 1.3 disabled. Confirm the
            // negotiated version is actually TLS 1.3 before reporting it as supported.
            Ok(Ok(tls_stream)) => {
                let negotiated = tls_stream.get_ref().1.protocol_version();
                if negotiated == Some(rustls::ProtocolVersion::TLSv1_3) {
                    Ok(ProtocolProbeOutcome::Supported)
                } else {
                    Ok(ProtocolProbeOutcome::NotSupported)
                }
            }
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

/// Classify a raw legacy-protocol ClientHello response.
///
/// `Supported` only when the server returns a ServerHello whose negotiated
/// version equals the probed version; a TLS alert means the version was rejected
/// (`NotSupported`); a downgraded ServerHello (e.g. the server picked SSLv3 for
/// a TLS1.0 probe) is also `NotSupported`; anything else (truncated, non-TLS) is
/// `Inconclusive` so a transport anomaly is never reported as a clean pass.
fn classify_legacy_probe_response(response: &[u8], protocol: Protocol) -> ProtocolProbeOutcome {
    if response.first() == Some(&CONTENT_TYPE_ALERT) {
        return ProtocolProbeOutcome::NotSupported;
    }

    match ServerHelloParser::parse(response) {
        Ok(server_hello) if server_hello.version == protocol => ProtocolProbeOutcome::Supported,
        Ok(_) => ProtocolProbeOutcome::NotSupported,
        Err(_) => ProtocolProbeOutcome::Inconclusive,
    }
}

#[cfg(test)]
mod legacy_probe_tests {
    use super::*;
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO};

    /// Build a minimal ServerHello record advertising `version` in the legacy
    /// version field (no supported_versions extension, so the parser reports the
    /// legacy version as negotiated).
    fn server_hello_record(version: u16) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.push(HANDSHAKE_TYPE_SERVER_HELLO);
        hello.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length (filled below)
        hello.extend_from_slice(&version.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0x00); // session_id length
        hello.extend_from_slice(&[0xc0, 0x13]); // cipher suite
        hello.push(0x00); // compression
        let body_len = hello.len() - 4;
        hello[1..4].copy_from_slice(&[
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ]);

        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn test_legacy_serverhello_matching_version_is_supported() {
        let record = server_hello_record(0x0301);
        assert_eq!(
            classify_legacy_probe_response(&record, Protocol::TLS10),
            ProtocolProbeOutcome::Supported
        );
    }

    #[test]
    fn test_legacy_alert_is_not_supported() {
        let alert = vec![CONTENT_TYPE_ALERT, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46];
        assert_eq!(
            classify_legacy_probe_response(&alert, Protocol::TLS10),
            ProtocolProbeOutcome::NotSupported
        );
    }

    #[test]
    fn test_legacy_downgraded_serverhello_is_not_supported() {
        let record = server_hello_record(0x0300);
        assert_eq!(
            classify_legacy_probe_response(&record, Protocol::TLS10),
            ProtocolProbeOutcome::NotSupported
        );
    }

    #[test]
    fn test_legacy_empty_response_is_inconclusive() {
        assert_eq!(
            classify_legacy_probe_response(&[], Protocol::TLS10),
            ProtocolProbeOutcome::Inconclusive
        );
    }
}
