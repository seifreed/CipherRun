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

        // Isolate per-protocol probe failures: a single protocol erroring
        // (e.g. a connection reset or an unparseable handshake on one version)
        // must not discard the results already collected for the others or
        // abort the whole enumeration. This mirrors the cipher phase's
        // per-protocol isolation. Previously `.collect::<Result<Vec<_>>>()?`
        // propagated the first error, which — combined with feature-detection
        // probe errors — could fail the entire protocol phase and, via the
        // vulnerability scanner's `detect_protocols`, the whole vulnerability
        // phase (0 results). An errored protocol is reported as inconclusive.
        let results: Vec<ProtocolTestResult> = stream::iter(protocols_to_test)
            .map(|protocol| async move {
                match self.test_protocol(protocol).await {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::warn!(
                            "Protocol {:?} probe failed; marking inconclusive so                              other protocols' results are preserved: {}",
                            protocol,
                            error
                        );
                        ProtocolTestResult {
                            protocol,
                            supported: false,
                            inconclusive: true,
                            preferred: false,
                            ciphers_count: 0,
                            handshake_time_ms: None,
                            heartbeat_enabled: None,
                            session_resumption_caching: None,
                            session_resumption_tickets: None,
                            secure_renegotiation: None,
                        }
                    }
                }
            })
            .buffer_unordered(6)
            .collect::<Vec<_>>()
            .await;

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
            Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
        } else {
            None
        };

        let heartbeat_enabled =
            if supported && !matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                self.detect_heartbeat_extension(protocol).await?
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
                self.detect_secure_renegotiation(protocol).await?
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
                    if crate::starttls::protocols::negotiate_starttls_with_timeout(
                        negotiator.as_ref(),
                        &mut stream,
                        self.read_timeout,
                    )
                    .await
                    .is_err()
                    {
                        return Ok(ProtocolProbeOutcome::Inconclusive);
                    }
                }

                let client_hello = self.build_sslv2_client_hello()?;

                match timeout(self.read_timeout, async {
                    stream.write_all(&client_hello).await?;
                    self.read_complete_sslv2_record(&mut stream, 1024).await
                })
                .await
                {
                    Ok(Ok(response)) if response.len() >= 3 => {
                        let header = response
                            .get(..3)
                            .ok_or_else(|| crate::TlsError::ParseError {
                                message: "SSLv2 probe response truncated before header"
                                    .to_string(),
                            })?;
                        let header: [u8; 3] =
                            header.try_into().map_err(|_| crate::TlsError::ParseError {
                                message: "SSLv2 probe response truncated before header".to_string(),
                            })?;
                        let [first, second, msg_type] = header;
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
                    // Clean connection close with no SSLv2 SERVER-HELLO: a server
                    // that actually spoke SSLv2 would have answered, so a close
                    // means the handshake was refused. This mirrors the
                    // legacy-TLS probe's rationale and keeps the verdict
                    // deterministic (a modern server may either send a TLS alert
                    // or just close in response to an SSLv2 hello).
                    Ok(Ok(response)) if response.is_empty() => {
                        Ok(ProtocolProbeOutcome::NotSupported)
                    }
                    // A reset/abort after the ClientHello is an active refusal.
                    Ok(Err(ref e)) if is_handshake_refusal(e) => {
                        Ok(ProtocolProbeOutcome::NotSupported)
                    }
                    // 1-2 byte partial reads are genuinely ambiguous transport states.
                    Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Ok(ProtocolProbeOutcome::Inconclusive),
                }
            }
            _ => Ok(ProtocolProbeOutcome::Inconclusive),
        }
    }

    pub(super) fn build_sslv2_client_hello(&self) -> crate::Result<Vec<u8>> {
        let mut body = vec![0x01, 0x00, 0x02];
        body.push(0x00);
        body.push(0x09); // cipher_spec_length: 9 bytes (3 ciphers × 3 bytes each)
        body.push(0x00);
        body.push(0x00);
        body.push(0x00);
        body.push(0x10);
        body.extend_from_slice(&[0x01, 0x00, 0x80]);
        body.extend_from_slice(&[0x02, 0x00, 0x80]);
        body.extend_from_slice(&[0x03, 0x00, 0x80]);
        body.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let len = body.len();
        let len = u8::try_from(len)
            .map_err(|_| crate::TlsError::Other("SSLv2 ClientHello too long".to_string()))?;
        let mut hello = vec![0x80, len];
        hello.extend_from_slice(&body);
        Ok(hello)
    }

    async fn read_complete_sslv2_record(
        &self,
        stream: &mut tokio::net::TcpStream,
        max_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut response = vec![0u8; max_len];
        let mut total = 0usize;

        loop {
            if total >= response.len() {
                break;
            }
            let Some(read_buf) = response.get_mut(total..) else {
                break;
            };
            let n = match timeout(self.read_timeout, stream.read(read_buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(err),
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            if total >= 2 {
                let record_len = (((response[0] & 0x7f) as usize) << 8) | response[1] as usize;
                if total >= 2 + record_len {
                    break;
                }
            }
        }

        response.truncate(total);
        Ok(response)
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
            if crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await
            .is_err()
            {
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

        match timeout(self.read_timeout, async {
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
            // Server answered: classify the ServerHello/alert by wire bytes.
            Ok(Ok(Some(resp))) => Ok(classify_legacy_probe_response(&resp, protocol)),
            // TCP connected and the ClientHello was sent, but the server closed
            // (clean EOF) or reset the connection without any TLS response.
            // Accepting the connection and then refusing the handshake for a
            // specific version is how many stacks reject an unsupported version,
            // so this is NotSupported — and a server that *did* support the
            // version would answer with a ServerHello, so a close/reset can
            // never mask real support.
            Ok(Ok(_)) => Ok(ProtocolProbeOutcome::NotSupported),
            Ok(Err(ref e)) if is_handshake_refusal(e) => Ok(ProtocolProbeOutcome::NotSupported),
            // Write failure or read timeout: genuinely ambiguous transport state.
            _ => Ok(ProtocolProbeOutcome::Inconclusive),
        }
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
            if crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await
            .is_err()
            {
                return Ok(ProtocolProbeOutcome::Inconclusive);
            }
        }

        let socket_timeout = std::time::Duration::from_secs(self.read_timeout.as_secs().max(10));
        let std_stream = crate::utils::network::into_blocking_std_stream(stream, socket_timeout)?;

        let enable_bugs_mode = self.enable_bugs_mode;
        let sni_host = self
            .sni_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        tokio::task::spawn_blocking(move || -> Result<ProtocolProbeOutcome> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

            if enable_bugs_mode {
                use openssl::ssl::SslOptions;
                builder.set_options(SslOptions::ALL);
            }

            let connector = builder.build();

            match connector.connect(&sni_host, std_stream) {
                Ok(_) => Ok(ProtocolProbeOutcome::Supported),
                Err(error) => Ok(classify_tls12_handshake_error(&error)),
            }
        })
        .await
        .map_err(|e| crate::TlsError::Other(format!("TLS 1.2 probe task failed: {}", e)))?
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
            if crate::starttls::protocols::negotiate_starttls_with_timeout(
                negotiator.as_ref(),
                &mut stream,
                self.read_timeout,
            )
            .await
            .is_err()
            {
                return Ok(ProtocolProbeOutcome::Inconclusive);
            }
        }

        let connector = if let Some(ref mtls_config) = self.mtls_config {
            mtls_config.build_tls_connector()?
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
            Ok(Err(_)) => Ok(ProtocolProbeOutcome::Inconclusive),
            Err(_) => Ok(ProtocolProbeOutcome::Inconclusive),
        }
    }

    pub(super) async fn test_quic_on_ip(
        &self,
        _addr: std::net::SocketAddr,
    ) -> Result<ProtocolProbeOutcome> {
        Ok(ProtocolProbeOutcome::Inconclusive)
    }
}

/// Whether an I/O error while exchanging the ClientHello means the server
/// actively refused the handshake (reset/aborted the connection) rather than a
/// local or ambiguous transport failure. A refusal on a successfully-connected
/// socket is a version rejection (`NotSupported`); everything else stays
/// `Inconclusive`.
fn is_handshake_refusal(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

/// Classify an OpenSSL handshake failure during the TLS 1.2 probe.
///
/// A protocol-level rejection (the server sends a TLS alert because it does not
/// offer TLS 1.2) is `NotSupported`. A transport anomaly on a successfully
/// connected socket — a read/write timeout (`SYSCALL`/`WANT_*`), a clean close
/// (`ZERO_RETURN`), a local setup/would-block failure, or an SSL-class
/// "unexpected eof"/reset (how OpenSSL 3.x reports a mid-handshake close) — is
/// ambiguous and must stay `Inconclusive` rather than masquerade as definitive
/// absence.
fn classify_tls12_handshake_error(
    error: &openssl::ssl::HandshakeError<std::net::TcpStream>,
) -> ProtocolProbeOutcome {
    use openssl::ssl::{ErrorCode, HandshakeError};

    match error {
        HandshakeError::SetupFailure(_) | HandshakeError::WouldBlock(_) => {
            ProtocolProbeOutcome::Inconclusive
        }
        HandshakeError::Failure(stream) => match stream.error().code() {
            ErrorCode::SYSCALL
            | ErrorCode::ZERO_RETURN
            | ErrorCode::WANT_READ
            | ErrorCode::WANT_WRITE => ProtocolProbeOutcome::Inconclusive,
            // OpenSSL 3.x reports a mid-handshake connection close as an
            // SSL-class error rather than SYSCALL, so inspect the message to
            // keep such transport anomalies inconclusive; a genuine TLS alert
            // ("alert handshake failure"/"protocol version") falls through to
            // NotSupported.
            _ => {
                if crate::utils::network::is_transport_anomaly_error(&stream.error().to_string()) {
                    ProtocolProbeOutcome::Inconclusive
                } else {
                    ProtocolProbeOutcome::NotSupported
                }
            }
        },
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
        if response.len() < 7 {
            return ProtocolProbeOutcome::Inconclusive;
        }
        let Some(alert_record_len) = response
            .get(3..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
        else {
            return ProtocolProbeOutcome::Inconclusive;
        };
        if alert_record_len != 2 || response.len() != 5 + alert_record_len {
            return ProtocolProbeOutcome::Inconclusive;
        }
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
    use crate::utils::mtls::MtlsConfig;
    use crate::utils::network::Target;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

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
        hello
            .get_mut(1..4)
            .expect("test ServerHello should contain handshake length placeholder")
            .copy_from_slice(&[
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
    fn test_legacy_truncated_alert_is_inconclusive() {
        let alert = vec![CONTENT_TYPE_ALERT, 0x03, 0x01, 0x00, 0x02, 0x02];
        assert_eq!(
            classify_legacy_probe_response(&alert, Protocol::TLS10),
            ProtocolProbeOutcome::Inconclusive
        );
    }

    #[test]
    fn test_legacy_malformed_alert_length_is_inconclusive() {
        let alert = vec![CONTENT_TYPE_ALERT, 0x03, 0x01, 0x00, 0x03, 0x02, 0x46];
        assert_eq!(
            classify_legacy_probe_response(&alert, Protocol::TLS10),
            ProtocolProbeOutcome::Inconclusive
        );
    }

    #[test]
    fn test_legacy_alert_with_trailing_bytes_is_inconclusive() {
        let alert = vec![CONTENT_TYPE_ALERT, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert_eq!(
            classify_legacy_probe_response(&alert, Protocol::TLS10),
            ProtocolProbeOutcome::Inconclusive
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

    #[tokio::test]
    async fn test_tls_legacy_raw_probe_handles_fragmented_server_hello() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = vec![0u8; 64];
                let _ = socket.read(&mut buffer).await.unwrap();

                let record = server_hello_record(0x0301);
                socket.write_all(&record[..6]).await.expect("write first fragment");
                socket.flush().await.expect("flush first fragment");
                tokio::time::sleep(Duration::from_millis(20)).await;
                socket
                    .write_all(&record[6..])
                    .await
                    .expect("write second fragment");
                socket.flush().await.expect("flush second fragment");
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let outcome = tester
            .test_tls_legacy_raw_on_ip(Protocol::TLS10, addr)
            .await
            .expect("fragmented ServerHello should be classified");

        assert_eq!(outcome, ProtocolProbeOutcome::Supported);
    }

    #[tokio::test]
    async fn test_sslv2_probe_handles_fragmented_server_hello() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = vec![0u8; 64];
                let _ = socket.read(&mut buffer).await.unwrap();

                let record = [0x80, 0x06, 0x02, 0x00, 0x00, 0x00];
                socket.write_all(&record[..2]).await.expect("write first fragment");
                socket.flush().await.expect("flush first fragment");
                tokio::time::sleep(Duration::from_millis(20)).await;
                socket
                    .write_all(&record[2..])
                    .await
                    .expect("write second fragment");
                socket.flush().await.expect("flush second fragment");
            }
        });

        let target = Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()])
            .expect("target should build");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(Duration::from_millis(100))
            .with_read_timeout(Duration::from_millis(100));

        let outcome = tester
            .test_sslv2_on_ip(addr)
            .await
            .expect("fragmented SSLv2 response should be classified");

        assert_eq!(outcome, ProtocolProbeOutcome::Supported);
    }

    #[test]
    fn test_connection_reset_is_handshake_refusal() {
        use std::io::{Error, ErrorKind};
        assert!(is_handshake_refusal(&Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(is_handshake_refusal(&Error::from(
            ErrorKind::ConnectionAborted
        )));
        assert!(is_handshake_refusal(&Error::from(ErrorKind::BrokenPipe)));
    }

    #[test]
    fn test_timeout_error_is_not_handshake_refusal() {
        use std::io::{Error, ErrorKind};
        // A read timeout / would-block is ambiguous, not a definitive refusal.
        assert!(!is_handshake_refusal(&Error::from(ErrorKind::TimedOut)));
        assert!(!is_handshake_refusal(&Error::from(ErrorKind::WouldBlock)));
    }

    #[tokio::test]
    async fn test_tls13_mtls_connector_error_is_propagated() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("test target should be valid");
        let mtls_config = MtlsConfig {
            cert_chain: vec![CertificateDer::from(vec![0x01, 0x02, 0x03])],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x04, 0x05, 0x06])),
        };
        let tester = ProtocolTester::with_mtls(target, mtls_config)
            .with_connect_timeout(Duration::from_secs(1))
            .with_read_timeout(Duration::from_secs(1));

        let err = tester
            .test_tls13_on_ip(addr)
            .await
            .expect_err("invalid local mTLS config should not be inconclusive");
        accept_task.abort();

        assert!(matches!(err, crate::error::TlsError::MtlsError { .. }));
    }

    #[tokio::test]
    async fn test_tls13_transport_anomaly_is_inconclusive() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have addr");

        let accept_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("test server should accept");
            let mut buf = [0u8; 512];
            let _ = socket
                .read(&mut buf)
                .await
                .expect("test server should observe client hello");
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("test target should be valid");
        let tester = ProtocolTester::new(target)
            .with_connect_timeout(Duration::from_secs(1))
            .with_read_timeout(Duration::from_secs(1));

        let outcome = tester
            .test_tls13_on_ip(addr)
            .await
            .expect("test should not error");
        accept_task.await.expect("test server task should complete");

        assert_eq!(outcome, ProtocolProbeOutcome::Inconclusive);
    }
}
