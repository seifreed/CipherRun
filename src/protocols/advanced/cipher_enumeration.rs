use super::analysis::analyze_cipher_details;
use super::{
    AdvancedCipherProbeOutcome, CipherDetails, CipherPerProtocolAnalysis, ProtocolAdvancedTester,
    ProtocolCipherSupport, TlsTruncationAnalysis, is_operational_tls_error,
};
use crate::Result;
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};
use std::sync::Arc;
use tokio::time::Duration;

const TRUNCATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TRUNCATION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// RFC 6066 `truncated_hmac` extension type.
const EXT_TRUNCATED_HMAC: u16 = 0x0004;

/// Outcome of a single truncation-related probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TruncationProbe {
    /// The behaviour was observed to be present.
    Present,
    /// The behaviour was observed to be absent.
    Absent,
    /// Could not be determined (transport error / unreachable).
    Unknown,
}

const TEST_CIPHERS: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
];

/// Returns `true` when `cipher` names a TLS 1.3 suite. TLS 1.3 suites must be
/// configured through `set_ciphersuites`; the legacy `set_cipher_list` API
/// rejects them outright, so routing them there would always report them as
/// unsupported.
fn is_tls13_suite(cipher: &str) -> bool {
    cipher.starts_with("TLS_")
}

/// Restrict `builder` to a single cipher and pin the protocol version so the
/// probe genuinely tests that cipher instead of letting the server fall back to
/// an unrelated (typically TLS 1.3) suite. Returns `false` when the local
/// OpenSSL build cannot configure the cipher, which the caller maps to
/// `NotSupported`.
fn configure_single_cipher(builder: &mut SslConnectorBuilder, cipher: &str) -> bool {
    if is_tls13_suite(cipher) {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .is_ok()
            && builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .is_ok()
            && builder.set_ciphersuites(cipher).is_ok()
    } else {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .is_ok()
            && builder.set_cipher_list(cipher).is_ok()
    }
}

/// Configure a single cipher for an already-pinned protocol. A TLS 1.3 suite is
/// only valid under TLS 1.3, and a legacy cipher only under TLS 1.2 and below,
/// so mismatched cipher/protocol combinations are reported as unsupported
/// rather than allowed to negotiate an unrelated suite.
fn configure_cipher_for_protocol(
    builder: &mut SslConnectorBuilder,
    cipher: &str,
    protocol: SslVersion,
) -> bool {
    if protocol == SslVersion::TLS1_3 {
        is_tls13_suite(cipher) && builder.set_ciphersuites(cipher).is_ok()
    } else {
        !is_tls13_suite(cipher) && builder.set_cipher_list(cipher).is_ok()
    }
}

impl ProtocolAdvancedTester {
    pub async fn test_tls_truncation(&self) -> Result<TlsTruncationAnalysis> {
        let truncated_hmac = self.probe_truncated_hmac().await;
        let close_notify = self.probe_missing_close_notify().await;

        let accepts_truncated_hmac = truncated_hmac == TruncationProbe::Present;
        let accepts_no_close_notify = close_notify == TruncationProbe::Present;
        let tested =
            truncated_hmac != TruncationProbe::Unknown || close_notify != TruncationProbe::Unknown;

        // Negotiating the deprecated truncated_hmac extension genuinely weakens
        // record integrity. A missing close_notify is reported as an observation
        // but not treated as a vulnerability on its own: RFC 5246 makes it a
        // SHOULD, and length-delimited HTTP responses are unaffected, so the
        // overwhelming majority of well-behaved servers omit it.
        let vulnerable = accepts_truncated_hmac;

        let details = build_truncation_details(truncated_hmac, close_notify);

        Ok(TlsTruncationAnalysis {
            vulnerable,
            accepts_truncated_hmac,
            accepts_no_close_notify,
            tested,
            details,
        })
    }

    /// Offer the deprecated `truncated_hmac` extension with CBC ciphers over
    /// TLS 1.2 and observe whether the server negotiates it (echoes it in the
    /// ServerHello).
    async fn probe_truncated_hmac(&self) -> TruncationProbe {
        use crate::protocols::handshake::{ClientHelloBuilder, ServerHelloParser};
        use crate::protocols::{Extension, Protocol};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Some(addr) = self.target.socket_addrs().first().copied() else {
            return TruncationProbe::Unknown;
        };
        let mut stream = match crate::utils::network::connect_with_timeout(
            addr,
            TRUNCATION_CONNECT_TIMEOUT,
            None,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return TruncationProbe::Unknown,
        };

        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.for_cbc_ciphers();
        builder.add_extension(Extension::new(EXT_TRUNCATED_HMAC, vec![]));
        let client_hello = match builder.build_with_defaults(Some(&self.target.hostname)) {
            Ok(ch) => ch,
            Err(_) => return TruncationProbe::Unknown,
        };

        let response = match tokio::time::timeout(TRUNCATION_HANDSHAKE_TIMEOUT, async {
            stream.write_all(&client_hello).await?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await?;
            buf.truncate(n);
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return TruncationProbe::Unknown,
        };

        match ServerHelloParser::parse(&response) {
            Ok(server_hello) => {
                if server_hello.has_extension(EXT_TRUNCATED_HMAC) {
                    TruncationProbe::Present
                } else {
                    TruncationProbe::Absent
                }
            }
            // A handshake alert (no ServerHello) means we cannot observe the
            // extension — e.g. the server requires AEAD/TLS 1.3.
            Err(_) => TruncationProbe::Unknown,
        }
    }

    /// Complete a TLS handshake, request a resource, and observe whether the
    /// server signals end-of-data with a `close_notify` alert (clean EOF) or an
    /// abrupt transport close (truncation-susceptible).
    async fn probe_missing_close_notify(&self) -> TruncationProbe {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Some(addr) = self.target.socket_addrs().first().copied() else {
            return TruncationProbe::Unknown;
        };
        let stream = match crate::utils::network::connect_with_timeout(
            addr,
            TRUNCATION_CONNECT_TIMEOUT,
            None,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return TruncationProbe::Unknown,
        };

        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            crate::utils::insecure_tls::insecure_client_config(),
        ));
        let domain = match crate::utils::network::server_name_for_hostname(&self.target.hostname) {
            Ok(d) => d,
            Err(_) => return TruncationProbe::Unknown,
        };
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.target.hostname
        );

        let result = tokio::time::timeout(TRUNCATION_HANDSHAKE_TIMEOUT, async {
            let mut tls = connector.connect(domain, stream).await?;
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;
            // Drain to end-of-stream. rustls surfaces a clean close_notify as
            // Ok(0) and an unsignalled transport close as UnexpectedEof.
            let mut buf = [0u8; 4096];
            loop {
                match tls.read(&mut buf).await {
                    Ok(0) => return Ok(false),
                    Ok(_) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(true),
                    Err(e) => return Err(e),
                }
            }
        })
        .await;

        match result {
            Ok(Ok(true)) => TruncationProbe::Present,
            Ok(Ok(false)) => TruncationProbe::Absent,
            _ => TruncationProbe::Unknown,
        }
    }

    pub async fn test_ciphers_per_protocol(&self) -> Result<CipherPerProtocolAnalysis> {
        let protocols = vec![
            ("SSLv3", SslVersion::SSL3),
            ("TLS 1.0", SslVersion::TLS1),
            ("TLS 1.1", SslVersion::TLS1_1),
            ("TLS 1.2", SslVersion::TLS1_2),
            ("TLS 1.3", SslVersion::TLS1_3),
        ];

        let mut protocol_results = Vec::new();
        let mut total_ciphers = 0;
        let mut inconclusive_protocols = Vec::new();

        for (protocol_name, ssl_version) in protocols {
            match self.enumerate_protocol_ciphers(ssl_version).await {
                Ok((ciphers, inconclusive)) => {
                    let cipher_count = ciphers.len();
                    total_ciphers += cipher_count;
                    if inconclusive {
                        inconclusive_protocols.push(protocol_name.to_string());
                    }
                    protocol_results.push(ProtocolCipherSupport {
                        protocol: protocol_name.to_string(),
                        supported_ciphers: ciphers,
                        cipher_count,
                    });
                }
                Err(_) => inconclusive_protocols.push(protocol_name.to_string()),
            }
        }

        let total_protocols = protocol_results.len();
        let inconclusive = !inconclusive_protocols.is_empty();
        let details = if inconclusive {
            format!(
                "Found {} cipher suites across {} protocols; inconclusive for {}",
                total_ciphers,
                total_protocols,
                inconclusive_protocols.join(", ")
            )
        } else {
            format!(
                "Found {} cipher suites across {} protocols",
                total_ciphers, total_protocols
            )
        };

        Ok(CipherPerProtocolAnalysis {
            protocols: protocol_results,
            total_ciphers,
            total_protocols,
            inconclusive,
            inconclusive_protocols,
            details,
        })
    }

    pub(super) async fn test_cipher_support_outcome(
        &self,
        cipher: &str,
    ) -> Result<AdvancedCipherProbeOutcome> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            match crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await {
                Ok(stream) => stream,
                Err(_) => return Ok(AdvancedCipherProbeOutcome::Inconclusive),
            };

        let std_stream =
            match crate::utils::network::into_blocking_std_stream(stream, handshake_timeout) {
                Ok(stream) => stream,
                Err(_) => return Ok(AdvancedCipherProbeOutcome::Inconclusive),
            };

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        if !configure_single_cipher(&mut builder, cipher) {
            return Ok(AdvancedCipherProbeOutcome::NotSupported);
        }
        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(AdvancedCipherProbeOutcome::Supported),
            Err(error) => {
                let error = error.to_string();
                Ok(if is_operational_tls_error(&error) {
                    AdvancedCipherProbeOutcome::Inconclusive
                } else {
                    AdvancedCipherProbeOutcome::NotSupported
                })
            }
        }
    }

    async fn enumerate_protocol_ciphers(
        &self,
        protocol: SslVersion,
    ) -> Result<(Vec<CipherDetails>, bool)> {
        let mut supported_ciphers = Vec::new();
        let mut saw_conclusive_probe = false;
        let mut saw_inconclusive_probe = false;

        for cipher in TEST_CIPHERS {
            match self
                .test_cipher_with_protocol_outcome(cipher, protocol)
                .await
            {
                Ok(AdvancedCipherProbeOutcome::Supported) => {
                    saw_conclusive_probe = true;
                    supported_ciphers.push(analyze_cipher_details(cipher));
                }
                Ok(AdvancedCipherProbeOutcome::NotSupported) => saw_conclusive_probe = true,
                Ok(AdvancedCipherProbeOutcome::Inconclusive) | Err(_) => {
                    saw_inconclusive_probe = true;
                }
            }
        }

        Ok((
            supported_ciphers,
            !saw_conclusive_probe && saw_inconclusive_probe,
        ))
    }

    async fn test_cipher_with_protocol_outcome(
        &self,
        cipher: &str,
        protocol: SslVersion,
    ) -> Result<AdvancedCipherProbeOutcome> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let handshake_timeout = Duration::from_secs(2);

        let stream =
            match crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await {
                Ok(stream) => stream,
                Err(_) => return Ok(AdvancedCipherProbeOutcome::Inconclusive),
            };

        let std_stream =
            match crate::utils::network::into_blocking_std_stream(stream, handshake_timeout) {
                Ok(stream) => stream,
                Err(_) => return Ok(AdvancedCipherProbeOutcome::Inconclusive),
            };

        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        if builder.set_min_proto_version(Some(protocol)).is_err()
            || builder.set_max_proto_version(Some(protocol)).is_err()
        {
            return Ok(AdvancedCipherProbeOutcome::Inconclusive);
        }
        if !configure_cipher_for_protocol(&mut builder, cipher, protocol) {
            return Ok(AdvancedCipherProbeOutcome::NotSupported);
        }

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(_) => Ok(AdvancedCipherProbeOutcome::Supported),
            Err(error) => {
                let error = error.to_string();
                Ok(if is_operational_tls_error(&error) {
                    AdvancedCipherProbeOutcome::Inconclusive
                } else {
                    AdvancedCipherProbeOutcome::NotSupported
                })
            }
        }
    }
}

/// Build the human-readable summary for a TLS truncation analysis.
fn build_truncation_details(
    truncated_hmac: TruncationProbe,
    close_notify: TruncationProbe,
) -> String {
    let hmac = match truncated_hmac {
        TruncationProbe::Present => {
            "server negotiates the deprecated truncated_hmac extension (weakens record integrity)"
        }
        TruncationProbe::Absent => "truncated_hmac extension not negotiated",
        TruncationProbe::Unknown => "truncated_hmac support could not be determined",
    };
    let notify = match close_notify {
        TruncationProbe::Present => {
            "server closes without a close_notify alert (truncation-susceptible; informational)"
        }
        TruncationProbe::Absent => "server sends close_notify on connection close",
        TruncationProbe::Unknown => "close_notify behaviour could not be determined",
    };
    format!("TLS truncation: {hmac}; {notify}")
}
