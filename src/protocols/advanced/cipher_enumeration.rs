use super::analysis::analyze_cipher_details;
use super::{
    AdvancedCipherProbeOutcome, CipherDetails, CipherPerProtocolAnalysis, ProtocolAdvancedTester,
    ProtocolCipherSupport, TlsTruncationAnalysis, is_operational_tls_error,
};
use crate::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::time::Duration;

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

impl ProtocolAdvancedTester {
    pub async fn test_tls_truncation(&self) -> Result<TlsTruncationAnalysis> {
        let accepts_truncated_hmac = false;
        let accepts_no_close_notify = false;
        let vulnerable = false;
        let tested = false;

        let details =
            "TLS truncation test inconclusive - active truncated-HMAC and close_notify probes are not implemented"
                .to_string();

        Ok(TlsTruncationAnalysis {
            vulnerable,
            accepts_truncated_hmac,
            accepts_no_close_notify,
            tested,
            details,
        })
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
        if builder.set_cipher_list(cipher).is_err() {
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
        if builder.set_cipher_list(cipher).is_err() {
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
