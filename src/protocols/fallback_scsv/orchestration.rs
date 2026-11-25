use super::model::ScsvSupport;
use super::{FallbackScsvTestResult, FallbackScsvTester};
use crate::Result;
use crate::protocols::{Protocol, tester::ProtocolTester};

impl FallbackScsvTester<'_> {
    pub(super) async fn count_supported_protocols(
        &self,
        protocol_tester: &ProtocolTester,
    ) -> Result<Vec<Protocol>> {
        let mut supported = Vec::new();

        for protocol in Protocol::all() {
            if matches!(protocol, Protocol::SSLv2 | Protocol::QUIC) {
                continue;
            }

            let result = protocol_tester.test_protocol(protocol).await?;
            if result.supported {
                supported.push(protocol);
            }
        }

        Ok(supported)
    }

    pub(super) async fn build_scsv_result(
        &self,
        supported_protocols: &[Protocol],
    ) -> Result<FallbackScsvTestResult> {
        if supported_protocols.len() <= 1 {
            let max_protocol = self.max_supported_protocol.ok_or_else(|| {
                crate::error::TlsError::Other(
                    "max_supported_protocol is None when it should be Some".into(),
                )
            })?;
            let protocol_name = max_protocol.name();
            let has_tls13 = matches!(max_protocol, Protocol::TLS13);
            tracing::debug!(
                event_name = "tls_fallback_scsv.inconclusive",
                protocol = protocol_name,
                reason = "insufficient_protocol_count",
                outcome = "inconclusive",
                "SCSV protection cannot be determined"
            );
            return Ok(FallbackScsvTestResult {
                supported: false,
                accepts_downgrade: false,
                vulnerable: false,
                inconclusive: true,
                not_applicable: false,
                details: format!(
                    "Downgrade attack prevention: Unknown (Server only supports {} - requires at least two protocols excluding SSL 2)",
                    protocol_name
                ),
                has_tls13_or_higher: has_tls13,
            });
        }

        let supported = self
            .test_rejects_inappropriate_fallback(supported_protocols)
            .await?;
        let has_tls13 = supported_protocols
            .iter()
            .any(|protocol| matches!(protocol, Protocol::TLS13));

        let details = if supported.supported {
            format!(
                "TLS_FALLBACK_SCSV supported - Protected against downgrade attacks (Protocols: {})",
                self.format_protocol_list(supported_protocols)
            )
        } else if supported.not_applicable {
            format!(
                "TLS_FALLBACK_SCSV not applicable for negotiated protocol set (Protocols: {})",
                self.format_protocol_list(supported_protocols)
            )
        } else if supported.inconclusive {
            format!(
                "Downgrade attack prevention: Inconclusive (fallback test did not complete cleanly) (Protocols: {})",
                self.format_protocol_list(supported_protocols)
            )
        } else {
            format!(
                "TLS_FALLBACK_SCSV NOT supported - Vulnerable to downgrade attacks (Protocols: {})",
                self.format_protocol_list(supported_protocols)
            )
        };

        Ok(FallbackScsvTestResult {
            supported: supported.supported,
            accepts_downgrade: supported.accepts_downgrade,
            vulnerable: supported.vulnerable,
            inconclusive: supported.inconclusive,
            not_applicable: supported.not_applicable,
            details,
            has_tls13_or_higher: has_tls13,
        })
    }

    pub(super) fn format_protocol_list(&self, protocols: &[Protocol]) -> String {
        protocols
            .iter()
            .map(|protocol| protocol.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(super) fn select_fallback_protocol(
        &self,
        supported_protocols: &[Protocol],
        max_protocol: Protocol,
    ) -> Option<Protocol> {
        supported_protocols
            .iter()
            .copied()
            .filter(|protocol| *protocol < max_protocol)
            .max()
    }

    pub(super) async fn test_rejects_inappropriate_fallback(
        &self,
        supported_protocols: &[Protocol],
    ) -> Result<ScsvSupport> {
        let max_protocol = self.max_supported_protocol.ok_or_else(|| {
            crate::error::TlsError::Other(
                "max_supported_protocol must be set before calling this method".into(),
            )
        })?;

        let fallback_protocol = match max_protocol {
            Protocol::SSLv3 => {
                tracing::warn!(
                    event_name = "tls_fallback_scsv.not_applicable",
                    protocol = max_protocol.name(),
                    reason = "no_lower_protocol",
                    outcome = "inconclusive",
                    "Cannot test SCSV without a lower fallback protocol"
                );
                return Ok(ScsvSupport::inconclusive());
            }
            Protocol::SSLv2 => {
                tracing::warn!(
                    event_name = "tls_fallback_scsv.not_applicable",
                    protocol = max_protocol.name(),
                    reason = "protocol_not_applicable",
                    outcome = "not_applicable",
                    "SCSV is not applicable to the negotiated protocol"
                );
                return Ok(ScsvSupport::not_applicable());
            }
            Protocol::QUIC => {
                tracing::warn!(
                    event_name = "tls_fallback_scsv.not_applicable",
                    protocol = max_protocol.name(),
                    reason = "protocol_not_applicable",
                    outcome = "not_applicable",
                    "SCSV is not applicable to the negotiated protocol"
                );
                return Ok(ScsvSupport::not_applicable());
            }
            _ => {
                let fallback = self.select_fallback_protocol(supported_protocols, max_protocol);
                let Some(fallback) = fallback else {
                    tracing::warn!(
                        event_name = "tls_fallback_scsv.inconclusive",
                        protocol = max_protocol.name(),
                        reason = "no_lower_protocol",
                        outcome = "inconclusive",
                        "No lower supported protocol is available for the SCSV test"
                    );
                    return Ok(ScsvSupport::inconclusive());
                };
                fallback
            }
        };

        let test_version = fallback_protocol.as_hex();
        tracing::debug!(
            event_name = "tls_fallback_scsv.probe.started",
            max_protocol = max_protocol.name(),
            fallback_protocol = fallback_protocol.name(),
            "Testing TLS_FALLBACK_SCSV"
        );

        if self.test_all_ips {
            self.test_scsv_all_ips(test_version).await
        } else {
            let addr = self
                .target
                .socket_addrs()
                .first()
                .copied()
                .ok_or(crate::TlsError::NoSocketAddresses)?;
            self.test_scsv_on_ip(test_version, addr).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::network::Target;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn target() -> Target {
        Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap()
    }

    async fn mock_tls_server(
        responses: Vec<&'static [u8]>,
    ) -> (Target, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                let mut client_hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
                stream.read_exact(&mut client_hello).await.unwrap();
                stream.write_all(response).await.unwrap();
            }
        });
        (
            Target::with_ips(
                "example.com".to_string(),
                address.port(),
                vec![address.ip()],
            )
            .unwrap(),
            server,
        )
    }

    #[test]
    fn formats_protocol_list_and_selects_highest_lower_protocol() {
        let target = target();
        let tester = FallbackScsvTester::new(&target);
        let protocols = [Protocol::TLS10, Protocol::TLS11, Protocol::TLS12];

        assert_eq!(
            tester.format_protocol_list(&protocols),
            "TLS 1.0, TLS 1.1, TLS 1.2"
        );
        assert_eq!(
            tester.select_fallback_protocol(&protocols, Protocol::TLS13),
            Some(Protocol::TLS12)
        );
        assert_eq!(
            tester.select_fallback_protocol(&protocols, Protocol::TLS10),
            None
        );
    }

    #[test]
    fn client_hello_omits_sni_extension_for_ip_literal_targets() {
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = FallbackScsvTester::new(&target);

        let hello = tester
            .build_client_hello_with_scsv(Protocol::TLS12.as_hex(), true)
            .unwrap();

        assert!(hello.ends_with(&[0, 0]));
    }

    #[tokio::test]
    async fn insufficient_protocol_results_are_inconclusive_and_require_detected_maximum() {
        let target = target();
        let mut tester = FallbackScsvTester::new(&target);
        assert!(tester.build_scsv_result(&[]).await.is_err());
        assert!(
            tester
                .test_rejects_inappropriate_fallback(&[])
                .await
                .is_err()
        );

        tester.max_supported_protocol = Some(Protocol::TLS13);
        let result = tester.build_scsv_result(&[Protocol::TLS13]).await.unwrap();
        assert!(result.inconclusive);
        assert!(result.has_tls13_or_higher);
        assert!(result.details.contains("only supports TLS 1.3"));
    }

    #[tokio::test]
    async fn unsupported_maximum_protocols_are_not_applicable() {
        let target = target();
        for protocol in [Protocol::SSLv2, Protocol::QUIC] {
            let mut tester = FallbackScsvTester::new(&target);
            tester.max_supported_protocol = Some(protocol);

            let result = tester
                .test_rejects_inappropriate_fallback(&[protocol])
                .await
                .unwrap();

            assert!(result.not_applicable);
            assert!(!result.inconclusive);
        }

        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::QUIC);
        let result = tester
            .build_scsv_result(&[Protocol::TLS13, Protocol::QUIC])
            .await
            .unwrap();
        assert!(result.not_applicable);
        assert!(result.has_tls13_or_higher);
        assert!(result.details.contains("not applicable"));
    }

    #[tokio::test]
    async fn absent_lower_protocol_and_ssl3_fallback_are_inconclusive() {
        let target = target();
        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::SSLv3);
        let result = tester
            .test_rejects_inappropriate_fallback(&[Protocol::SSLv3])
            .await
            .unwrap();
        assert!(result.inconclusive);

        tester.max_supported_protocol = Some(Protocol::TLS12);
        let result = tester
            .test_rejects_inappropriate_fallback(&[Protocol::TLS12])
            .await
            .unwrap();
        assert!(result.inconclusive);
    }

    #[tokio::test]
    async fn counts_supported_protocols_while_skipping_ssl2_and_quic() {
        let alert = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let (target, server) = mock_tls_server(vec![alert, alert, alert, alert, alert]).await;
        let tester = FallbackScsvTester::new(&target);
        let protocols = tester
            .count_supported_protocols(&ProtocolTester::new(target.clone()))
            .await
            .unwrap();

        server.await.unwrap();
        assert!(protocols.is_empty());
    }

    #[tokio::test]
    async fn builds_protected_result_from_all_ip_probe() {
        let baseline = &[0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
        let alert = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x56];
        let (target, server) = mock_tls_server(vec![baseline, alert]).await;
        let mut tester = FallbackScsvTester::new(&target).with_test_all_ips(true);
        tester.max_supported_protocol = Some(Protocol::TLS12);

        let result = tester
            .build_scsv_result(&[Protocol::TLS11, Protocol::TLS12])
            .await
            .unwrap();

        server.await.unwrap();
        assert!(result.supported);
        assert!(!result.inconclusive);
        assert!(
            result
                .details
                .contains("Protected against downgrade attacks")
        );
    }

    #[tokio::test]
    async fn builds_inconclusive_and_vulnerable_results_from_single_ip_probes() {
        let alert = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let (target, server) = mock_tls_server(vec![alert]).await;
        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::TLS12);
        let result = tester
            .build_scsv_result(&[Protocol::TLS11, Protocol::TLS12])
            .await
            .unwrap();
        server.await.unwrap();
        assert!(result.inconclusive);
        assert!(result.details.contains("Inconclusive"));

        let baseline = &[0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
        let handshake = &[0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
        let (target, server) = mock_tls_server(vec![baseline, handshake]).await;
        let mut tester = FallbackScsvTester::new(&target);
        tester.max_supported_protocol = Some(Protocol::TLS12);
        let result = tester
            .build_scsv_result(&[Protocol::TLS11, Protocol::TLS12])
            .await
            .unwrap();
        server.await.unwrap();
        assert!(result.vulnerable);
        assert!(result.accepts_downgrade);
        assert!(result.details.contains("Vulnerable to downgrade attacks"));
    }
}
