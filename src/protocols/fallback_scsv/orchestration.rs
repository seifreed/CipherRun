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
