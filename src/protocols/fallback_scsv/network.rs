use super::FallbackScsvTester;
use super::model::ScsvSupport;
use crate::Result;
use crate::constants::CONTENT_TYPE_ALERT;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

impl FallbackScsvTester<'_> {
    pub(super) async fn test_scsv_all_ips(&self, test_version: u16) -> Result<ScsvSupport> {
        let addrs = self.target.socket_addrs();

        if addrs.is_empty() {
            return Ok(ScsvSupport::inconclusive());
        }

        tracing::info!(
            "Testing TLS_FALLBACK_SCSV on {} IPs for hostname {}",
            addrs.len(),
            self.target.hostname
        );

        let mut all_support = true;
        let mut inconclusive = false;

        for (idx, addr) in addrs.iter().enumerate() {
            let ip_supports = self.test_scsv_on_ip(test_version, *addr).await?;

            tracing::debug!(
                "IP {} ({}/{}): SCSV {} - {}",
                addr.ip(),
                idx + 1,
                addrs.len(),
                if ip_supports.supported {
                    "supported"
                } else {
                    "NOT supported"
                },
                if ip_supports.supported { "✓" } else { "✗" }
            );

            if ip_supports.inconclusive {
                inconclusive = true;
            }

            if !ip_supports.supported {
                all_support = false;
            }
        }

        Ok(aggregate_scsv_support(all_support, inconclusive))
    }

    pub(super) async fn test_scsv_on_ip(
        &self,
        test_version: u16,
        addr: std::net::SocketAddr,
    ) -> Result<ScsvSupport> {
        match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(5), None).await
        {
            Ok(mut stream) => {
                let client_hello_no_scsv = self.build_client_hello_with_scsv(test_version, false);

                tracing::debug!(
                    "Sending ClientHello with version 0x{:04x} (no SCSV) to IP {}",
                    test_version,
                    addr.ip()
                );

                stream.write_all(&client_hello_no_scsv).await?;

                let mut buffer = vec![0u8; 8192];
                let baseline = timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
                if !self.baseline_fallback_accepted(baseline, &buffer) {
                    tracing::debug!(
                        "SCSV test: baseline fallback without SCSV did not complete cleanly"
                    );
                    return Ok(ScsvSupport::inconclusive());
                }

                let stream =
                    crate::utils::network::connect_with_timeout(addr, Duration::from_secs(5), None)
                        .await;
                let Ok(mut stream) = stream else {
                    tracing::debug!("SCSV test: Failed to reconnect for SCSV test");
                    return Ok(ScsvSupport::inconclusive());
                };

                let client_hello_scsv = self.build_client_hello_with_scsv(test_version, true);

                tracing::debug!(
                    "Sending ClientHello with version 0x{:04x} + TLS_FALLBACK_SCSV to IP {}",
                    test_version,
                    addr.ip()
                );

                stream.write_all(&client_hello_scsv).await?;

                let mut buffer = vec![0u8; 8192];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::debug!(
                            "SCSV test: received {} bytes, first byte: 0x{:02x}",
                            n,
                            buffer[0]
                        );

                        let bytes_hex: Vec<String> = buffer[..n]
                            .iter()
                            .map(|byte| format!("{:02x}", byte))
                            .collect();
                        tracing::debug!("SCSV test: full response bytes: {}", bytes_hex.join(" "));

                        if n > 6 && buffer[0] == CONTENT_TYPE_ALERT {
                            let alert_level = buffer[5];
                            let alert_desc = buffer[6];

                            tracing::debug!(
                                "SCSV test: Alert level: 0x{:02x}, description: 0x{:02x}",
                                alert_level,
                                alert_desc
                            );

                            if alert_desc == 0x56 {
                                tracing::info!(
                                    "✓ Server correctly rejected inappropriate fallback with alert 0x56 (inappropriate_fallback)"
                                );
                                Ok(ScsvSupport::supported())
                            } else {
                                tracing::debug!(
                                    "Server sent alert 0x{:02x} (not inappropriate_fallback)",
                                    alert_desc
                                );
                                Ok(ScsvSupport::not_supported())
                            }
                        } else {
                            tracing::warn!(
                                "✗ Server at IP {} accepted fallback (version 0x{:04x}) - NOT protected by SCSV",
                                addr.ip(),
                                test_version
                            );
                            Ok(ScsvSupport::not_supported())
                        }
                    }
                    Ok(Ok(_)) => {
                        tracing::debug!(
                            "SCSV test: Empty response - server may have rejected connection"
                        );
                        Ok(ScsvSupport::inconclusive())
                    }
                    Err(error) => {
                        tracing::debug!("SCSV test: Timeout reading response: {}", error);
                        Ok(ScsvSupport::inconclusive())
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(
                            "SCSV test: Error reading response: {} - Server may have closed connection",
                            error
                        );
                        Ok(ScsvSupport::inconclusive())
                    }
                }
            }
            _ => {
                tracing::debug!("SCSV test: Failed to connect to server");
                Ok(ScsvSupport::inconclusive())
            }
        }
    }

}

/// Aggregate per-IP SCSV results into a single verdict.
///
/// Precedence (S5 fix): if any IP was inconclusive the aggregate is inconclusive;
/// otherwise, if any IP does not support SCSV the aggregate is not_supported;
/// otherwise all IPs support it. Previously `!all_support` won over `inconclusive`,
/// yielding false-positive "fallback vulnerability" verdicts when a single probe
/// was inconclusive alongside a not_supported IP.
fn aggregate_scsv_support(all_support: bool, inconclusive: bool) -> ScsvSupport {
    if inconclusive {
        ScsvSupport::inconclusive()
    } else if !all_support {
        ScsvSupport::not_supported()
    } else {
        ScsvSupport::supported()
    }
}

impl FallbackScsvTester<'_> {
    pub(super) fn baseline_fallback_accepted(
        &self,
        read_result: std::result::Result<
            std::result::Result<usize, std::io::Error>,
            tokio::time::error::Elapsed,
        >,
        buffer: &[u8],
    ) -> bool {
        match read_result {
            Ok(Ok(n)) if n > 0 => {
                if n > 6 && buffer[0] == CONTENT_TYPE_ALERT {
                    return false;
                }
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_scsv_inconclusive_wins_over_not_supported() {
        // Regression test for S5: a single inconclusive probe must not be
        // overridden by another IP that returned not_supported. Reporting
        // a downgrade vulnerability without conclusive evidence is a false
        // positive in a security scanner.
        let result = aggregate_scsv_support(/*all_support=*/ false, /*inconclusive=*/ true);
        assert!(
            result.inconclusive,
            "inconclusive must win when at least one IP was inconclusive"
        );
        assert!(!result.vulnerable, "inconclusive must not imply vulnerable");
    }

    #[test]
    fn test_aggregate_scsv_all_supported() {
        let result = aggregate_scsv_support(true, false);
        assert!(result.supported);
        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
    }

    #[test]
    fn test_aggregate_scsv_not_supported_when_no_inconclusive() {
        let result = aggregate_scsv_support(false, false);
        assert!(!result.supported);
        assert!(result.vulnerable);
        assert!(result.accepts_downgrade);
    }
}
