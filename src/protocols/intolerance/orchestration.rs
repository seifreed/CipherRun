use super::{IntoleranceTestResult, IntoleranceTester};
use crate::Result;
use crate::constants::ALERT_UNRECOGNIZED_NAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntoleranceProbe {
    Detected,
    NotDetected,
    Inconclusive,
}

impl IntoleranceTester {
    pub async fn test_all(&self) -> Result<IntoleranceTestResult> {
        let mut result = IntoleranceTestResult::default();

        match self.test_extension_intolerance().await? {
            IntoleranceProbe::Detected => {
                result.extension_intolerance = true;
                result.details.insert(
                    "extension_intolerance".to_string(),
                    "Server rejects ClientHellos with certain extensions (bad)".to_string(),
                );
            }
            IntoleranceProbe::Inconclusive => {
                mark_inconclusive(&mut result, "extension_intolerance");
            }
            IntoleranceProbe::NotDetected => {}
        }

        match self.test_version_intolerance().await? {
            IntoleranceProbe::Detected => {
                result.version_intolerance = true;
                result.details.insert(
                    "version_intolerance".to_string(),
                    "Server rejects ClientHello with high version in record layer (bad)"
                        .to_string(),
                );
            }
            IntoleranceProbe::Inconclusive => {
                mark_inconclusive(&mut result, "version_intolerance");
            }
            IntoleranceProbe::NotDetected => {}
        }

        match self.test_long_handshake_intolerance().await? {
            IntoleranceProbe::Detected => {
                result.long_handshake_intolerance = true;
                result.details.insert(
                    "long_handshake_intolerance".to_string(),
                    "Server rejects ClientHello > 256 bytes (bad)".to_string(),
                );
            }
            IntoleranceProbe::Inconclusive => {
                mark_inconclusive(&mut result, "long_handshake_intolerance");
            }
            IntoleranceProbe::NotDetected => {}
        }

        match self.test_sni_alerts().await? {
            IntoleranceProbe::Detected => {
                result.incorrect_sni_alerts = true;
                result.details.insert(
                    "incorrect_sni_alerts".to_string(),
                    "Server sends incorrect alert when SNI fails (bad)".to_string(),
                );
            }
            IntoleranceProbe::Inconclusive => {
                mark_inconclusive(&mut result, "incorrect_sni_alerts");
            }
            IntoleranceProbe::NotDetected => {}
        }

        match self.test_common_dh_primes().await? {
            IntoleranceProbe::Detected => {
                result.uses_common_dh_primes = true;
                result.details.insert(
                    "uses_common_dh_primes".to_string(),
                    "Server uses known weak DH primes (critical security issue)".to_string(),
                );
            }
            IntoleranceProbe::Inconclusive => {
                mark_inconclusive(&mut result, "uses_common_dh_primes");
            }
            IntoleranceProbe::NotDetected => {}
        }

        Ok(result)
    }

    async fn test_extension_intolerance(&self) -> Result<IntoleranceProbe> {
        let minimal_hello = self.build_minimal_client_hello()?;
        let minimal_response = self.send_client_hello(&minimal_hello).await;

        let extended_hello = self.build_extended_client_hello()?;
        let extended_response = self.send_client_hello(&extended_hello).await;

        Ok(compare_baseline_probe(minimal_response, extended_response))
    }

    async fn test_version_intolerance(&self) -> Result<IntoleranceProbe> {
        let normal_hello = self.build_versioned_client_hello(0x0303)?;
        let normal_response = self.send_client_hello(&normal_hello).await;

        // Use a future/draft version (0x0305) instead of TLS 1.2 (0x0303)
        // to properly detect version intolerance
        let high_version_hello = self.build_versioned_client_hello(0x0305)?;
        let high_version_response = self.send_client_hello(&high_version_hello).await;

        Ok(compare_baseline_probe(
            normal_response,
            high_version_response,
        ))
    }

    async fn test_long_handshake_intolerance(&self) -> Result<IntoleranceProbe> {
        let normal_hello = self.build_minimal_client_hello()?;
        let normal_response = self.send_client_hello(&normal_hello).await;

        let long_hello = self.build_long_client_hello()?;
        let long_response = self.send_client_hello(&long_hello).await;

        Ok(compare_baseline_probe(normal_response, long_response))
    }

    async fn test_sni_alerts(&self) -> Result<IntoleranceProbe> {
        let invalid_sni_hello = self.build_invalid_sni_client_hello()?;

        match self.send_and_read_alert(&invalid_sni_hello).await {
            Ok(Some(alert_code)) if alert_code != ALERT_UNRECOGNIZED_NAME => {
                Ok(IntoleranceProbe::Detected)
            }
            Ok(_) => Ok(IntoleranceProbe::NotDetected),
            Err(_) => Ok(IntoleranceProbe::Inconclusive),
        }
    }

    async fn test_common_dh_primes(&self) -> Result<IntoleranceProbe> {
        let common_primes = Self::load_common_primes()?;

        match self.extract_dh_prime().await {
            Ok(Some(prime_hex)) if common_primes.contains(&prime_hex.to_uppercase()) => {
                Ok(IntoleranceProbe::Detected)
            }
            Ok(_) => Ok(IntoleranceProbe::NotDetected),
            Err(_) => Ok(IntoleranceProbe::Inconclusive),
        }
    }
}

fn compare_baseline_probe(baseline: Result<Vec<u8>>, variant: Result<Vec<u8>>) -> IntoleranceProbe {
    match (baseline, variant) {
        (Ok(_), Err(_)) => IntoleranceProbe::Detected,
        (Ok(_), Ok(_)) => IntoleranceProbe::NotDetected,
        (Err(_), _) => IntoleranceProbe::Inconclusive,
    }
}

fn mark_inconclusive(result: &mut IntoleranceTestResult, key: &str) {
    result.inconclusive = true;
    result.inconclusive_checks.push(key.to_string());
    result.details.insert(
        key.to_string(),
        format!(
            "{} test inconclusive - baseline probe did not complete",
            key
        ),
    );
}
