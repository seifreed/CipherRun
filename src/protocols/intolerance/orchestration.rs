use super::{IntoleranceTestResult, IntoleranceTester};
use crate::Result;
use crate::constants::ALERT_UNRECOGNIZED_NAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntoleranceProbe {
    Detected,
    NotDetected,
    Inconclusive,
}

#[derive(Clone, Copy)]
enum IntoleranceCheck {
    Extensions,
    Version,
    LongHandshake,
    SniAlert,
    CommonDhPrime,
}

impl IntoleranceCheck {
    fn key(self) -> &'static str {
        match self {
            Self::Extensions => "extension_intolerance",
            Self::Version => "version_intolerance",
            Self::LongHandshake => "long_handshake_intolerance",
            Self::SniAlert => "incorrect_sni_alerts",
            Self::CommonDhPrime => "uses_common_dh_primes",
        }
    }

    fn detected_detail(self) -> &'static str {
        match self {
            Self::Extensions => "Server rejects ClientHellos with certain extensions (bad)",
            Self::Version => "Server rejects ClientHello with high version in record layer (bad)",
            Self::LongHandshake => "Server rejects ClientHello > 256 bytes (bad)",
            Self::SniAlert => "Server sends incorrect alert when SNI fails (bad)",
            Self::CommonDhPrime => "Server uses known weak DH primes (critical security issue)",
        }
    }

    fn mark_detected(self, result: &mut IntoleranceTestResult) {
        match self {
            Self::Extensions => result.extension_intolerance = true,
            Self::Version => result.version_intolerance = true,
            Self::LongHandshake => result.long_handshake_intolerance = true,
            Self::SniAlert => result.incorrect_sni_alerts = true,
            Self::CommonDhPrime => result.uses_common_dh_primes = true,
        }
    }
}

impl IntoleranceTester {
    pub async fn test_all(&self) -> Result<IntoleranceTestResult> {
        Ok(result_from_probes([
            self.test_extension_intolerance().await?,
            self.test_version_intolerance().await?,
            self.test_long_handshake_intolerance().await?,
            self.test_sni_alerts().await?,
            self.test_common_dh_primes().await?,
        ]))
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

        Ok(classify_sni_alert(
            self.send_and_read_alert(&invalid_sni_hello).await,
        ))
    }

    async fn test_common_dh_primes(&self) -> Result<IntoleranceProbe> {
        let common_primes = Self::load_common_primes()?;

        Ok(classify_common_dh_prime(
            self.extract_dh_prime().await,
            &common_primes,
        ))
    }
}

fn result_from_probes(probes: [IntoleranceProbe; 5]) -> IntoleranceTestResult {
    let mut result = IntoleranceTestResult::default();
    for (probe, check) in [
        (probes[0], IntoleranceCheck::Extensions),
        (probes[1], IntoleranceCheck::Version),
        (probes[2], IntoleranceCheck::LongHandshake),
        (probes[3], IntoleranceCheck::SniAlert),
        (probes[4], IntoleranceCheck::CommonDhPrime),
    ] {
        apply_probe_result(&mut result, probe, check);
    }
    result
}

fn apply_probe_result(
    result: &mut IntoleranceTestResult,
    probe: IntoleranceProbe,
    check: IntoleranceCheck,
) {
    match probe {
        IntoleranceProbe::Detected => {
            check.mark_detected(result);
            result
                .details
                .insert(check.key().to_string(), check.detected_detail().to_string());
        }
        IntoleranceProbe::Inconclusive => mark_inconclusive(result, check.key()),
        IntoleranceProbe::NotDetected => {}
    }
}

fn classify_sni_alert(result: Result<Option<u8>>) -> IntoleranceProbe {
    match result {
        Ok(Some(alert_code)) if alert_code != ALERT_UNRECOGNIZED_NAME => IntoleranceProbe::Detected,
        Ok(_) => IntoleranceProbe::NotDetected,
        Err(_) => IntoleranceProbe::Inconclusive,
    }
}

fn classify_common_dh_prime(
    result: Result<Option<String>>,
    common_primes: &[String],
) -> IntoleranceProbe {
    match result {
        Ok(Some(prime_hex)) if common_primes.contains(&prime_hex.to_uppercase()) => {
            IntoleranceProbe::Detected
        }
        Ok(_) => IntoleranceProbe::NotDetected,
        Err(_) => IntoleranceProbe::Inconclusive,
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

#[cfg(test)]
mod tests {
    use super::{
        IntoleranceCheck, IntoleranceProbe, classify_common_dh_prime, classify_sni_alert,
        compare_baseline_probe, mark_inconclusive, result_from_probes,
    };
    use crate::constants::ALERT_UNRECOGNIZED_NAME;
    use crate::protocols::intolerance::IntoleranceTestResult;

    #[test]
    fn compares_baseline_and_variant_outcomes() {
        let failed_probe = || Err(crate::TlsError::Other("probe failed".into()));
        assert_eq!(
            compare_baseline_probe(Ok(vec![1]), failed_probe()),
            IntoleranceProbe::Detected
        );
        assert_eq!(
            compare_baseline_probe(Ok(vec![1]), Ok(vec![2])),
            IntoleranceProbe::NotDetected
        );
        assert_eq!(
            compare_baseline_probe(failed_probe(), Ok(vec![2])),
            IntoleranceProbe::Inconclusive
        );
    }

    #[test]
    fn marks_the_named_check_inconclusive_with_a_reason() {
        let mut result = IntoleranceTestResult::default();
        mark_inconclusive(&mut result, "version_intolerance");

        assert!(result.inconclusive);
        assert_eq!(result.inconclusive_checks, ["version_intolerance"]);
        assert!(result.details["version_intolerance"].contains("baseline probe did not complete"));
    }

    #[test]
    fn result_from_probes_records_every_detection_and_clean_outcome() {
        let detected = result_from_probes([IntoleranceProbe::Detected; 5]);
        assert!(detected.extension_intolerance);
        assert!(detected.version_intolerance);
        assert!(detected.long_handshake_intolerance);
        assert!(detected.incorrect_sni_alerts);
        assert!(detected.uses_common_dh_primes);
        assert_eq!(detected.details.len(), 5);
        assert!(!detected.inconclusive);

        let clean = result_from_probes([IntoleranceProbe::NotDetected; 5]);
        assert!(clean.details.is_empty());
        assert!(!clean.inconclusive);
        assert!(!clean.extension_intolerance);
        assert!(!clean.version_intolerance);
        assert!(!clean.long_handshake_intolerance);
        assert!(!clean.incorrect_sni_alerts);
        assert!(!clean.uses_common_dh_primes);

        for check in [
            IntoleranceCheck::Extensions,
            IntoleranceCheck::Version,
            IntoleranceCheck::LongHandshake,
            IntoleranceCheck::SniAlert,
            IntoleranceCheck::CommonDhPrime,
        ] {
            assert!(!check.key().is_empty());
            assert!(!check.detected_detail().is_empty());
        }
    }

    #[test]
    fn sni_alert_outcomes_are_classified() {
        let failed = || Err(crate::TlsError::Other("alert read failed".into()));
        assert_eq!(classify_sni_alert(Ok(Some(42))), IntoleranceProbe::Detected);
        assert_eq!(
            classify_sni_alert(Ok(Some(ALERT_UNRECOGNIZED_NAME))),
            IntoleranceProbe::NotDetected
        );
        assert_eq!(classify_sni_alert(Ok(None)), IntoleranceProbe::NotDetected);
        assert_eq!(classify_sni_alert(failed()), IntoleranceProbe::Inconclusive);
    }

    #[test]
    fn common_dh_prime_outcomes_are_classified_case_insensitively() {
        let primes = vec!["ABCD".to_string()];
        let failed = || Err(crate::TlsError::Other("handshake failed".into()));
        assert_eq!(
            classify_common_dh_prime(Ok(Some("abcd".to_string())), &primes),
            IntoleranceProbe::Detected
        );
        assert_eq!(
            classify_common_dh_prime(Ok(Some("1234".to_string())), &primes),
            IntoleranceProbe::NotDetected
        );
        assert_eq!(
            classify_common_dh_prime(Ok(None), &primes),
            IntoleranceProbe::NotDetected
        );
        assert_eq!(
            classify_common_dh_prime(failed(), &primes),
            IntoleranceProbe::Inconclusive
        );
    }

    #[tokio::test]
    async fn test_all_marks_network_failures_inconclusive() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral loopback port should be available");
        let port = listener
            .local_addr()
            .expect("bound address should exist")
            .port();
        drop(listener);

        let target = crate::utils::network::Target::with_ips(
            "example.test".to_string(),
            port,
            vec![std::net::Ipv4Addr::LOCALHOST.into()],
        )
        .expect("loopback target should be valid");
        let result = crate::protocols::intolerance::IntoleranceTester::new(target)
            .test_all()
            .await
            .expect("network failures are reported in the result");

        assert!(result.inconclusive);
        assert_eq!(
            result.inconclusive_checks,
            [
                "extension_intolerance",
                "version_intolerance",
                "long_handshake_intolerance",
                "incorrect_sni_alerts",
                "uses_common_dh_primes",
            ]
        );
        assert_eq!(result.details.len(), 5);
        assert!(result.details.values().all(|detail| {
            detail.contains("inconclusive") && detail.contains("baseline probe did not complete")
        }));
    }
}
