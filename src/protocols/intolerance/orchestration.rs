use super::{IntoleranceTestResult, IntoleranceTester};
use crate::Result;
use crate::constants::ALERT_UNRECOGNIZED_NAME;

impl IntoleranceTester {
    pub async fn test_all(&self) -> Result<IntoleranceTestResult> {
        let mut result = IntoleranceTestResult::default();

        result.extension_intolerance = self.test_extension_intolerance().await?;
        if result.extension_intolerance {
            result.details.insert(
                "extension_intolerance".to_string(),
                "Server rejects ClientHellos with certain extensions (bad)".to_string(),
            );
        }

        result.version_intolerance = self.test_version_intolerance().await?;
        if result.version_intolerance {
            result.details.insert(
                "version_intolerance".to_string(),
                "Server rejects ClientHello with high version in record layer (bad)".to_string(),
            );
        }

        result.long_handshake_intolerance = self.test_long_handshake_intolerance().await?;
        if result.long_handshake_intolerance {
            result.details.insert(
                "long_handshake_intolerance".to_string(),
                "Server rejects ClientHello > 256 bytes (bad)".to_string(),
            );
        }

        result.incorrect_sni_alerts = self.test_sni_alerts().await?;
        if result.incorrect_sni_alerts {
            result.details.insert(
                "incorrect_sni_alerts".to_string(),
                "Server sends incorrect alert when SNI fails (bad)".to_string(),
            );
        }

        result.uses_common_dh_primes = self.test_common_dh_primes().await?;
        if result.uses_common_dh_primes {
            result.details.insert(
                "uses_common_dh_primes".to_string(),
                "Server uses known weak DH primes (critical security issue)".to_string(),
            );
        }

        Ok(result)
    }

    async fn test_extension_intolerance(&self) -> Result<bool> {
        let minimal_hello = self.build_minimal_client_hello()?;
        let minimal_response = self.send_client_hello(&minimal_hello).await;

        let extended_hello = self.build_extended_client_hello()?;
        let extended_response = self.send_client_hello(&extended_hello).await;

        Ok(matches!(
            (minimal_response, extended_response),
            (Ok(_), Err(_))
        ))
    }

    async fn test_version_intolerance(&self) -> Result<bool> {
        let normal_hello = self.build_versioned_client_hello(0x0301)?;
        let normal_response = self.send_client_hello(&normal_hello).await;

        // Use a future/draft version (0x0305) instead of TLS 1.2 (0x0303)
        // to properly detect version intolerance
        let high_version_hello = self.build_versioned_client_hello(0x0305)?;
        let high_version_response = self.send_client_hello(&high_version_hello).await;

        Ok(matches!(
            (normal_response, high_version_response),
            (Ok(_), Err(_))
        ))
    }

    async fn test_long_handshake_intolerance(&self) -> Result<bool> {
        let normal_hello = self.build_minimal_client_hello()?;
        let normal_response = self.send_client_hello(&normal_hello).await;

        let long_hello = self.build_long_client_hello()?;
        let long_response = self.send_client_hello(&long_hello).await;

        Ok(matches!((normal_response, long_response), (Ok(_), Err(_))))
    }

    async fn test_sni_alerts(&self) -> Result<bool> {
        let invalid_sni_hello = self.build_invalid_sni_client_hello()?;

        match self.send_and_read_alert(&invalid_sni_hello).await {
            Ok(Some(alert_code)) => Ok(alert_code != ALERT_UNRECOGNIZED_NAME),
            _ => Ok(false),
        }
    }

    async fn test_common_dh_primes(&self) -> Result<bool> {
        let common_primes = Self::load_common_primes()?;

        match self.extract_dh_prime().await {
            Ok(Some(prime_hex)) => Ok(common_primes.contains(&prime_hex.to_uppercase())),
            _ => Ok(false),
        }
    }
}
