// ROBOT (Return Of Bleichenbacher's Oracle Threat) Vulnerability Test
// CVE-2017-17382 (among others)
//
// ROBOT is a variant of Bleichenbacher's attack against RSA PKCS#1 v1.5 encryption.
// It affects TLS implementations that support RSA key exchange.

use crate::Result;
use crate::constants::{
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
    HANDSHAKE_TYPE_FINISHED, TLS_HANDSHAKE_TIMEOUT, VERSION_TLS_1_0,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// ROBOT vulnerability tester
pub struct RobotTester {
    target: Target,
}

impl RobotTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for ROBOT vulnerability
    pub async fn test(&self) -> Result<RobotTestResult> {
        let result = self.test_robot_oracle().await?;

        let details = match result {
            RobotStatus::Vulnerable => {
                "Vulnerable to ROBOT attack - Server responds differently to invalid RSA padding"
                    .to_string()
            }
            RobotStatus::WeakOracle => {
                "Potentially vulnerable - Weak oracle detected, may be exploitable".to_string()
            }
            RobotStatus::NotVulnerable => {
                "Not vulnerable - No RSA padding oracle detected".to_string()
            }
            RobotStatus::Inconclusive => {
                "ROBOT test inconclusive - transport or handshake failures prevented a reliable oracle comparison".to_string()
            }
        };

        Ok(RobotTestResult {
            vulnerable: matches!(result, RobotStatus::Vulnerable | RobotStatus::WeakOracle),
            status: result,
            details,
        })
    }

    /// Test for ROBOT padding oracle
    ///
    /// Uses multiple test vectors to detect Bleichenbacher-style padding oracles.
    /// Testing methodology based on ROBOT attack research which found that different
    /// error codes or timing differences can reveal oracle behavior.
    async fn test_robot_oracle(&self) -> Result<RobotStatus> {
        // Test with multiple different invalid RSA paddings
        // ROBOT research shows that 3+ test vectors can reveal oracle behavior
        // but we should use timing analysis as well for robust detection
        const TEST_VECTORS: usize = 5;
        const MIN_SAMPLES: usize = 3;

        let mut responses: Vec<Option<Vec<u8>>> = Vec::with_capacity(TEST_VECTORS);

        for i in 0..TEST_VECTORS {
            let response = self.send_invalid_rsa_ciphertext(i as u8).await?;
            responses.push(response);

            // Small delay to avoid rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Count successful responses
        let successful_responses: Vec<_> = responses.iter().filter_map(|r| r.as_ref()).collect();

        if successful_responses.len() < MIN_SAMPLES {
            // Not enough successful responses - inconclusive
            return Ok(RobotStatus::Inconclusive);
        }

        // Analyze responses for padding oracle detection
        // Count unique response patterns (by error codes and lengths)
        let mut response_patterns: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        let mut error_codes: std::collections::HashSet<u8> = std::collections::HashSet::new();
        let mut response_lengths: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        for response in &successful_responses {
            // Extract alert error code if present (TLS alert format: 0x15 0x03 0x03 0x00 0x02 <level> <description>)
            if response.len() >= 7 && response[0] == 0x15 {
                let error_code = response[6];
                error_codes.insert(error_code);
            }
            response_lengths.insert(response.len());

            // Create a pattern from first N bytes for comparison
            let pattern_len = response.len().min(32);
            response_patterns.insert(response[..pattern_len].to_vec());
        }

        // Detection logic:
        // 1. Different error codes indicate oracle (server distinguishes padding errors)
        // 2. Different response lengths may indicate oracle behavior
        // 3. Different response patterns indicate observable differences

        let unique_error_codes = error_codes.len();
        let unique_patterns = response_patterns.len();

        // Strong oracle: Different error codes or many unique response patterns
        if unique_error_codes > 1 || unique_patterns >= 3 {
            return Ok(RobotStatus::Vulnerable);
        }

        // Weak oracle: Two distinct response patterns indicate observable differences.
        // However, we need additional validation to avoid false positives from noise.
        // Response length alone is NOT a reliable oracle indicator — network fragmentation,
        // error message variation, and TCP buffering can cause length differences without
        // revealing padding validity.
        //
        // To be classified as a weak oracle, two patterns must:
        // 1. Be genuinely different (not just a few bytes apart)
        // 2. Have sufficient byte-level differences to indicate real oracle behavior
        if unique_patterns == 2 {
            // Calculate the actual byte-level difference between the two patterns
            let patterns: Vec<_> = response_patterns.iter().collect();
            if patterns.len() == 2 {
                let p1 = patterns[0];
                let p2 = patterns[1];

                // Count byte-level differences between patterns
                let min_len = p1.len().min(p2.len());
                let mut byte_differences = 0;
                for i in 0..min_len {
                    if p1.get(i) != p2.get(i) {
                        byte_differences += 1;
                    }
                }
                // Add length difference as additional divergence
                let len_difference = (p1.len() as isize - p2.len() as isize).unsigned_abs();
                byte_differences += len_difference;

                // Adaptive threshold: use absolute count OR relative percentage
                const MIN_BYTE_DIFFERENCES: usize = 4;
                const MIN_RELATIVE_DIFFERENCE: f64 = 0.1; // 10% of pattern length

                let pattern_len = p1.len().max(p2.len()) as f64;
                let relative_diff = if pattern_len > 0.0 {
                    byte_differences as f64 / pattern_len
                } else {
                    0.0
                };

                // Consider it a weak oracle if:
                // 1. Absolute difference >= MIN_BYTE_DIFFERENCES, OR
                // 2. Relative difference >= 10% of the longer pattern
                if byte_differences >= MIN_BYTE_DIFFERENCES
                    || relative_diff >= MIN_RELATIVE_DIFFERENCE
                {
                    tracing::debug!(
                        "ROBOT: Weak oracle detected - {} byte differences ({:.1}% of {} bytes)",
                        byte_differences,
                        relative_diff * 100.0,
                        pattern_len as usize
                    );
                    return Ok(RobotStatus::WeakOracle);
                }

                // Borderline case (2-3 byte differences): log for manual investigation
                if byte_differences >= 2 {
                    tracing::info!(
                        "ROBOT: Borderline detection - {} byte differences ({:.1}% of pattern), manual investigation recommended",
                        byte_differences,
                        relative_diff * 100.0
                    );
                }

                // Fewer differences - could be noise, classify as not vulnerable
                tracing::debug!(
                    "ROBOT: Two patterns detected but only {} byte differences (min: {} or {:.0}%), likely noise",
                    byte_differences,
                    MIN_BYTE_DIFFERENCES,
                    MIN_RELATIVE_DIFFERENCE * 100.0
                );
            }
        }

        // All responses identical - no observable oracle
        Ok(RobotStatus::NotVulnerable)
    }

    /// Send ClientKeyExchange with invalid RSA ciphertext
    async fn send_invalid_rsa_ciphertext(&self, variant: u8) -> Result<Option<Vec<u8>>> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;

        let mut stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

        // Send ClientHello
        let client_hello = self.build_client_hello();
        stream.write_all(&client_hello).await?;

        // Read ServerHello, Certificate, ServerHelloDone
        let mut buffer = vec![0u8; 8192];
        timeout(Duration::from_secs(3), stream.read(&mut buffer)).await??;

        // Send ClientKeyExchange with invalid padding
        let client_key_exchange = self.build_invalid_client_key_exchange(variant);
        stream.write_all(&client_key_exchange).await?;

        // Send ChangeCipherSpec
        let ccs = vec![
            CONTENT_TYPE_CHANGE_CIPHER_SPEC, // 0x14
            0x03,
            0x03, // TLS 1.2 version
            0x00,
            0x01, // Length: 1 byte
            0x01, // CCS message
        ];
        stream.write_all(&ccs).await?;

        // Send Finished (will be invalid)
        let finished = self.build_finished();
        stream.write_all(&finished).await?;

        // Read server's response
        let mut response = vec![0u8; 1024];
        match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                response.truncate(n);
                Ok(Some(response))
            }
            _ => Ok(None),
        }
    }

    /// Build ClientHello with RSA key exchange using ClientHelloBuilder
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_rsa_key_exchange();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
    }

    /// Build ClientKeyExchange with invalid RSA padding
    fn build_invalid_client_key_exchange(&self, variant: u8) -> Vec<u8> {
        let mut msg = vec![
            CONTENT_TYPE_HANDSHAKE,         // TLS Record: Handshake (0x16)
            (VERSION_TLS_1_0 >> 8) as u8,   // 0x03
            (VERSION_TLS_1_0 & 0xff) as u8, // 0x01
            0x00,
            0x86,                               // Length (134 bytes)
            HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, // Handshake: ClientKeyExchange (0x10)
            0x00,
            0x00,
            0x82, // Handshake length (130 bytes)
            0x00,
            0x80, // Encrypted PMS length (128 bytes for 1024-bit RSA)
        ];

        // Invalid RSA ciphertext (different variants for oracle detection)
        match variant {
            0 => {
                // All zeros
                msg.extend_from_slice(&[0x00; 128]);
            }
            1 => {
                // All ones
                msg.extend_from_slice(&[0xff; 128]);
            }
            2 => {
                // Sequential pattern
                for i in 0..128 {
                    msg.push((i & 0xff) as u8);
                }
            }
            3 => {
                // Alternating pattern
                for i in 0..128 {
                    msg.push(if i % 2 == 0 { 0xAA } else { 0x55 });
                }
            }
            _ => {
                // Random-looking pattern (deterministic based on variant)
                for i in 0..128 {
                    msg.push(((i as u16 * 179 + variant as u16 * 37) & 0xff) as u8);
                }
            }
        }

        msg
    }

    /// Build Finished message
    fn build_finished(&self) -> Vec<u8> {
        vec![
            CONTENT_TYPE_HANDSHAKE,         // Record header (0x16)
            (VERSION_TLS_1_0 >> 8) as u8,   // 0x03
            (VERSION_TLS_1_0 & 0xff) as u8, // 0x01
            0x00,
            0x10,                    // Length
            HANDSHAKE_TYPE_FINISHED, // Finished (0x14)
            0x00,
            0x00,
            0x0c, // Length
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // Verify data (invalid)
        ]
    }
}

/// ROBOT status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RobotStatus {
    Vulnerable,
    WeakOracle,
    NotVulnerable,
    Inconclusive,
}

/// ROBOT test result
#[derive(Debug, Clone)]
pub struct RobotTestResult {
    pub vulnerable: bool,
    pub status: RobotStatus,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_robot_status() {
        assert_eq!(RobotStatus::Vulnerable, RobotStatus::Vulnerable);
        assert_ne!(RobotStatus::Vulnerable, RobotStatus::NotVulnerable);
    }

    #[test]
    fn test_robot_result() {
        let result = RobotTestResult {
            vulnerable: true,
            status: RobotStatus::Vulnerable,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
    }

    #[test]
    fn test_build_invalid_client_key_exchange_variants() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = RobotTester::new(target);

        let msg0 = tester.build_invalid_client_key_exchange(0);
        let msg1 = tester.build_invalid_client_key_exchange(1);
        let msg2 = tester.build_invalid_client_key_exchange(2);

        assert_eq!(msg0.len(), msg1.len());
        assert_eq!(msg1.len(), msg2.len());
        assert!(msg0.len() >= 128);
        assert_ne!(msg0, msg1);
    }

    #[test]
    fn test_build_finished_structure() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = RobotTester::new(target);
        let msg = tester.build_finished();
        assert_eq!(msg[0], CONTENT_TYPE_HANDSHAKE);
        assert_eq!(msg[5], HANDSHAKE_TYPE_FINISHED);
    }

    #[test]
    fn test_build_client_hello_non_empty() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = RobotTester::new(target);
        let hello = tester.build_client_hello();
        assert!(!hello.is_empty());
        assert_eq!(hello[0], CONTENT_TYPE_HANDSHAKE);
    }

    #[test]
    fn test_invalid_client_key_exchange_payload_patterns() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = RobotTester::new(target);

        let msg0 = tester.build_invalid_client_key_exchange(0);
        let msg1 = tester.build_invalid_client_key_exchange(1);
        let msg2 = tester.build_invalid_client_key_exchange(2);

        let payload0 = &msg0[msg0.len() - 128..];
        let payload1 = &msg1[msg1.len() - 128..];
        let payload2 = &msg2[msg2.len() - 128..];

        assert!(payload0.iter().all(|b| *b == 0x00));
        assert!(payload1.iter().all(|b| *b == 0xff));
        assert_ne!(payload0, payload2);
    }

    #[test]
    fn test_robot_result_details() {
        let result = RobotTestResult {
            vulnerable: false,
            status: RobotStatus::NotVulnerable,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(result.details.contains("Not vulnerable"));
    }

    #[test]
    fn test_robot_result_debug_contains_status() {
        let result = RobotTestResult {
            vulnerable: true,
            status: RobotStatus::Vulnerable,
            details: "Details".to_string(),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("Vulnerable"));
    }
}
