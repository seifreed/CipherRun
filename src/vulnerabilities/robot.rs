// ROBOT (Return Of Bleichenbacher's Oracle Threat) Vulnerability Test
// CVE-2017-17382 (among others)
//
// ROBOT is a variant of Bleichenbacher's attack against RSA PKCS#1 v1.5 encryption.
// It affects TLS implementations that support RSA key exchange.

use crate::Result;
use crate::constants::{
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
    HANDSHAKE_TYPE_FINISHED, VERSION_TLS_1_0,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    async fn test_robot_oracle(&self) -> Result<RobotStatus> {
        let _addr = self.target.socket_addrs()[0];

        // Test with three different invalid RSA paddings
        let response1 = self.send_invalid_rsa_ciphertext(0).await?;
        let response2 = self.send_invalid_rsa_ciphertext(1).await?;
        let response3 = self.send_invalid_rsa_ciphertext(2).await?;

        let (Some(response1), Some(response2), Some(response3)) = (response1, response2, response3)
        else {
            return Ok(RobotStatus::Inconclusive);
        };

        // Analyze responses for padding oracle detection
        // Count unique responses to determine oracle strength
        let unique_responses = {
            let mut set = std::collections::HashSet::new();
            set.insert(&response1);
            set.insert(&response2);
            set.insert(&response3);
            set.len()
        };

        match unique_responses {
            1 => {
                // All responses identical - no observable oracle
                Ok(RobotStatus::NotVulnerable)
            }
            3 => {
                // All three responses different - strong oracle detected
                Ok(RobotStatus::Vulnerable)
            }
            2 => {
                // Two identical, one different - weak oracle
                // Further testing needed to determine exploitability
                Ok(RobotStatus::WeakOracle)
            }
            _ => Ok(RobotStatus::Inconclusive),
        }
    }

    /// Send ClientKeyExchange with invalid RSA ciphertext
    async fn send_invalid_rsa_ciphertext(&self, variant: u8) -> Result<Option<Vec<u8>>> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
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

        // Invalid RSA ciphertext (different variants)
        match variant {
            0 => {
                // All zeros
                msg.extend_from_slice(&[0x00; 128]);
            }
            1 => {
                // All ones
                msg.extend_from_slice(&[0xff; 128]);
            }
            _ => {
                // Pattern
                for i in 0..128 {
                    msg.push((i & 0xff) as u8);
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
