// Key Exchange Groups Enumeration (Curves, DH groups, PQ groups)

use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupType {
    EllipticCurve,
    FiniteField,
    PostQuantum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeGroup {
    pub name: String,
    pub iana_value: u16,
    pub group_type: GroupType,
    pub bits: u16,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEnumerationResult {
    pub groups: Vec<KeyExchangeGroup>,
    pub measured: bool,
    pub details: String,
}

pub struct GroupTester {
    target: Target,
}

impl GroupTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    pub async fn enumerate_groups(&self) -> Result<GroupEnumerationResult> {
        let _ = &self.target;

        // Common key exchange groups
        let groups = vec![
            // Elliptic Curves
            KeyExchangeGroup {
                name: "secp256r1 (P-256)".to_string(),
                iana_value: 23,
                group_type: GroupType::EllipticCurve,
                bits: 256,
                supported: false,
            },
            KeyExchangeGroup {
                name: "secp384r1 (P-384)".to_string(),
                iana_value: 24,
                group_type: GroupType::EllipticCurve,
                bits: 384,
                supported: false,
            },
            KeyExchangeGroup {
                name: "secp521r1 (P-521)".to_string(),
                iana_value: 25,
                group_type: GroupType::EllipticCurve,
                bits: 521,
                supported: false,
            },
            KeyExchangeGroup {
                name: "x25519".to_string(),
                iana_value: 29,
                group_type: GroupType::EllipticCurve,
                bits: 253,
                supported: false,
            },
            KeyExchangeGroup {
                name: "x448".to_string(),
                iana_value: 30,
                group_type: GroupType::EllipticCurve,
                bits: 448,
                supported: false,
            },
            // Finite Field (DHE)
            KeyExchangeGroup {
                name: "ffdhe2048".to_string(),
                iana_value: 256,
                group_type: GroupType::FiniteField,
                bits: 2048,
                supported: false,
            },
            KeyExchangeGroup {
                name: "ffdhe3072".to_string(),
                iana_value: 257,
                group_type: GroupType::FiniteField,
                bits: 3072,
                supported: false,
            },
            KeyExchangeGroup {
                name: "ffdhe4096".to_string(),
                iana_value: 258,
                group_type: GroupType::FiniteField,
                bits: 4096,
                supported: false,
            },
            KeyExchangeGroup {
                name: "ffdhe6144".to_string(),
                iana_value: 259,
                group_type: GroupType::FiniteField,
                bits: 6144,
                supported: false,
            },
            KeyExchangeGroup {
                name: "ffdhe8192".to_string(),
                iana_value: 260,
                group_type: GroupType::FiniteField,
                bits: 8192,
                supported: false,
            },
            // Post-Quantum
            KeyExchangeGroup {
                name: "X25519Kyber768Draft00".to_string(),
                iana_value: 0x6399,
                group_type: GroupType::PostQuantum,
                bits: 768,
                supported: false,
            },
            KeyExchangeGroup {
                name: "X25519MLKEM768".to_string(),
                iana_value: 0x11EB,
                group_type: GroupType::PostQuantum,
                bits: 768,
                supported: false,
            },
        ];

        Ok(GroupEnumerationResult {
            groups,
            measured: false,
            details:
                "Supported groups are not marked because this code path does not parse real group negotiation yet"
                    .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_group_enumeration_success_is_inconclusive_without_real_parsing() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let _ = socket.try_write(&[0x16, 0x03, 0x03, 0x00, 0x01]);
            }
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("test assertion should succeed");
        let tester = GroupTester::new(target);

        let result = tester
            .enumerate_groups()
            .await
            .expect("test assertion should succeed");

        assert!(!result.measured);
        assert!(result.groups.iter().all(|g| !g.supported));
        assert!(result.details.contains("does not parse real group negotiation"));
    }

    #[tokio::test]
    async fn test_group_enumeration_failure_has_no_supported() {
        let target = Target::with_ips(
            "localhost".to_string(),
            9, // discard port, likely closed
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = GroupTester::new(target);

        let result = tester
            .enumerate_groups()
            .await
            .expect("test assertion should succeed");

        assert!(result.groups.iter().all(|g| !g.supported));
    }

    #[test]
    fn test_group_type_serde_roundtrip() {
        let group = GroupType::PostQuantum;
        let json = serde_json::to_string(&group).expect("serialize");
        let decoded: GroupType = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, GroupType::PostQuantum));
    }

    #[test]
    fn test_group_enumeration_result_empty() {
        let result = GroupEnumerationResult {
            groups: Vec::new(),
            measured: false,
            details: String::new(),
        };
        assert!(result.groups.is_empty());
    }
}
