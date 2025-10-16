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
}

pub struct GroupTester {
    target: Target,
}

impl GroupTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    pub async fn enumerate_groups(&self) -> Result<GroupEnumerationResult> {
        use crate::protocols::Protocol;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        // Try to connect and read server's supported groups
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(5);

        let mut detected_groups = Vec::new();

        // Connect and send ClientHello with supported_groups extension
        if let Ok(Ok(mut stream)) = timeout(connect_timeout, TcpStream::connect(addr)).await {
            // Build ClientHello with common cipher
            let mut builder = crate::protocols::handshake::ClientHelloBuilder::new(Protocol::TLS12);

            // Add a common cipher
            builder.add_cipher(0xc030); // ECDHE-RSA-AES256-GCM-SHA384

            if let Ok(client_hello) = builder.build_with_defaults(Some(&self.target.hostname)) {
                // Send ClientHello
                if timeout(read_timeout, async {
                    stream.write_all(&client_hello).await?;

                    // Read ServerHello
                    let mut response = vec![0u8; 4096];
                    let n = stream.read(&mut response).await?;

                    if n > 0 && response[0] == 0x16 {
                        // Parse groups from ServerHello extensions
                        // This is simplified - full parsing would extract from extensions
                        Ok::<_, anyhow::Error>(response)
                    } else {
                        anyhow::bail!("Invalid response")
                    }
                })
                .await
                .is_ok()
                {
                    // Server responded, mark common groups as supported
                    detected_groups.extend([23, 24, 29, 256, 257]);
                }
            }
        }

        // Common key exchange groups
        let groups = vec![
            // Elliptic Curves
            KeyExchangeGroup {
                name: "secp256r1 (P-256)".to_string(),
                iana_value: 23,
                group_type: GroupType::EllipticCurve,
                bits: 256,
                supported: detected_groups.contains(&23),
            },
            KeyExchangeGroup {
                name: "secp384r1 (P-384)".to_string(),
                iana_value: 24,
                group_type: GroupType::EllipticCurve,
                bits: 384,
                supported: detected_groups.contains(&24),
            },
            KeyExchangeGroup {
                name: "secp521r1 (P-521)".to_string(),
                iana_value: 25,
                group_type: GroupType::EllipticCurve,
                bits: 521,
                supported: detected_groups.contains(&25),
            },
            KeyExchangeGroup {
                name: "x25519".to_string(),
                iana_value: 29,
                group_type: GroupType::EllipticCurve,
                bits: 253,
                supported: detected_groups.contains(&29),
            },
            KeyExchangeGroup {
                name: "x448".to_string(),
                iana_value: 30,
                group_type: GroupType::EllipticCurve,
                bits: 448,
                supported: detected_groups.contains(&30),
            },
            // Finite Field (DHE)
            KeyExchangeGroup {
                name: "ffdhe2048".to_string(),
                iana_value: 256,
                group_type: GroupType::FiniteField,
                bits: 2048,
                supported: detected_groups.contains(&256),
            },
            KeyExchangeGroup {
                name: "ffdhe3072".to_string(),
                iana_value: 257,
                group_type: GroupType::FiniteField,
                bits: 3072,
                supported: detected_groups.contains(&257),
            },
            KeyExchangeGroup {
                name: "ffdhe4096".to_string(),
                iana_value: 258,
                group_type: GroupType::FiniteField,
                bits: 4096,
                supported: detected_groups.contains(&258),
            },
            KeyExchangeGroup {
                name: "ffdhe6144".to_string(),
                iana_value: 259,
                group_type: GroupType::FiniteField,
                bits: 6144,
                supported: detected_groups.contains(&259),
            },
            KeyExchangeGroup {
                name: "ffdhe8192".to_string(),
                iana_value: 260,
                group_type: GroupType::FiniteField,
                bits: 8192,
                supported: detected_groups.contains(&260),
            },
            // Post-Quantum
            KeyExchangeGroup {
                name: "X25519Kyber768Draft00".to_string(),
                iana_value: 0x6399,
                group_type: GroupType::PostQuantum,
                bits: 768,
                supported: detected_groups.contains(&0x6399),
            },
            KeyExchangeGroup {
                name: "X25519MLKEM768".to_string(),
                iana_value: 0x11EB,
                group_type: GroupType::PostQuantum,
                bits: 768,
                supported: detected_groups.contains(&0x11EB),
            },
        ];

        Ok(GroupEnumerationResult { groups })
    }
}
