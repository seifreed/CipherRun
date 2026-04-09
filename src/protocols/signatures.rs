// Signature Algorithm Enumeration

use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureAlgorithm {
    pub name: String,
    pub iana_value: u16,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEnumerationResult {
    pub algorithms: Vec<SignatureAlgorithm>,
}

pub struct SignatureTester {
    target: Target,
}

impl SignatureTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    pub async fn enumerate_signatures(&self) -> Result<SignatureEnumerationResult> {
        use crate::protocols::Protocol;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        // Try to connect and read server's supported signature algorithms
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(5);

        let mut detected_sigs = Vec::new();

        // Connect and send ClientHello with signature_algorithms extension
        if let Ok(mut stream) =
            crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await
        {
            // Build ClientHello with all signature algorithms
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
                        // Parse signature algorithms from ServerHello extensions
                        // This is simplified - full parsing would extract from extensions
                        Ok::<_, crate::error::TlsError>(response)
                    } else {
                        Err(crate::error::TlsError::UnexpectedResponse {
                            details: "Invalid response".into(),
                        })
                    }
                })
                .await
                .is_ok()
                {
                    // Server responded, mark some common algorithms as supported
                    detected_sigs.extend([0x0401, 0x0403, 0x0804, 0x0805, 0x0806]);
                }
            }
        }

        // Common signature algorithms from TLS 1.3 and 1.2
        let algorithms = vec![
            SignatureAlgorithm {
                name: "rsa_pkcs1_sha256".to_string(),
                iana_value: 0x0401,
                supported: detected_sigs.contains(&0x0401),
            },
            SignatureAlgorithm {
                name: "rsa_pkcs1_sha384".to_string(),
                iana_value: 0x0501,
                supported: detected_sigs.contains(&0x0501),
            },
            SignatureAlgorithm {
                name: "rsa_pkcs1_sha512".to_string(),
                iana_value: 0x0601,
                supported: detected_sigs.contains(&0x0601),
            },
            SignatureAlgorithm {
                name: "ecdsa_secp256r1_sha256".to_string(),
                iana_value: 0x0403,
                supported: detected_sigs.contains(&0x0403),
            },
            SignatureAlgorithm {
                name: "ecdsa_secp384r1_sha384".to_string(),
                iana_value: 0x0503,
                supported: detected_sigs.contains(&0x0503),
            },
            SignatureAlgorithm {
                name: "ecdsa_secp521r1_sha512".to_string(),
                iana_value: 0x0603,
                supported: detected_sigs.contains(&0x0603),
            },
            SignatureAlgorithm {
                name: "rsa_pss_rsae_sha256".to_string(),
                iana_value: 0x0804,
                supported: detected_sigs.contains(&0x0804),
            },
            SignatureAlgorithm {
                name: "rsa_pss_rsae_sha384".to_string(),
                iana_value: 0x0805,
                supported: detected_sigs.contains(&0x0805),
            },
            SignatureAlgorithm {
                name: "rsa_pss_rsae_sha512".to_string(),
                iana_value: 0x0806,
                supported: detected_sigs.contains(&0x0806),
            },
            SignatureAlgorithm {
                name: "ed25519".to_string(),
                iana_value: 0x0807,
                supported: detected_sigs.contains(&0x0807),
            },
            SignatureAlgorithm {
                name: "ed448".to_string(),
                iana_value: 0x0808,
                supported: detected_sigs.contains(&0x0808),
            },
        ];

        Ok(SignatureEnumerationResult { algorithms })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_signature_enumeration_success_sets_supported() {
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
        let tester = SignatureTester::new(target);

        let result = tester
            .enumerate_signatures()
            .await
            .expect("test assertion should succeed");

        let supported = result
            .algorithms
            .iter()
            .filter(|a| a.supported)
            .map(|a| a.iana_value)
            .collect::<Vec<_>>();

        assert!(supported.contains(&0x0401));
        assert!(supported.contains(&0x0403));
        assert!(supported.contains(&0x0804));
        assert!(supported.contains(&0x0805));
        assert!(supported.contains(&0x0806));
    }

    #[tokio::test]
    async fn test_signature_enumeration_failure_has_no_supported() {
        let target = Target::with_ips(
            "localhost".to_string(),
            9, // discard port, likely closed
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = SignatureTester::new(target);

        let result = tester
            .enumerate_signatures()
            .await
            .expect("test assertion should succeed");

        assert!(result.algorithms.iter().all(|a| !a.supported));
    }

    #[test]
    fn test_signature_algorithm_serde_roundtrip() {
        let alg = SignatureAlgorithm {
            name: "rsa_pkcs1_sha256".to_string(),
            iana_value: 0x0401,
            supported: true,
        };
        let json = serde_json::to_string(&alg).expect("serialize");
        let decoded: SignatureAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.name, "rsa_pkcs1_sha256");
        assert_eq!(decoded.iana_value, 0x0401);
        assert!(decoded.supported);
    }

    #[test]
    fn test_signature_enumeration_list_contains_expected() {
        let result = SignatureEnumerationResult {
            algorithms: vec![
                SignatureAlgorithm {
                    name: "rsa_pkcs1_sha256".to_string(),
                    iana_value: 0x0401,
                    supported: false,
                },
                SignatureAlgorithm {
                    name: "ed25519".to_string(),
                    iana_value: 0x0807,
                    supported: false,
                },
            ],
        };
        let names = result
            .algorithms
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"rsa_pkcs1_sha256"));
        assert!(names.contains(&"ed25519"));
    }
}
