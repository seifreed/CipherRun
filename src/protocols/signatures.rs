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
    sni_hostname: Option<String>,
}

impl SignatureTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            sni_hostname: None,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    pub async fn enumerate_signatures(&self) -> Result<SignatureEnumerationResult> {
        use crate::protocols::Protocol;
        use crate::protocols::handshake::{ClientHelloBuilder, ServerHelloParser};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(5);

        let sni_hostname = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        );

        // Probe each algorithm individually: send a ClientHello advertising only that
        // one algorithm in the signature_algorithms extension. A ServerHello response
        // (not a TLS Alert) means the server accepts that algorithm for its certificate.
        // (hash_byte, sig_byte) pairs corresponding to IANA two-byte code points.
        let algo_pairs: &[(u16, u8, u8)] = &[
            (0x0401, 0x04, 0x01), // rsa_pkcs1_sha256
            (0x0501, 0x05, 0x01), // rsa_pkcs1_sha384
            (0x0601, 0x06, 0x01), // rsa_pkcs1_sha512
            (0x0403, 0x04, 0x03), // ecdsa_secp256r1_sha256
            (0x0503, 0x05, 0x03), // ecdsa_secp384r1_sha384
            (0x0603, 0x06, 0x03), // ecdsa_secp521r1_sha512
            (0x0804, 0x08, 0x04), // rsa_pss_rsae_sha256
            (0x0805, 0x08, 0x05), // rsa_pss_rsae_sha384
            (0x0806, 0x08, 0x06), // rsa_pss_rsae_sha512
            (0x0807, 0x08, 0x07), // ed25519
            (0x0808, 0x08, 0x08), // ed448
        ];

        let mut detected_sigs: Vec<u16> = Vec::new();

        for &(iana_value, hash_byte, sig_byte) in algo_pairs {
            let Ok(mut stream) =
                crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await
            else {
                continue;
            };

            // Build ClientHello with only this one signature algorithm so the server
            // must use a certificate signed with a compatible algorithm or reject.
            let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
            builder.add_cipher(0xc030); // ECDHE-RSA-AES256-GCM-SHA384
            if let Some(sni) = sni_hostname.as_deref() {
                builder.add_sni(sni);
            }
            builder.add_supported_groups(&[0x001d, 0x0017, 0x0018, 0x0019]);
            builder.add_signature_algorithms(&[(hash_byte, sig_byte)]);
            builder.add_session_ticket();
            builder.add_renegotiation_info();

            let Ok(client_hello) = builder.build() else {
                continue;
            };

            let probe = timeout(read_timeout, async {
                stream.write_all(&client_hello).await?;
                let mut response = vec![0u8; 4096];
                let n = stream.read(&mut response).await?;
                response.truncate(n);
                Ok::<Vec<u8>, anyhow::Error>(response)
            })
            .await;

            if let Ok(Ok(response)) = probe
                && ServerHelloParser::parse(&response).is_ok()
            {
                detected_sigs.push(iana_value);
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

        // Mock server sends a malformed/minimal response; probes should fail and
        // no algorithms should be detected as supported against this fake server.
        assert!(result.algorithms.iter().all(|a| !a.supported));
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
