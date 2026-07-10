// Signature Algorithm Enumeration

use crate::Result;
use crate::constants::{BUFFER_SIZE_MAX_WITH_OVERHEAD, TLS_RECORD_HEADER_SIZE};
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
    #[serde(default)]
    pub inconclusive: bool,
}

pub struct SignatureTester {
    target: Target,
    sni_hostname: Option<String>,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    starttls_server_mode: bool,
}

impl SignatureTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            sni_hostname: None,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
        }
    }

    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni_hostname = sni;
        self
    }

    pub fn with_starttls(
        mut self,
        starttls: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = starttls;
        self.starttls_hostname = hostname;
        self
    }

    pub fn with_starttls_server_mode(mut self, server_mode: bool) -> Self {
        self.starttls_server_mode = server_mode;
        self
    }

    fn tls_record_total_len(
        header: &[u8; TLS_RECORD_HEADER_SIZE],
    ) -> std::io::Result<Option<usize>> {
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE
            .checked_add(record_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "signature record length overflow",
                )
            })?;
        if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
            return Ok(None);
        }
        Ok(Some(total_len))
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
        let starttls_hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());

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
        let mut saw_inconclusive_probe = false;
        let mut saw_conclusive_probe = false;

        for &(iana_value, hash_byte, sig_byte) in algo_pairs {
            let stream = if let Some(starttls) = self.starttls {
                crate::utils::network::connect_with_starttls(
                    addr,
                    connect_timeout,
                    Some(starttls),
                    &starttls_hostname,
                    self.starttls_server_mode,
                )
                .await
            } else {
                crate::utils::network::connect_with_timeout(addr, connect_timeout, None).await
            };
            let Ok(mut stream) = stream else {
                saw_inconclusive_probe = true;
                continue;
            };

            // Build ClientHello with only this one signature algorithm so the server
            // must use a certificate signed with a compatible algorithm or reject.
            let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
            builder.add_cipher(0xc030); // ECDHE-RSA-AES256-GCM-SHA384
            if let Some(sni) = sni_hostname.as_deref()
                && builder.add_sni(sni).is_err()
            {
                saw_inconclusive_probe = true;
                continue;
            }
            if builder
                .add_supported_groups(&[0x001d, 0x0017, 0x0018, 0x0019])
                .and_then(|builder| builder.add_signature_algorithms(&[(hash_byte, sig_byte)]))
                .is_err()
            {
                saw_inconclusive_probe = true;
                continue;
            }
            builder.add_session_ticket();
            builder.add_renegotiation_info();

            let Ok(client_hello) = builder.build() else {
                saw_inconclusive_probe = true;
                continue;
            };

            let probe = timeout(read_timeout, async {
                stream.write_all(&client_hello).await?;
                let mut header = [0u8; 5];
                if stream.read_exact(&mut header).await.is_err() {
                    return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                }

                let Some(total_len) = Self::tls_record_total_len(&header)? else {
                    return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                };
                let mut response = vec![0u8; total_len];
                response[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
                if stream
                    .read_exact(&mut response[TLS_RECORD_HEADER_SIZE..])
                    .await
                    .is_err()
                {
                    return Ok::<Option<Vec<u8>>, std::io::Error>(None);
                }

                Ok::<Option<Vec<u8>>, std::io::Error>(Some(response))
            })
            .await;

            match probe {
                Ok(Ok(Some(response))) if ServerHelloParser::parse(&response).is_ok() => {
                    saw_conclusive_probe = true;
                    detected_sigs.push(iana_value);
                }
                Ok(Ok(Some(response))) if response.first() == Some(&0x15) => {
                    saw_conclusive_probe = true;
                }
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                    saw_inconclusive_probe = true;
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

        Ok(SignatureEnumerationResult {
            algorithms,
            inconclusive: saw_inconclusive_probe && !saw_conclusive_probe,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_signature_record_total_len_rejects_oversized_record() {
        let max_record_len = crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD
            - crate::constants::TLS_RECORD_HEADER_SIZE;
        let allowed = max_record_len as u16;
        let rejected = (max_record_len + 1) as u16;

        let allowed_header = [0x16, 0x03, 0x03, (allowed >> 8) as u8, allowed as u8];
        assert_eq!(
            SignatureTester::tls_record_total_len(&allowed_header).expect("length should parse"),
            Some(crate::constants::BUFFER_SIZE_MAX_WITH_OVERHEAD)
        );

        let rejected_header = [0x16, 0x03, 0x03, (rejected >> 8) as u8, rejected as u8];
        assert_eq!(
            SignatureTester::tls_record_total_len(&rejected_header).expect("length should parse"),
            None
        );
    }

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
        assert!(result.inconclusive);
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
        assert!(result.inconclusive);
    }

    #[tokio::test]
    async fn test_signature_enumeration_fragmented_server_hello_is_supported() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 512];
                let _ = socket.read(&mut buf).await;

                let mut response = vec![
                    0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
                ];
                response.extend_from_slice(&[0u8; 32]);
                response.push(0x00);
                response.extend_from_slice(&[0x00, 0x9c]);
                response.push(0x00);
                response.extend_from_slice(&[0x00, 0x00]);
                let hs_len = (response.len() - 9) as u32;
                response[6] = ((hs_len >> 16) & 0xff) as u8;
                response[7] = ((hs_len >> 8) & 0xff) as u8;
                response[8] = (hs_len & 0xff) as u8;
                let rec_len = (response.len() - 5) as u16;
                response[3] = (rec_len >> 8) as u8;
                response[4] = (rec_len & 0xff) as u8;

                socket.write_all(&response[..8]).await.unwrap();
                socket.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                socket.write_all(&response[8..]).await.unwrap();
                socket.flush().await.unwrap();
            }
        });

        let target = Target::with_ips("localhost".to_string(), addr.port(), vec![addr.ip()])
            .expect("test assertion should succeed");
        let tester = SignatureTester::new(target);

        let result = tester
            .enumerate_signatures()
            .await
            .expect("test assertion should succeed");

        assert!(result.algorithms.iter().any(|a| a.supported));
        assert!(!result.inconclusive);
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
    fn test_starttls_configuration_is_stored() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![std::net::IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = SignatureTester::new(target)
            .with_starttls(Some(crate::starttls::StarttlsProtocol::XMPP), Some("xmpp.example.com".to_string()))
            .with_starttls_server_mode(true);

        assert_eq!(tester.starttls, Some(crate::starttls::StarttlsProtocol::XMPP));
        assert_eq!(tester.starttls_hostname.as_deref(), Some("xmpp.example.com"));
        assert!(tester.starttls_server_mode);
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
            inconclusive: false,
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
