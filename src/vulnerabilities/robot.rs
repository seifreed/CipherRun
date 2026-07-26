// ROBOT (Return Of Bleichenbacher's Oracle Threat) Vulnerability Test
// CVE-2017-17382 (among others)
//
// ROBOT is a variant of Bleichenbacher's attack against RSA PKCS#1 v1.5 encryption.
// It affects TLS implementations that support RSA key exchange.

use crate::Result;
use crate::constants::{CONTENT_TYPE_CHANGE_CIPHER_SPEC, TLS_HANDSHAKE_TIMEOUT};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

mod alert_signal;
mod certificate;
mod client_hello;
mod messages;
mod oracle_analysis;
mod result;

pub use result::{RobotStatus, RobotTestResult};

/// ROBOT vulnerability tester
pub struct RobotTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
    test_all_ips: bool,
}

impl RobotTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
            test_all_ips: false,
        }
    }

    /// Configure STARTTLS negotiation before each ROBOT oracle probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
        server_mode: bool,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, test_all_ips: bool) -> Self {
        self.test_all_ips = test_all_ips;
        self
    }

    fn probe_addrs(&self) -> Result<Vec<std::net::SocketAddr>> {
        crate::utils::target_addrs::socket_addrs_for_probe(&self.target, self.test_all_ips)
    }

    /// Test for ROBOT vulnerability
    pub async fn test(&self) -> Result<RobotTestResult> {
        Ok(RobotTestResult::from_status(
            self.test_robot_oracle().await?,
        ))
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

        // A real Bleichenbacher oracle is deterministic: a given malformed padding
        // always yields the same alert. Multi-backend CDNs / load balancers return
        // varying alerts for the SAME input across separate connections, which must
        // not be mistaken for an oracle. Probe each vector across multiple rounds
        // and keep the responses per vector so the verdict can require per-vector
        // determinism before reporting an oracle.
        const CONFIRMATION_ROUNDS: usize = 2;
        let mut responses: Vec<Option<Vec<u8>>> =
            Vec::with_capacity(TEST_VECTORS * CONFIRMATION_ROUNDS);
        let mut per_vector: Vec<Vec<Vec<u8>>> = vec![Vec::new(); TEST_VECTORS];

        for _round in 0..CONFIRMATION_ROUNDS {
            for (i, vector_responses) in per_vector.iter_mut().enumerate() {
                // A transient error is recorded as a missing sample rather than
                // aborting the whole probe set (MIN_SAMPLES gates the verdict).
                let variant = u8::try_from(i).map_err(|_| crate::TlsError::InvalidInput {
                    message: "ROBOT test vector index exceeds u8".to_string(),
                })?;
                match self.send_invalid_rsa_ciphertext(variant).await {
                    Ok(Some(response)) => {
                        vector_responses.push(response.clone());
                        responses.push(Some(response));
                    }
                    Ok(None) => responses.push(None),
                    Err(err) => {
                        tracing::debug!(
                            "ROBOT probe {} failed transiently ({}); recording as missing sample",
                            i,
                            err
                        );
                        responses.push(None);
                    }
                }

                // Small delay to avoid rate limiting
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        // Count successful responses
        let successful_responses: Vec<_> = responses.iter().filter_map(|r| r.as_ref()).collect();

        if successful_responses.len() < MIN_SAMPLES {
            // Not enough successful responses - inconclusive
            return Ok(RobotStatus::Inconclusive);
        }

        Ok(oracle_analysis::classify_responses(
            &successful_responses,
            &per_vector,
            CONFIRMATION_ROUNDS,
        ))
    }

    /// Send ClientKeyExchange with invalid RSA ciphertext
    async fn send_invalid_rsa_ciphertext(&self, variant: u8) -> Result<Option<Vec<u8>>> {
        for addr in self.probe_addrs()? {
            if let Some(response) = self.send_invalid_rsa_ciphertext_addr(addr, variant).await? {
                return Ok(Some(response));
            }
        }
        Ok(None)
    }

    async fn send_invalid_rsa_ciphertext_addr(
        &self,
        addr: std::net::SocketAddr,
        variant: u8,
    ) -> Result<Option<Vec<u8>>> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        let mut stream = match crate::utils::network::connect_with_starttls(
            addr,
            TLS_HANDSHAKE_TIMEOUT,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        // Send ClientHello
        let client_hello = client_hello::tls10_rsa()?;
        stream.write_all(&client_hello).await?;

        // Read until ServerHelloDone so the full certificate chain is in the buffer,
        // even for large chains (e.g. RSA-4096) that span multiple TLS records.
        let mut buffer = vec![0u8; 32768];
        let mut total = 0usize;
        while let Some(read_buffer) = buffer.get_mut(total..) {
            let n = match timeout(Duration::from_secs(3), stream.read(read_buffer)).await {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            let Some(accumulated) = buffer.get(..total) else {
                break;
            };
            if super::handshake_read::has_server_hello_done(accumulated) || total >= buffer.len() {
                break;
            }
        }
        if total == 0 {
            return Ok(None);
        }
        buffer.truncate(total);

        // Determine the server's RSA key size from the Certificate message so we send
        // the right payload length (128 bytes for RSA-1024, 256 for RSA-2048, etc.).
        let rsa_key_len = certificate::extract_rsa_key_len(&buffer)?;

        // Send ClientKeyExchange with invalid padding
        let client_key_exchange = messages::invalid_client_key_exchange(variant, rsa_key_len)?;
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
        let finished = messages::finished();
        stream.write_all(&finished).await?;

        self.read_first_response_record(&mut stream, Duration::from_secs(2))
            .await
    }

    async fn read_first_response_record(
        &self,
        stream: &mut tokio::net::TcpStream,
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        let mut header = [0u8; 5];
        match timeout(timeout_duration, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(None),
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = match 5usize.checked_add(record_len) {
            Some(len) if len <= 1024 => len,
            _ => return Ok(None),
        };

        let mut response = vec![0u8; total_len];
        response[..5].copy_from_slice(&header);
        match timeout(timeout_duration, stream.read_exact(&mut response[5..])).await {
            Ok(Ok(_)) => Ok(Some(response)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_FINISHED};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use std::net::IpAddr;

    #[test]
    fn test_robot_status() {
        assert_eq!(RobotStatus::Vulnerable, RobotStatus::Vulnerable);
        assert_ne!(RobotStatus::Vulnerable, RobotStatus::NotVulnerable);
    }

    #[test]
    fn test_robot_probe_addrs_honors_all_ips() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let single = RobotTester::new(target.clone()).probe_addrs().unwrap();
        let all = RobotTester::new(target)
            .with_test_all_ips(true)
            .probe_addrs()
            .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_build_invalid_client_key_exchange_variants() {
        let msg0 =
            messages::invalid_client_key_exchange(0, 256).expect("ClientKeyExchange should build");
        let msg1 =
            messages::invalid_client_key_exchange(1, 256).expect("ClientKeyExchange should build");
        let msg2 =
            messages::invalid_client_key_exchange(2, 256).expect("ClientKeyExchange should build");

        assert_eq!(msg0.len(), msg1.len());
        assert_eq!(msg1.len(), msg2.len());
        assert!(msg0.len() >= 256);
        assert_ne!(msg0, msg1);
    }

    #[test]
    fn test_build_finished_structure() {
        let msg = messages::finished();
        assert_eq!(msg.first(), Some(&CONTENT_TYPE_HANDSHAKE));
        assert_eq!(msg.get(5), Some(&HANDSHAKE_TYPE_FINISHED));
    }

    #[test]
    fn test_build_client_hello_non_empty() {
        let hello = client_hello::tls10_rsa().expect("ClientHello should build");
        assert!(!hello.is_empty());
        assert_eq!(hello.first(), Some(&CONTENT_TYPE_HANDSHAKE));
    }

    #[test]
    fn test_invalid_client_key_exchange_payload_patterns() {
        let msg0 =
            messages::invalid_client_key_exchange(0, 128).expect("ClientKeyExchange should build");
        let msg1 =
            messages::invalid_client_key_exchange(1, 128).expect("ClientKeyExchange should build");
        let msg2 =
            messages::invalid_client_key_exchange(2, 128).expect("ClientKeyExchange should build");

        let payload0 = msg0
            .get(msg0.len() - 128..)
            .expect("test message should contain payload");
        let payload1 = msg1
            .get(msg1.len() - 128..)
            .expect("test message should contain payload");
        let payload2 = msg2
            .get(msg2.len() - 128..)
            .expect("test message should contain payload");

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

    #[test]
    fn test_extract_rsa_key_len_rejects_missing_certificate() {
        let err = certificate::extract_rsa_key_len(&[]).expect_err("missing handshake should fail");
        assert!(
            err.to_string()
                .contains("Unable to determine RSA key length")
        );
    }

    #[test]
    fn test_extract_rsa_key_len_rejects_certificate_beyond_handshake() {
        let rsa = Rsa::generate(2048).expect("RSA key should generate");
        let pkey = PKey::from_rsa(rsa).expect("PKey should build");
        let mut name = X509NameBuilder::new().expect("name builder should build");
        name.append_entry_by_text("CN", "robot.test")
            .expect("CN should set");
        let name = name.build();

        let mut builder = X509Builder::new().expect("X509 builder should build");
        builder.set_version(2).expect("version should set");
        builder.set_subject_name(&name).expect("subject should set");
        builder.set_issuer_name(&name).expect("issuer should set");
        builder.set_pubkey(&pkey).expect("pubkey should set");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("not_before should build"))
            .expect("not_before should set");
        builder
            .set_not_after(&Asn1Time::days_from_now(30).expect("not_after should build"))
            .expect("not_after should set");
        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("cert should sign");
        let cert_der = builder.build().to_der().expect("cert DER should serialize");

        let cert_len = cert_der.len();
        let mut record = vec![
            0x16,
            0x03,
            0x03,
            0x00,
            0x00, // record header
            0x0b,
            0x00,
            0x00,
            0x06, // Certificate hs_len excludes DER
            0x00,
            0x00,
            0x00, // certificate_list length placeholder
            ((cert_len >> 16) & 0xff) as u8,
            ((cert_len >> 8) & 0xff) as u8,
            (cert_len & 0xff) as u8,
        ];
        record.extend_from_slice(&cert_der);
        let record_len = record.len() - 5;
        record[3] = ((record_len >> 8) & 0xff) as u8;
        record[4] = (record_len & 0xff) as u8;

        let err = certificate::extract_rsa_key_len(&record)
            .expect_err("certificate bytes outside hs_len must be ignored");
        assert!(
            err.to_string()
                .contains("ROBOT Certificate list length mismatch")
        );
    }

    #[test]
    fn test_extract_rsa_key_len_rejects_certificate_list_mismatch() {
        let record = [
            0x16, 0x03, 0x03, 0x00, 0x0a, // record header
            0x0b, 0x00, 0x00, 0x06, // Certificate handshake
            0x00, 0x00, 0x02, // list claims 2 bytes, but body has 3 bytes after list len
            0x00, 0x00, 0x00,
        ];

        let err =
            certificate::extract_rsa_key_len(&record).expect_err("mismatched list should fail");
        assert!(
            err.to_string()
                .contains("ROBOT Certificate list length mismatch")
        );
    }

    #[test]
    fn test_alert_description_code_rejects_trailing_bytes() {
        let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert_eq!(alert_signal::alert_description_code(&response), None);
    }

    #[test]
    fn test_robot_alert_code_signal_requires_confirmed_samples() {
        let alert_46 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let alert_47 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x47];
        let per_vector = vec![vec![alert_46], vec![alert_47]];

        assert_eq!(
            alert_signal::classify(&per_vector, 2),
            alert_signal::CodeSignal::Inconclusive
        );
    }

    #[test]
    fn test_robot_alert_code_signal_flags_confirmed_oracle() {
        let alert_46 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
        let alert_47 = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x47];
        let per_vector = vec![
            vec![alert_46.clone(), alert_46],
            vec![alert_47.clone(), alert_47],
        ];

        assert_eq!(
            alert_signal::classify(&per_vector, 2),
            alert_signal::CodeSignal::ConfirmedOracle
        );
    }

    #[tokio::test]
    async fn test_robot_reads_fragmented_final_alert_record() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            server.write_all(&[0x15, 0x03, 0x03]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            server.write_all(&[0x00, 0x02, 0x02, 0x46]).await.unwrap();
        });

        let mut header = [0u8; 5];
        timeout(Duration::from_secs(2), client.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut response = vec![0u8; 5 + record_len];
        response[..5].copy_from_slice(&header);
        timeout(
            Duration::from_secs(2),
            client.read_exact(&mut response[5..]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46]);

        writer.await.unwrap();
    }
}
