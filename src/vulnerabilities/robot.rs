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
use openssl::x509::X509;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

fn read_u24_at(data: &[u8], offset: usize) -> Option<usize> {
    data.get(offset..offset.checked_add(3)?)
        .and_then(|bytes| <&[u8; 3]>::try_from(bytes).ok())
        .map(|bytes| {
            let [high, mid, low] = *bytes;
            u32::from_be_bytes([0, high, mid, low]) as usize
        })
}

/// Return true once a ServerHelloDone record (handshake type 0x0e) is present in `buf`.
fn has_server_hello_done(buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let Some(header) = buf
            .get(offset..offset + 5)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
        else {
            break;
        };
        let [content_type, _, _, len_high, len_low] = *header;
        let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buf.len() {
            break;
        }
        if content_type == 0x16 {
            let hs_start = offset + 5;
            if hs_start < record_end && buf.get(hs_start) == Some(&0x0e) {
                return true;
            }
        }
        offset = record_end;
    }
    false
}

/// Parse the server handshake buffer to find the Certificate message and return the RSA
/// modulus length in bytes.
fn extract_rsa_key_len(buffer: &[u8]) -> Result<usize> {
    let mut offset = 0;
    while offset + 5 <= buffer.len() {
        let Some(header) = buffer
            .get(offset..offset + 5)
            .and_then(|header| <&[u8; 5]>::try_from(header).ok())
        else {
            break;
        };
        let [record_type, _, _, len_high, len_low] = *header;
        let record_len = u16::from_be_bytes([len_high, len_low]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buffer.len() {
            break;
        }
        if record_type == 0x16 {
            // Handshake record — scan for Certificate message (type 0x0b)
            let mut hoff = offset + 5;
            while hoff + 4 <= record_end {
                let Some(hs_type) = buffer.get(hoff).copied() else {
                    break;
                };
                let Some(hs_len) = read_u24_at(buffer, hoff + 1) else {
                    break;
                };
                let hs_end = hoff + 4 + hs_len;
                if hs_end > record_end {
                    break;
                }
                // Certificate message: type=0x0b, body=[3:list_len][3:cert_len][der...]
                if hs_type == 0x0b && hoff + 10 <= hs_end {
                    let Some(cert_len) = read_u24_at(buffer, hoff + 7) else {
                        break;
                    };
                    let cert_start = hoff + 10;
                    let cert_end = cert_start + cert_len;
                    if let Some(cert_der) = buffer.get(cert_start..cert_end)
                        && let Ok(cert) = X509::from_der(cert_der)
                        && let Ok(pkey) = cert.public_key()
                        && let Ok(rsa) = pkey.rsa()
                    {
                        return Ok(rsa.n().num_bytes() as usize);
                    }
                }
                hoff = hs_end;
            }
        }
        offset = record_end;
    }
    Err(crate::TlsError::ParseError {
        message: "Unable to determine RSA key length from server handshake".to_string(),
    })
}

/// Extract the description byte from a TLS alert record only if the record is
/// structurally complete.
fn alert_description_code(response: &[u8]) -> Option<u8> {
    if response.len() >= 7 && response.first() == Some(&0x15) {
        let record_len = read_u16_at(response, 3)? as usize;
        if record_len == 2 && response.len() == 5 + record_len {
            return response.get(6).copied();
        }
    }
    None
}

/// ROBOT vulnerability tester
pub struct RobotTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
}

impl RobotTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each ROBOT oracle probe.
    pub fn with_starttls(
        mut self,
        protocol: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = protocol;
        self.starttls_hostname = hostname;
        self
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
            // Only a clear oracle (distinct alert/error codes, RobotStatus::Vulnerable)
            // is a confirmed verdict. WeakOracle is derived from raw response-byte
            // divergence across independent connections, which legitimately varies
            // (alert vs. handshake framing, ticket rotation) on non-vulnerable
            // servers — it must be inconclusive, not a hard vulnerable verdict.
            vulnerable: matches!(result, RobotStatus::Vulnerable),
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
                match self.send_invalid_rsa_ciphertext(i as u8).await {
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

        // Analyze responses for padding oracle detection
        // Count unique response patterns (by error codes and lengths)
        let mut response_patterns: std::collections::BTreeSet<Vec<u8>> =
            std::collections::BTreeSet::new();

        for response in &successful_responses {
            // Create a pattern from first N bytes for comparison
            let pattern_len = response.len().min(32);
            if let Some(pattern) = response.get(..pattern_len) {
                response_patterns.insert(pattern.to_vec());
            }
        }

        let unique_patterns = response_patterns.len();

        // Extract a TLS alert description byte if the response is a single alert
        // record (0x15 .. record_len 0x0002 <level> <description>). The record
        // length check avoids reading stray bytes from concatenated/malformed records.
        // Strong oracle: a malformed-padding vector must DETERMINISTICALLY yield its
        // own alert code (stable across rounds), and the stable codes must differ
        // between vectors — i.e. the server distinguishes padding by type, a real
        // Bleichenbacher oracle. A vector whose alert code VARIES across rounds is
        // backend variance on a load-balanced deployment (e.g. a multi-backend CDN),
        // not an oracle, and must never produce a "vulnerable" verdict.
        let mut stable_codes: std::collections::HashSet<u8> = std::collections::HashSet::new();
        let mut saw_unstable_code = false;
        for probes in &per_vector {
            let codes: std::collections::HashSet<u8> = probes
                .iter()
                .filter_map(|response| alert_description_code(response))
                .collect();
            match codes.len() {
                0 => {}
                1 => stable_codes.extend(codes),
                _ => saw_unstable_code = true,
            }
        }

        if stable_codes.len() > 1 {
            return Ok(RobotStatus::Vulnerable);
        }
        if saw_unstable_code {
            // The same malformed input produced different alerts across connections:
            // multi-backend variance, not a deterministic padding oracle.
            return Ok(RobotStatus::Inconclusive);
        }

        // Weak oracle: Two or more distinct response patterns indicate observable differences.
        // However, we need additional validation to avoid false positives from noise.
        // Response length alone is NOT a reliable oracle indicator — network fragmentation,
        // error message variation, and TCP buffering can cause length differences without
        // revealing padding validity.
        //
        // To be classified as a weak oracle, two patterns must:
        // 1. Be genuinely different (not just a few bytes apart)
        // 2. Have sufficient byte-level differences to indicate real oracle behavior
        if unique_patterns >= 2 {
            let patterns: Vec<_> = response_patterns.iter().collect();

            // Find the pair with the greatest byte-level divergence.
            // BTreeSet ordering is lexicographic, so the first two entries are not
            // necessarily the most different — iterate all pairs to find the true maximum.
            let mut best_diff = 0usize;
            let Some((&mut_p1, rest)) = patterns.split_first() else {
                return Ok(RobotStatus::Inconclusive);
            };
            let Some(&mut_p2) = rest.first() else {
                return Ok(RobotStatus::Inconclusive);
            };
            let (mut p1, mut p2) = (mut_p1, mut_p2);
            for (i, left) in patterns.iter().enumerate() {
                for right in patterns.iter().skip(i + 1) {
                    let min_len = left.len().min(right.len());
                    let diff: usize = (0..min_len)
                        .filter(|&k| left.get(k) != right.get(k))
                        .count()
                        + (left.len() as isize - right.len() as isize).unsigned_abs();
                    if diff > best_diff {
                        best_diff = diff;
                        p1 = left;
                        p2 = right;
                    }
                }
            }

            // Count byte-level differences between the most divergent pair
            let min_len = p1.len().min(p2.len());
            let mut content_differences = 0usize;
            for i in 0..min_len {
                if p1.get(i) != p2.get(i) {
                    content_differences += 1;
                }
            }
            // Add length difference as additional divergence
            let len_difference = (p1.len() as isize - p2.len() as isize).unsigned_abs();
            let byte_differences = content_differences + len_difference;

            // Pure length-only differences (no content divergence) are TCP segmentation noise,
            // not an actual oracle — a real Bleichenbacher oracle produces distinct error bytes.
            if content_differences == 0 && len_difference > 0 {
                tracing::debug!(
                    "ROBOT: {} patterns differ only in length ({} bytes) — TCP noise, not an oracle",
                    unique_patterns,
                    len_difference
                );
                return Ok(RobotStatus::NotVulnerable);
            }

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
            if byte_differences >= MIN_BYTE_DIFFERENCES || relative_diff >= MIN_RELATIVE_DIFFERENCE
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
                "ROBOT: {} patterns detected but only {} byte differences (min: {} or {:.0}%), likely noise",
                unique_patterns,
                byte_differences,
                MIN_BYTE_DIFFERENCES,
                MIN_RELATIVE_DIFFERENCE * 100.0
            );
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
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        let mut stream = match crate::utils::network::connect_with_starttls(
            addr,
            TLS_HANDSHAKE_TIMEOUT,
            self.starttls,
            &hostname,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        // Send ClientHello
        let client_hello = self.build_client_hello()?;
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
            if has_server_hello_done(accumulated) || total >= buffer.len() {
                break;
            }
        }
        if total == 0 {
            return Ok(None);
        }
        buffer.truncate(total);

        // Determine the server's RSA key size from the Certificate message so we send
        // the right payload length (128 bytes for RSA-1024, 256 for RSA-2048, etc.).
        let rsa_key_len = extract_rsa_key_len(&buffer)?;

        // Send ClientKeyExchange with invalid padding
        let client_key_exchange = self.build_invalid_client_key_exchange(variant, rsa_key_len);
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
    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_rsa_key_exchange();
        builder.build_minimal()
    }

    /// Build ClientKeyExchange with invalid RSA padding, sized for the server's actual key length.
    fn build_invalid_client_key_exchange(&self, variant: u8, key_len: usize) -> Vec<u8> {
        // record_body = handshake_header(4) + encrypted_pms_len_field(2) + encrypted_pms(key_len)
        let record_body_len = 6 + key_len;
        let handshake_body_len = 2 + key_len; // encrypted_pms_len_field + encrypted_pms

        let mut msg = vec![
            CONTENT_TYPE_HANDSHAKE,             // TLS Record: Handshake (0x16)
            (VERSION_TLS_1_0 >> 8) as u8,       // 0x03
            (VERSION_TLS_1_0 & 0xff) as u8,     // 0x01
            (record_body_len >> 8) as u8,       // record length hi
            (record_body_len & 0xff) as u8,     // record length lo
            HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, // ClientKeyExchange (0x10)
            0x00,                               // handshake length (3 bytes)
            (handshake_body_len >> 8) as u8,
            (handshake_body_len & 0xff) as u8,
            (key_len >> 8) as u8,   // encrypted PMS length hi
            (key_len & 0xff) as u8, // encrypted PMS length lo
        ];

        // Invalid RSA ciphertext (different variants for oracle detection)
        match variant {
            0 => msg.extend(std::iter::repeat_n(0x00u8, key_len)),
            1 => msg.extend(std::iter::repeat_n(0xffu8, key_len)),
            2 => {
                for i in 0..key_len {
                    msg.push((i & 0xff) as u8);
                }
            }
            3 => {
                for i in 0..key_len {
                    msg.push(if i % 2 == 0 { 0xAA } else { 0x55 });
                }
            }
            _ => {
                for i in 0..key_len {
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

        let msg0 = tester.build_invalid_client_key_exchange(0, 256);
        let msg1 = tester.build_invalid_client_key_exchange(1, 256);
        let msg2 = tester.build_invalid_client_key_exchange(2, 256);

        assert_eq!(msg0.len(), msg1.len());
        assert_eq!(msg1.len(), msg2.len());
        assert!(msg0.len() >= 256);
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
        assert_eq!(msg.first(), Some(&CONTENT_TYPE_HANDSHAKE));
        assert_eq!(msg.get(5), Some(&HANDSHAKE_TYPE_FINISHED));
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
        let hello = tester
            .build_client_hello()
            .expect("ClientHello should build");
        assert!(!hello.is_empty());
        assert_eq!(hello.first(), Some(&CONTENT_TYPE_HANDSHAKE));
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

        let msg0 = tester.build_invalid_client_key_exchange(0, 128);
        let msg1 = tester.build_invalid_client_key_exchange(1, 128);
        let msg2 = tester.build_invalid_client_key_exchange(2, 128);

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
        let err = extract_rsa_key_len(&[]).expect_err("missing handshake should fail");
        assert!(
            err.to_string()
                .contains("Unable to determine RSA key length")
        );
    }

    #[test]
    fn test_alert_description_code_rejects_trailing_bytes() {
        let response = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert_eq!(alert_description_code(&response), None);
    }
}
