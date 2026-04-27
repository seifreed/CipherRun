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

/// Return true once a ServerHelloDone record (handshake type 0x0e) is present in `buf`.
fn has_server_hello_done(buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let content_type = buf[offset];
        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buf.len() {
            break;
        }
        if content_type == 0x16 {
            let hs_start = offset + 5;
            if hs_start < record_end && buf[hs_start] == 0x0e {
                return true;
            }
        }
        offset = record_end;
    }
    false
}

/// Parse the server handshake buffer to find the Certificate message and return the RSA
/// modulus length in bytes.  Falls back to 256 (RSA-2048) if parsing fails.
fn extract_rsa_key_len(buffer: &[u8]) -> usize {
    const DEFAULT: usize = 256; // RSA-2048 — the common modern case
    let mut offset = 0;
    while offset + 5 <= buffer.len() {
        let record_type = buffer[offset];
        let record_len = u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buffer.len() {
            break;
        }
        if record_type == 0x16 {
            // Handshake record — scan for Certificate message (type 0x0b)
            let mut hoff = offset + 5;
            while hoff + 4 <= record_end {
                let hs_type = buffer[hoff];
                let hs_len =
                    u32::from_be_bytes([0, buffer[hoff + 1], buffer[hoff + 2], buffer[hoff + 3]])
                        as usize;
                let hs_end = hoff + 4 + hs_len;
                if hs_end > record_end {
                    break;
                }
                // Certificate message: type=0x0b, body=[3:list_len][3:cert_len][der...]
                if hs_type == 0x0b && hoff + 10 <= hs_end {
                    let cert_len = u32::from_be_bytes([
                        0,
                        buffer[hoff + 7],
                        buffer[hoff + 8],
                        buffer[hoff + 9],
                    ]) as usize;
                    let cert_start = hoff + 10;
                    let cert_end = cert_start + cert_len;
                    if cert_end <= buffer.len() {
                        let cert_der = &buffer[cert_start..cert_end];
                        if let Ok(cert) = X509::from_der(cert_der)
                            && let Ok(pkey) = cert.public_key()
                            && let Ok(rsa) = pkey.rsa()
                        {
                            return rsa.n().num_bytes() as usize;
                        }
                    }
                }
                hoff = hs_end;
            }
        }
        offset = record_end;
    }
    DEFAULT
}

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
            // V9 fix: previously `await?` aborted the entire probe set on the
            // first transient error. A single timeout on vector 2/5 prevented
            // the remaining 3 from running and the function returned Err rather
            // than the MIN_SAMPLES-gated Inconclusive verdict.
            let response = match self.send_invalid_rsa_ciphertext(i as u8).await {
                Ok(r) => r,
                Err(err) => {
                    tracing::debug!(
                        "ROBOT probe {} failed transiently ({}); recording as missing sample",
                        i,
                        err
                    );
                    None
                }
            };
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
        let mut response_patterns: std::collections::BTreeSet<Vec<u8>> =
            std::collections::BTreeSet::new();
        let mut error_codes: std::collections::HashSet<u8> = std::collections::HashSet::new();
        let mut response_lengths: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        for response in &successful_responses {
            // Extract alert error code if present (TLS alert format: 0x15 0x03 0x03 0x00 0x02 <level> <description>)
            // Validate the record length field (bytes 3-4) equals 0x0002 to avoid reading
            // stray bytes from concatenated records or malformed responses.
            if response.len() >= 7 && response[0] == 0x15 {
                let record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
                if record_len == 2 {
                    let error_code = response[6];
                    error_codes.insert(error_code);
                }
            }
            response_lengths.insert(response.len());

            // Create a pattern from first N bytes for comparison
            let pattern_len = response.len().min(32);
            response_patterns.insert(response[..pattern_len].to_vec());
        }

        // Detection logic:
        // 1. Different error codes indicate oracle (server distinguishes padding errors)
        // 2. Different response patterns may indicate observable differences
        //
        // Only differing TLS alert description bytes (error_codes) constitute a strong
        // oracle signal. Pattern diversity alone (first 32 bytes) is easily caused by
        // network jitter, TCP fragmentation, or RST/FIN timing differences.

        let unique_error_codes = error_codes.len();
        let unique_patterns = response_patterns.len();

        // Strong oracle: only different alert description bytes qualify.
        if unique_error_codes > 1 {
            return Ok(RobotStatus::Vulnerable);
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
            let (mut p1, mut p2) = (patterns[0], patterns[1]);
            for i in 0..patterns.len() {
                for j in (i + 1)..patterns.len() {
                    let min_len = patterns[i].len().min(patterns[j].len());
                    let diff: usize = (0..min_len)
                        .filter(|&k| patterns[i][k] != patterns[j][k])
                        .count()
                        + (patterns[i].len() as isize - patterns[j].len() as isize).unsigned_abs();
                    if diff > best_diff {
                        best_diff = diff;
                        p1 = patterns[i];
                        p2 = patterns[j];
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

        // Read until ServerHelloDone so the full certificate chain is in the buffer,
        // even for large chains (e.g. RSA-4096) that span multiple TLS records.
        let mut buffer = vec![0u8; 32768];
        let mut total = 0usize;
        loop {
            let n = match timeout(Duration::from_secs(3), stream.read(&mut buffer[total..])).await {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            if has_server_hello_done(&buffer[..total]) || total >= buffer.len() {
                break;
            }
        }
        if total == 0 {
            return Ok(None);
        }
        buffer.truncate(total);

        // Determine the server's RSA key size from the Certificate message so we send
        // the right payload length (128 bytes for RSA-1024, 256 for RSA-2048, etc.).
        let rsa_key_len = extract_rsa_key_len(&buffer);

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
    fn build_client_hello(&self) -> Vec<u8> {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
        builder.for_rsa_key_exchange();
        builder.build_minimal().unwrap_or_else(|_| Vec::new())
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

        let msg0 = tester.build_invalid_client_key_exchange(0, 128);
        let msg1 = tester.build_invalid_client_key_exchange(1, 128);
        let msg2 = tester.build_invalid_client_key_exchange(2, 128);

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
