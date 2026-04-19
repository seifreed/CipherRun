// DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) Vulnerability Test
// CVE-2016-0800
//
// DROWN allows attackers to decrypt TLS sessions by exploiting SSLv2 on the same
// server or another server using the same private key. Even if the server doesn't
// support SSLv2 on HTTPS, if it supports SSLv2 on another port (like SMTP), it's vulnerable.
//
// DETECTION APPROACH:
// This implementation detects SSLv2 support with varying levels of confidence:
//
// 1. Confirmed: Valid SSLv2 ServerHello (message type 0x04) - definitive SSLv2 support
// 2. Probable: SSLv2 record structure with known SSLv2 message types - likely SSLv2
// 3. Suspicious: SSLv2-like header but unusual message - manual review recommended
// 4. Not Supported: No SSLv2 response or connection error
//
// SSLv2 message types:
// - 0x00: Error
// - 0x01: ClientHello
// - 0x02: ClientMasterKey
// - 0x03: ClientFinished (ClientVerify in some implementations)
// - 0x04: ServerHello
// - 0x05: ServerVerify
// - 0x06: ServerFinished
// - 0x07: RequestCertificate
// - 0x08: ClientCertificate

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// SSLv2 detection status with granular confidence levels
///
/// # DROWN Vulnerability Context
///
/// DROWN (CVE-2016-0800) exploits SSLv2 connections to decrypt TLS sessions.
/// A server is DROWN-vulnerable if it accepts SSLv2 connections, allowing an attacker
/// to perform a "cross-protocol" attack.
///
/// # Status Interpretation
///
/// - **Confirmed**: Server sent a valid SSLv2 ServerHello (message type 0x04).
///   This definitively proves SSLv2 support and DROWN vulnerability.
///
/// - **Probable**: Server sent an SSLv2 Error (0x00) or other known SSLv2 message.
///   The server SPEAKS SSLv2, but our specific handshake was rejected.
///   DROWN may still be possible with different cipher configurations.
///   Manual verification is recommended.
///
/// - **Suspicious**: Server sent data that looks like SSLv2 but has unusual structure.
///   Further manual analysis required.
///
/// - **NotSupported**: No SSLv2 response detected - server likely doesn't support SSLv2.
///
/// - **Inconclusive**: Connection error prevented detection - retry recommended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sslv2Status {
    /// Valid SSLv2 ServerHello (0x04) - definitive support
    Confirmed,
    /// SSLv2 record structure with known message type (0x00-0x08)
    /// Server speaks SSLv2 but our handshake was rejected - DROWN may still be possible
    Probable,
    /// SSLv2-like header but unusual message type - manual review needed
    Suspicious,
    /// No SSLv2 response detected
    NotSupported,
    /// Connection error prevented detection
    Inconclusive,
}

impl Sslv2Status {
    /// Returns true if SSLv2 is likely supported (Confirmed or Probable)
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, Self::Confirmed | Self::Probable)
    }
}

/// DROWN vulnerability tester
pub struct DrownTester {
    target: Target,
}

impl DrownTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    fn detailed_status(status: Sslv2Status) -> Option<Sslv2Status> {
        match status {
            Sslv2Status::Inconclusive => None,
            _ => Some(status),
        }
    }

    /// Test for DROWN vulnerability
    pub async fn test(&self) -> Result<DrownTestResult> {
        let sslv2_status = self.test_sslv2().await?;
        let sslv2_supported = sslv2_status.is_vulnerable();

        let sslv2_export_status = if sslv2_supported {
            Self::detailed_status(self.test_sslv2_export_ciphers().await?)
        } else {
            None
        };

        let sslv2_export = sslv2_export_status
            .as_ref()
            .is_some_and(Sslv2Status::is_vulnerable);
        let vulnerable = sslv2_supported;

        let details = match sslv2_status {
            Sslv2Status::Confirmed if sslv2_export => {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 ServerHello received, export ciphers enabled (highly vulnerable)".to_string()
            }
            Sslv2Status::Confirmed => {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 ServerHello received".to_string()
            }
            Sslv2Status::Probable if sslv2_export => {
                "Potentially vulnerable to DROWN - SSLv2 probable (known message type detected), export ciphers enabled".to_string()
            }
            Sslv2Status::Probable => {
                "Potentially vulnerable to DROWN - SSLv2 probable (known message type detected)".to_string()
            }
            Sslv2Status::Suspicious => {
                "DROWN: SSLv2-like response detected - manual verification recommended".to_string()
            }
            Sslv2Status::NotSupported => {
                "Not vulnerable - SSLv2 not supported".to_string()
            }
            Sslv2Status::Inconclusive => {
                "DROWN test inconclusive - connection error prevented SSLv2 detection".to_string()
            }
        };

        Ok(DrownTestResult {
            vulnerable,
            sslv2_supported,
            sslv2_export_ciphers: sslv2_export,
            sslv2_export_status,
            sslv2_status: Self::detailed_status(sslv2_status),
            details,
        })
    }

    /// Test if SSLv2 is supported with detailed status
    async fn test_sslv2(&self) -> Result<Sslv2Status> {
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
                Err(_) => return Ok(Sslv2Status::Inconclusive),
            };

        // Send SSLv2 ClientHello
        let client_hello = self.build_sslv2_client_hello();
        stream.write_all(&client_hello).await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n >= 2 => Self::analyze_sslv2_response(&buffer[..n]),
            Ok(Ok(_)) => {
                // Zero bytes - connection closed
                Ok(Sslv2Status::NotSupported)
            }
            Ok(Err(_)) | Err(_) => {
                // Read error or timeout
                Ok(Sslv2Status::Inconclusive)
            }
        }
    }

    /// Analyze SSLv2 response and return detection status
    fn analyze_sslv2_response(data: &[u8]) -> Result<Sslv2Status> {
        if data.len() < 2 {
            return Ok(Sslv2Status::NotSupported);
        }

        let first_byte = data[0];
        let second_byte = data[1];

        // SSLv2 uses 2-byte or 3-byte record headers
        // 2-byte header: high bit set, length in lower 15 bits
        let is_sslv2_header = (first_byte & 0x80) != 0;

        if !is_sslv2_header {
            return Ok(Sslv2Status::NotSupported);
        }

        let record_len = ((first_byte & 0x7f) as usize) << 8 | second_byte as usize;
        let is_reasonable_length = record_len > 0 && record_len <= 16384;
        let has_enough_data = data.len() >= 3 && data.len() >= record_len.saturating_add(2);

        if !is_reasonable_length || !has_enough_data {
            // SSLv2 header present but insufficient data
            tracing::debug!(
                "DROWN: SSLv2 header detected but response truncated (len={}, expected={})",
                data.len(),
                record_len.saturating_add(2)
            );
            return Ok(Sslv2Status::Suspicious);
        }

        let msg_type = data[2];

        // SSLv2 message types
        match msg_type {
            0x04 => {
                // ServerHello - definitive SSLv2 support
                tracing::debug!("DROWN: SSLv2 ServerHello (0x04) confirmed");
                Ok(Sslv2Status::Confirmed)
            }
            0x00 => {
                // SSLv2 Error message (0x00) - server speaks SSLv2 but rejected our ClientHello
                //
                // IMPORTANT: This is marked as "Probable" rather than "Confirmed" because:
                // 1. The server DOES speak SSLv2 (it responded with a valid SSLv2 Error message)
                // 2. However, DROWN requires a server that accepts SSLv2 connections, not just speaks it
                // 3. An Error response means our specific cipher/clienthello was rejected
                // 4. The server might still be exploitable via a different cipher combination
                //
                // Security implication: Any SSLv2-speaking server should be considered a potential
                // DROWN vector. Manual verification with different cipher combinations is recommended.
                tracing::warn!(
                    "DROWN: SSLv2 Error (0x00) received - server speaks SSLv2 but rejected handshake, \
                     manual review recommended. Server may still be DROWN-vulnerable with different ciphers."
                );
                Ok(Sslv2Status::Probable)
            }
            0x02 | 0x03 => {
                // ClientMasterKey (0x02) and ClientFinished (0x03) are client→server messages.
                // Receiving them from a server indicates protocol confusion, not SSLv2 support.
                // Use Suspicious (is_vulnerable() == false) to avoid false positives.
                tracing::warn!(
                    "DROWN: Client-only SSLv2 message type 0x{:02x} received from server — protocol confusion, not SSLv2 support",
                    msg_type
                );
                Ok(Sslv2Status::Suspicious)
            }
            0x05..=0x07 => {
                // ServerVerify (0x05), ServerFinished (0x06), RequestCertificate (0x07)
                tracing::debug!(
                    "DROWN: SSLv2 message type 0x{:02x} detected - SSLv2 probable",
                    msg_type
                );
                Ok(Sslv2Status::Probable)
            }
            0x08 => {
                // ClientCertificate (0x08) is a client→server message — receiving it from a server
                // indicates protocol confusion, not SSLv2 support.
                tracing::warn!(
                    "DROWN: Client-only SSLv2 message 0x08 (ClientCertificate) received from server — protocol confusion"
                );
                Ok(Sslv2Status::Suspicious)
            }
            _ => {
                // Unknown message type but valid SSLv2 structure
                tracing::debug!(
                    "DROWN: Suspicious SSLv2-like response with unknown message type 0x{:02x}",
                    msg_type
                );
                Ok(Sslv2Status::Suspicious)
            }
        }
    }

    /// Test for SSLv2 export ciphers (makes DROWN easier to exploit)
    async fn test_sslv2_export_ciphers(&self) -> Result<Sslv2Status> {
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
                Err(_) => return Ok(Sslv2Status::Inconclusive),
            };

        // Send SSLv2 ClientHello with export ciphers only
        let client_hello = self.build_sslv2_client_hello_export();
        stream.write_all(&client_hello).await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n >= 2 => Self::analyze_sslv2_response(&buffer[..n]),
            _ => Ok(Sslv2Status::Inconclusive),
        }
    }

    /// Build SSLv2 ClientHello
    fn build_sslv2_client_hello(&self) -> Vec<u8> {
        // SSLv2 ClientHello structure:
        // - Message type: 1 byte (CLIENT-HELLO = 0x01)
        // - Version: 2 bytes (SSL 2.0 = 0x0002)
        // - Cipher specs length: 2 bytes
        // - Session ID length: 2 bytes (0 for ClientHello)
        // - Challenge length: 2 bytes (16 bytes typical)
        // - Cipher specs: variable (5 ciphers * 3 bytes = 15 bytes)
        // - Challenge: 16 bytes

        let cipher_specs_len: u16 = 15; // 5 ciphers * 3 bytes each
        let session_id_len: u16 = 0;
        let challenge_len: u16 = 16;

        // Calculate body length (everything after the 2-byte header)
        // body_len = 1 (msg_type) + 2 (version) + 2 (cipher_len) + 2 (session_id_len) + 2 (challenge_len) + cipher_specs + 16 (challenge)
        let body_len: u16 = 1 + 2 + 2 + 2 + 2 + cipher_specs_len + challenge_len; // = 40 bytes

        let mut hello = Vec::new();

        // SSLv2 record header (2-byte format with high bit set)
        // Length is in the lower 7 bits of first byte and all of second byte
        let header_byte1 = 0x80 | ((body_len >> 8) & 0x7f) as u8;
        let header_byte2 = (body_len & 0xff) as u8;
        hello.push(header_byte1); // 0x80 (since body_len = 40 < 128)
        hello.push(header_byte2); // 0x28 (40 in hex)

        // Message type: CLIENT-HELLO
        hello.push(0x01);

        // Version: SSL 2.0
        hello.push(0x00);
        hello.push(0x02);

        // Cipher specs length
        hello.push((cipher_specs_len >> 8) as u8);
        hello.push((cipher_specs_len & 0xff) as u8);

        // Session ID length (always 0 for ClientHello)
        hello.push((session_id_len >> 8) as u8);
        hello.push((session_id_len & 0xff) as u8);

        // Challenge length
        hello.push((challenge_len >> 8) as u8);
        hello.push((challenge_len & 0xff) as u8);

        // Cipher specs (3-byte cipher codes)
        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5 (0x0700C0)
        hello.push(0x07);
        hello.push(0x00);
        hello.push(0xC0);

        // SSL_CK_RC4_128_WITH_MD5 (0x010080)
        hello.push(0x01);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC2_128_CBC_WITH_MD5
        hello.push(0x03);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_DES_64_CBC_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 (0x040080)
        hello.push(0x04);
        hello.push(0x00);
        hello.push(0x80);

        // Challenge (16 bytes)
        for i in 0..16 {
            hello.push((i * 13) as u8);
        }

        hello
    }

    /// Build SSLv2 ClientHello with export ciphers only
    fn build_sslv2_client_hello_export(&self) -> Vec<u8> {
        // SSLv2 ClientHello with export ciphers only
        // 2 export ciphers * 3 bytes each = 6 bytes

        let cipher_specs_len: u16 = 6; // 2 ciphers * 3 bytes each
        let session_id_len: u16 = 0;
        let challenge_len: u16 = 16;

        // Calculate body length
        let body_len: u16 = 1 + 2 + 2 + 2 + 2 + cipher_specs_len + challenge_len; // = 31 bytes

        let mut hello = Vec::new();

        // SSLv2 record header (2-byte format with high bit set)
        let header_byte1 = 0x80 | ((body_len >> 8) & 0x7f) as u8;
        let header_byte2 = (body_len & 0xff) as u8;
        hello.push(header_byte1); // 0x80 (since body_len = 31 < 128)
        hello.push(header_byte2); // 0x1f (31 in hex)

        // Message type: CLIENT-HELLO
        hello.push(0x01);

        // Version: SSL 2.0
        hello.push(0x00);
        hello.push(0x02);

        // Cipher specs length
        hello.push((cipher_specs_len >> 8) as u8);
        hello.push((cipher_specs_len & 0xff) as u8);

        // Session ID length (always 0 for ClientHello)
        hello.push((session_id_len >> 8) as u8);
        hello.push((session_id_len & 0xff) as u8);

        // Challenge length
        hello.push((challenge_len >> 8) as u8);
        hello.push((challenge_len & 0xff) as u8);

        // Export cipher specs
        // SSL_CK_RC4_128_EXPORT40_WITH_MD5 (0x020080)
        hello.push(0x02);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 (0x040080)
        hello.push(0x04);
        hello.push(0x00);
        hello.push(0x80);

        // Challenge (16 bytes)
        for i in 0..16 {
            hello.push((i * 17) as u8);
        }

        hello
    }
}

/// DROWN test result
#[derive(Debug, Clone)]
pub struct DrownTestResult {
    pub vulnerable: bool,
    pub sslv2_supported: bool,
    pub sslv2_export_ciphers: bool,
    /// Detailed SSLv2 export detection status (None if the probe did not run or was inconclusive)
    pub sslv2_export_status: Option<Sslv2Status>,
    /// Detailed SSLv2 detection status (None if test was inconclusive)
    pub sslv2_status: Option<Sslv2Status>,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sslv2_status_is_vulnerable() {
        assert!(Sslv2Status::Confirmed.is_vulnerable());
        assert!(Sslv2Status::Probable.is_vulnerable());
        assert!(!Sslv2Status::Suspicious.is_vulnerable());
        assert!(!Sslv2Status::NotSupported.is_vulnerable());
        assert!(!Sslv2Status::Inconclusive.is_vulnerable());
    }

    #[test]
    fn test_drown_result_not_vulnerable() {
        let result = DrownTestResult {
            vulnerable: false,
            sslv2_supported: false,
            sslv2_export_ciphers: false,
            sslv2_export_status: None,
            sslv2_status: Some(Sslv2Status::NotSupported),
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
    }

    #[test]
    fn test_detailed_status_omits_inconclusive() {
        assert_eq!(
            DrownTester::detailed_status(Sslv2Status::Inconclusive),
            None
        );
        assert_eq!(
            DrownTester::detailed_status(Sslv2Status::NotSupported),
            Some(Sslv2Status::NotSupported)
        );
        assert_eq!(
            DrownTester::detailed_status(Sslv2Status::Confirmed),
            Some(Sslv2Status::Confirmed)
        );
    }

    #[test]
    fn test_drown_result_vulnerable() {
        let result = DrownTestResult {
            vulnerable: true,
            sslv2_supported: true,
            sslv2_export_ciphers: false,
            sslv2_export_status: None,
            sslv2_status: Some(Sslv2Status::Confirmed),
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.sslv2_supported);
    }

    #[test]
    fn test_drown_result_probable() {
        let result = DrownTestResult {
            vulnerable: true,
            sslv2_supported: true,
            sslv2_export_ciphers: false,
            sslv2_export_status: None,
            sslv2_status: Some(Sslv2Status::Probable),
            details: "Potentially vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.sslv2_supported);
    }

    #[test]
    fn test_analyze_sslv2_response_confirmed() {
        // SSLv2 ServerHello (message type 0x04)
        // Need valid record: header (2 bytes) + length must match data
        // Record length 0x40 = 64 bytes, so total = 66 bytes (header + body)
        let mut response = vec![0x80, 0x40, 0x04]; // header (length=64) + msg type
        response.extend(vec![0u8; 63]); // padding to match length
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::Confirmed);
    }

    #[test]
    fn test_analyze_sslv2_response_error() {
        // SSLv2 Error message (message type 0x00)
        let mut response = vec![0x80, 0x40, 0x00]; // header + msg type
        response.extend(vec![0u8; 63]); // padding to match length
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::Probable);
    }

    #[test]
    fn test_analyze_sslv2_response_server_verify() {
        // SSLv2 ServerVerify (message type 0x05)
        let mut response = vec![0x80, 0x40, 0x05];
        response.extend(vec![0u8; 63]);
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::Probable);
    }

    #[test]
    fn test_analyze_sslv2_response_unknown() {
        // Unknown SSLv2 message type with valid length
        let mut response = vec![0x80, 0x40, 0xFF];
        response.extend(vec![0u8; 63]);
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::Suspicious);
    }

    #[test]
    fn test_analyze_sslv2_response_not_sslv2() {
        // TLS record (not SSLv2)
        let response = vec![0x16, 0x03, 0x01]; // TLS handshake
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::NotSupported);
    }

    #[test]
    fn test_analyze_sslv2_response_truncated() {
        // SSLv2 header but insufficient data
        let response = vec![0x80]; // Only 1 byte
        let result = DrownTester::analyze_sslv2_response(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Sslv2Status::NotSupported);
    }

    #[test]
    fn test_sslv2_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x80); // SSLv2 record
        assert_eq!(hello[2], 0x01); // CLIENT-HELLO
        assert_eq!(hello[3], 0x00); // SSL 2.0 version
        assert_eq!(hello[4], 0x02);
    }

    #[test]
    fn test_sslv2_export_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello_export();

        assert!(hello.len() > 30);
        assert_eq!(hello[0], 0x80);
        assert_eq!(hello[2], 0x01);
        assert_eq!(hello[3], 0x00);
        assert_eq!(hello[4], 0x02);
        assert_eq!(hello[6], 0x06); // cipher specs length low byte
    }

    #[test]
    fn test_sslv2_export_client_hello_cipher_length_matches_payload() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello_export();
        let cipher_specs_len = ((hello[5] as usize) << 8) | (hello[6] as usize);

        // Header(2) + fixed ClientHello fields(9) + cipher specs + challenge(16)
        let actual_cipher_specs_len = hello.len() - 2 - 9 - 16;
        assert_eq!(cipher_specs_len, actual_cipher_specs_len);
    }

    #[test]
    fn test_sslv2_client_hello_length_matches_header() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello();
        let len = ((hello[0] as usize & 0x7f) << 8) | (hello[1] as usize);
        assert_eq!(hello.len(), len + 2);
    }

    #[test]
    fn test_sslv2_export_hello_length_matches_header() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = DrownTester::new(target);
        let hello = tester.build_sslv2_client_hello_export();
        let len = ((hello[0] as usize & 0x7f) << 8) | (hello[1] as usize);
        assert_eq!(hello.len(), len + 2);
    }
}
