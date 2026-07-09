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

const SSLV2_MAX_RECORD_WITH_HEADER: usize = 32767 + 2;

fn sslv2_record_shape(data: &[u8]) -> Option<(usize, usize, usize)> {
    let first = *data.first()?;
    let second = *data.get(1)?;
    if matches!(first, 0x14..=0x18) && second == 0x03 {
        return None;
    }
    if (first & 0x80) != 0 {
        let record_len = ((first & 0x7f) as usize) << 8 | second as usize;
        Some((2, record_len, 2 + record_len))
    } else {
        let record_len = ((first & 0x3f) as usize) << 8 | second as usize;
        Some((3, record_len, 3 + record_len))
    }
}

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
    /// Returns true only when the server actually accepted an SSLv2 handshake
    /// (issued an SSLv2 ServerHello), which is the precondition for a DROWN
    /// decryption oracle (CVE-2016-0800). `Probable` means the server merely
    /// spoke SSLv2 but rejected our probe (e.g. an SSLv2 Error record) — that is
    /// not a usable oracle and must not be reported as a hard vulnerable verdict.
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

/// DROWN vulnerability tester
pub struct DrownTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_server_mode: bool,
    starttls_hostname: Option<String>,
}

impl DrownTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_server_mode: false,
            starttls_hostname: None,
        }
    }

    /// Configure STARTTLS negotiation before each DROWN/SSLv2 probe.
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

    /// Connect, upgrading via STARTTLS first for plaintext-first services.
    async fn starttls_connect(
        &self,
        addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<tokio::net::TcpStream> {
        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        crate::utils::network::connect_with_starttls(
            addr,
            timeout,
            self.starttls,
            &hostname,
            self.starttls_server_mode,
        )
        .await
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

        let mut stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(Sslv2Status::Inconclusive),
        };

        // Send SSLv2 ClientHello
        let client_hello = self.build_sslv2_client_hello();
        stream.write_all(&client_hello).await?;

        // Read the full SSLv2 response record so fragmented headers do not get
        // misclassified as truncation.
        let mut buffer = vec![0u8; SSLV2_MAX_RECORD_WITH_HEADER];
        match timeout(
            Duration::from_secs(3),
            Self::read_complete_sslv2_record(&mut stream, &mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                let response = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                    message: "DROWN SSLv2 response read length exceeded buffer".to_string(),
                })?;
                Self::analyze_sslv2_response(response)
            }
            Ok(Ok(_)) => {
                // Zero bytes - connection closed
                Ok(Sslv2Status::Inconclusive)
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
            return Ok(Sslv2Status::Inconclusive);
        }

        let Some((header_len, record_len, record_total)) = sslv2_record_shape(data) else {
            return Ok(Sslv2Status::NotSupported);
        };
        let is_reasonable_length = record_len > 0 && record_len <= 32767;
        let has_enough_data = data.len() > header_len && data.len() >= record_total;

        if !is_reasonable_length || !has_enough_data {
            // SSLv2 header present but insufficient data
            tracing::debug!(
                "DROWN: SSLv2 header detected but response truncated (len={}, expected={})",
                data.len(),
                record_total
            );
            return Ok(Sslv2Status::Suspicious);
        }

        let Some(&msg_type) = data.get(header_len) else {
            return Ok(Sslv2Status::Suspicious);
        };

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

        let mut stream = match self.starttls_connect(addr, TLS_HANDSHAKE_TIMEOUT).await {
            Ok(s) => s,
            Err(_) => return Ok(Sslv2Status::Inconclusive),
        };

        // Send SSLv2 ClientHello with export ciphers only
        let client_hello = self.build_sslv2_client_hello_export();
        stream.write_all(&client_hello).await?;

        // Read the full SSLv2 response record so fragmented headers do not get
        // misclassified as truncation.
        let mut buffer = vec![0u8; SSLV2_MAX_RECORD_WITH_HEADER];
        match timeout(
            Duration::from_secs(3),
            Self::read_complete_sslv2_record(&mut stream, &mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n >= 2 => {
                let response = buffer.get(..n).ok_or_else(|| crate::TlsError::ParseError {
                    message: "DROWN export response read length exceeded buffer".to_string(),
                })?;
                Self::analyze_sslv2_response(response)
            }
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
        let body_len_bytes = body_len.to_be_bytes();
        let header_byte1 = 0x80 | (body_len_bytes[0] & 0x7f);
        let header_byte2 = body_len_bytes[1];
        hello.push(header_byte1); // 0x80 (since body_len = 40 < 128)
        hello.push(header_byte2); // 0x28 (40 in hex)

        // Message type: CLIENT-HELLO
        hello.push(0x01);

        // Version: SSL 2.0
        hello.push(0x00);
        hello.push(0x02);

        // Cipher specs length
        hello.extend_from_slice(&cipher_specs_len.to_be_bytes());

        // Session ID length (always 0 for ClientHello)
        hello.extend_from_slice(&session_id_len.to_be_bytes());

        // Challenge length
        hello.extend_from_slice(&challenge_len.to_be_bytes());

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
        for i in 0_u8..16 {
            hello.push(i * 13);
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
        let body_len_bytes = body_len.to_be_bytes();
        let header_byte1 = 0x80 | (body_len_bytes[0] & 0x7f);
        let header_byte2 = body_len_bytes[1];
        hello.push(header_byte1); // 0x80 (since body_len = 31 < 128)
        hello.push(header_byte2); // 0x1f (31 in hex)

        // Message type: CLIENT-HELLO
        hello.push(0x01);

        // Version: SSL 2.0
        hello.push(0x00);
        hello.push(0x02);

        // Cipher specs length
        hello.extend_from_slice(&cipher_specs_len.to_be_bytes());

        // Session ID length (always 0 for ClientHello)
        hello.extend_from_slice(&session_id_len.to_be_bytes());

        // Challenge length
        hello.extend_from_slice(&challenge_len.to_be_bytes());

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
        for i in 0_u8..16 {
            hello.push(i * 17);
        }

        hello
    }

    async fn read_complete_sslv2_record(
        stream: &mut tokio::net::TcpStream,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::io::ErrorKind;
        use tokio::time::timeout;

        let mut total = 0;
        while total < buffer.len() {
            match timeout(Duration::from_secs(3), stream.read(&mut buffer[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= 2 {
                        let Some((header_len, _record_len, record_total)) =
                            sslv2_record_shape(buffer.get(..total).unwrap_or(&[]))
                        else {
                            continue;
                        };
                        if total < header_len {
                            continue;
                        }
                        if record_total > buffer.len() {
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "DROWN SSLv2 response length exceeds buffer",
                            ));
                        }
                        if total >= record_total {
                            break;
                        }
                    }
                }
                Ok(Err(err))
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Ok(Err(err))
                    if total > 0
                        && matches!(
                            err.kind(),
                            ErrorKind::TimedOut
                                | ErrorKind::WouldBlock
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Ok(Err(err)) => return Err(err),
                Err(_) if total > 0 => break,
                Err(_) => return Ok(0),
            }
        }

        Ok(total)
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, sleep};

    fn byte_at(data: &[u8], offset: usize) -> Option<u8> {
        data.get(offset).copied()
    }

    fn sslv2_header_len(data: &[u8]) -> usize {
        let first = data
            .first()
            .copied()
            .expect("test SSLv2 header should contain first byte");
        let second = data
            .get(1)
            .copied()
            .expect("test SSLv2 header should contain second byte");
        ((first as usize & 0x7f) << 8) | second as usize
    }

    #[test]
    fn test_sslv2_status_is_vulnerable() {
        // Only an accepted SSLv2 handshake (Confirmed) is a usable DROWN oracle.
        assert!(Sslv2Status::Confirmed.is_vulnerable());
        // Probable = the server spoke SSLv2 but rejected our probe (e.g. an SSLv2
        // Error record) — not a confirmed oracle, must not be a vulnerable verdict.
        assert!(!Sslv2Status::Probable.is_vulnerable());
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
    fn test_analyze_sslv2_response_confirmed_with_three_byte_header() {
        let response = [0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00];
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
        assert_eq!(result.unwrap(), Sslv2Status::Inconclusive);
    }

    #[tokio::test]
    async fn test_sslv2_one_byte_response_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 128];
            let _ = socket.read(&mut buf).await.expect("read client hello");
            socket
                .write_all(&[0x80])
                .await
                .expect("write partial header");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = DrownTester::new(target).test().await.unwrap();
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
        assert_eq!(result.sslv2_status, None);
        assert!(result.details.contains("inconclusive"), "{result:?}");
    }

    #[tokio::test]
    async fn test_sslv2_zero_byte_response_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept");
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = DrownTester::new(target).test().await.unwrap();
        server.await.expect("server task");

        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
        assert_eq!(result.sslv2_status, None);
        assert!(result.details.contains("inconclusive"), "{result:?}");
    }

    #[tokio::test]
    async fn test_sslv2_reads_fragmented_response_record() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 128];
            let _ = socket.read(&mut buf).await.expect("read client hello");
            let mut response = vec![0x80, 0x40, 0x04];
            response.extend(vec![0u8; 63]);
            let _ = socket.write_all(&response[..1]).await;
            sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&response[1..]).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = DrownTester::new(target)
            .test_sslv2()
            .await
            .expect("sslv2 probe should not error");
        server.await.expect("server task");

        assert_eq!(result, Sslv2Status::Confirmed);
    }

    #[tokio::test]
    async fn test_sslv2_reads_large_response_record() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 128];
            let _ = socket.read(&mut buf).await.expect("read client hello");
            let record_len = 5000usize;
            let mut response = vec![0x80 | ((record_len >> 8) as u8), record_len as u8, 0x04];
            response.extend(vec![0u8; record_len - 1]);
            let _ = socket.write_all(&response).await;
        });

        let target = Target::with_ips(
            "localhost".to_string(),
            port,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        let result = DrownTester::new(target)
            .test_sslv2()
            .await
            .expect("sslv2 probe should not error");
        server.await.expect("server task");

        assert_eq!(result, Sslv2Status::Confirmed);
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
        assert_eq!(byte_at(&hello, 0), Some(0x80)); // SSLv2 record
        assert_eq!(byte_at(&hello, 2), Some(0x01)); // CLIENT-HELLO
        assert_eq!(byte_at(&hello, 3), Some(0x00)); // SSL 2.0 version
        assert_eq!(byte_at(&hello, 4), Some(0x02));
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
        assert_eq!(byte_at(&hello, 0), Some(0x80));
        assert_eq!(byte_at(&hello, 2), Some(0x01));
        assert_eq!(byte_at(&hello, 3), Some(0x00));
        assert_eq!(byte_at(&hello, 4), Some(0x02));
        assert_eq!(byte_at(&hello, 6), Some(0x06)); // cipher specs length low byte
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
        let cipher_specs_len =
            ((byte_at(&hello, 5).unwrap() as usize) << 8) | byte_at(&hello, 6).unwrap() as usize;

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
        let len = sslv2_header_len(&hello);
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
        let len = sslv2_header_len(&hello);
        assert_eq!(hello.len(), len + 2);
    }
}
