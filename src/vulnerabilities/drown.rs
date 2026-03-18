// DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) Vulnerability Test
// CVE-2016-0800
//
// DROWN allows attackers to decrypt TLS sessions by exploiting SSLv2 on the same
// server or another server using the same private key. Even if the server doesn't
// support SSLv2 on HTTPS, if it supports SSLv2 on another port (like SMTP), it's vulnerable.

use crate::Result;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// DROWN vulnerability tester
pub struct DrownTester {
    target: Target,
}

impl DrownTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for DROWN vulnerability
    pub async fn test(&self) -> Result<DrownTestResult> {
        let sslv2_supported = self.test_sslv2().await?;
        let sslv2_export = if sslv2_supported {
            self.test_sslv2_export_ciphers().await?
        } else {
            false
        };

        let vulnerable = sslv2_supported;

        let details = if vulnerable {
            if sslv2_export {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 with export ciphers enabled (highly vulnerable)".to_string()
            } else {
                "Vulnerable to DROWN (CVE-2016-0800) - SSLv2 enabled".to_string()
            }
        } else {
            "Not vulnerable - SSLv2 not supported".to_string()
        };

        Ok(DrownTestResult {
            vulnerable,
            sslv2_supported,
            sslv2_export_ciphers: sslv2_export,
            details,
        })
    }

    /// Test if SSLv2 is supported
    async fn test_sslv2(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send SSLv2 ClientHello
                let client_hello = self.build_sslv2_client_hello();
                stream.write_all(&client_hello).await?;

                // Read response
                let mut buffer = vec![0u8; 4096];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 2 => {
                        // Check for SSLv2 ServerHello response
                        // SSLv2 uses a 2-byte or 3-byte length header:
                        // - If high bit is set (0x80+), it's a 2-byte header: length is (byte[0] & 0x7F) << 8 | byte[1]
                        // - If first byte is 0x00, it's a 3-byte header (rare)
                        // The first byte of the record also encodes the handshake type
                        let first_byte = buffer[0];
                        let second_byte = buffer[1];

                        // SSLv2 ServerHello has:
                        // - Message type 0x04 (SERVER-HELLO) in the response
                        // - High bit set in first byte for 2-byte length encoding
                        let is_sslv2_header = (first_byte & 0x80) != 0;

                        // Additional check: SSLv2 record header encodes length
                        // For 2-byte header: length = ((byte[0] & 0x7f) << 8) | byte[1]
                        // The length should be reasonable (not exceed buffer)
                        if is_sslv2_header {
                            let record_len = ((first_byte & 0x7f) as usize) << 8 | second_byte as usize;
                            // SSLv2 responses typically have reasonable length (11-300+ bytes)
                            // and we should have read at least as many bytes as the header indicates
                            // Plus 2 for the header itself
                            let is_reasonable_length = record_len > 0 && record_len <= 16384;
                            let has_enough_data = n >= record_len.saturating_add(2).min(10);

                            if is_reasonable_length && has_enough_data {
                                // Verify this looks like an SSLv2 SERVER-HELLO
                                // Parse the record to check for SERVER-HELLO (type 4)
                                // The message type is after the header
                                let msg_type_offset = if record_len > 0 { 2 } else { 3 };
                                if n > msg_type_offset {
                                    let msg_type = buffer[msg_type_offset];
                                    // SERVER-HELLO has type 0x04
                                    if msg_type == 0x04 {
                                        return Ok(true);
                                    }
                                }
                            }
                        }

                        // If we couldn't definitively confirm SSLv2, be conservative
                        // and return false to avoid false positives
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test for SSLv2 export ciphers (makes DROWN easier to exploit)
    async fn test_sslv2_export_ciphers(&self) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send SSLv2 ClientHello with export ciphers only
                let client_hello = self.build_sslv2_client_hello_export();
                stream.write_all(&client_hello).await?;

                // Read response
                let mut buffer = vec![0u8; 4096];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 2 => {
                        // Same improved SSLv2 detection logic
                        let first_byte = buffer[0];
                        let second_byte = buffer[1];

                        let is_sslv2_header = (first_byte & 0x80) != 0;

                        if is_sslv2_header {
                            let record_len = ((first_byte & 0x7f) as usize) << 8 | second_byte as usize;
                            let is_reasonable_length = record_len > 0 && record_len <= 16384;
                            let has_enough_data = n >= record_len.saturating_add(2).min(10);

                            if is_reasonable_length && has_enough_data {
                                let msg_type_offset = if record_len > 0 { 2 } else { 3 };
                                if n > msg_type_offset {
                                    let msg_type = buffer[msg_type_offset];
                                    if msg_type == 0x04 {
                                        return Ok(true);
                                    }
                                }
                            }
                        }

                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
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
        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        hello.push(0x01);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC4_128_WITH_MD5
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

        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
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
        // 3 export ciphers * 3 bytes each = 9 bytes
        
        let cipher_specs_len: u16 = 9; // 3 ciphers * 3 bytes each
        let session_id_len: u16 = 0;
        let challenge_len: u16 = 16;
        
        // Calculate body length
        let body_len: u16 = 1 + 2 + 2 + 2 + 2 + cipher_specs_len + challenge_len; // = 34 bytes

        let mut hello = Vec::new();
        
        // SSLv2 record header (2-byte format with high bit set)
        let header_byte1 = 0x80 | ((body_len >> 8) & 0x7f) as u8;
        let header_byte2 = (body_len & 0xff) as u8;
        hello.push(header_byte1); // 0x80 (since body_len = 34 < 128)
        hello.push(header_byte2); // 0x22 (34 in hex)
        
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
        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        hello.push(0x04);
        hello.push(0x00);
        hello.push(0x80);

        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

        // SSL_CK_DES_64_CBC_WITH_MD5
        hello.push(0x06);
        hello.push(0x00);
        hello.push(0x40);

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
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drown_result_not_vulnerable() {
        let result = DrownTestResult {
            vulnerable: false,
            sslv2_supported: false,
            sslv2_export_ciphers: false,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        assert!(!result.sslv2_supported);
    }

    #[test]
    fn test_drown_result_vulnerable() {
        let result = DrownTestResult {
            vulnerable: true,
            sslv2_supported: true,
            sslv2_export_ciphers: false,
            details: "Vulnerable".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.sslv2_supported);
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
        assert_eq!(hello[6], 0x09); // cipher specs length low byte
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
