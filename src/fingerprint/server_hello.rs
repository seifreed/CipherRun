// ServerHello capture and parsing module
//
// This module implements parsing of TLS ServerHello messages for JA3S fingerprinting

use crate::Result;
use crate::error::TlsError;
use crate::utils::parse_length as length;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

/// TLS Extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

/// ServerHello message capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloCapture {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHelloCapture {
    fn cursor_position(cursor: &Cursor<&[u8]>) -> usize {
        // Reads stay within the slice, and the only explicit seek is to a validated offset.
        cursor.position() as usize
    }

    /// Parse ServerHello from raw TLS record bytes
    ///
    /// Expected format:
    /// - TLS Record Layer: ContentType(1) + Version(2) + Length(2) + Fragment
    /// - Handshake Protocol: HandshakeType(1) + Length(3) + Body
    /// - ServerHello: Version(2) + Random(32) + SessionID(1+N) + CipherSuite(2) + Compression(1) + Extensions
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Skip TLS record layer (5 bytes: ContentType + Version + Length)
        let mut record_header = [0u8; 5];
        cursor
            .read_exact(&mut record_header)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read record header: {}", e),
            })?;

        let content_type = record_header[0];
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        // The record length is a u16, so this addition fits all supported Rust targets.
        let record_end = 5 + record_len;
        if record_end > data.len() {
            return Err(TlsError::ParseError {
                message: "ServerHello record length exceeds available data".to_string(),
            });
        }

        // Check for TLS Alert (0x15) before expecting handshake
        if content_type == 0x15 {
            // Try to parse the alert to provide better error message
            if let Some([alert_level, alert_description]) = data
                .get(5..7)
                .and_then(|bytes| <&[u8; 2]>::try_from(bytes).ok())
            {
                return Err(TlsError::ParseError {
                    message: format!(
                        "TLS Alert received (level: {}, description: {}): {}",
                        alert_level,
                        alert_description,
                        Self::get_alert_description(*alert_description)
                    ),
                });
            } else {
                return Err(TlsError::ParseError {
                    message: "TLS Alert received from server".to_string(),
                });
            }
        }

        if content_type != 0x16 {
            return Err(TlsError::ParseError {
                message: format!(
                    "Invalid content type: expected 0x16 (handshake), got 0x{:02x}",
                    content_type
                ),
            });
        }

        // Parse handshake header (4 bytes: HandshakeType + Length)
        let mut handshake_header = [0u8; 4];
        cursor
            .read_exact(&mut handshake_header)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read handshake header: {}", e),
            })?;

        let handshake_type = handshake_header[0];
        if handshake_type != 0x02 {
            return Err(TlsError::ParseError {
                message: format!(
                    "Invalid handshake type: expected 0x02 (ServerHello), got 0x{:02x}",
                    handshake_type
                ),
            });
        }
        let handshake_len = ((handshake_header[1] as usize) << 16)
            | ((handshake_header[2] as usize) << 8)
            | handshake_header[3] as usize;
        // The handshake length is a 24-bit field and is bounded by the u16 record length.
        let handshake_end = 9 + handshake_len;
        if handshake_end > record_end {
            return Err(TlsError::ParseError {
                message: "ServerHello handshake length exceeds record length".to_string(),
            });
        }
        if handshake_end != record_end {
            return Err(TlsError::ParseError {
                message: "ServerHello record contains trailing bytes after handshake".to_string(),
            });
        }
        // handshake_end <= record_end <= data.len() was established above.
        let data = &data[..handshake_end];
        cursor = Cursor::new(data);
        cursor.set_position(9);

        // Parse ServerHello version (2 bytes)
        let mut version_bytes = [0u8; 2];
        cursor
            .read_exact(&mut version_bytes)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read version: {}", e),
            })?;
        let version = u16::from_be_bytes(version_bytes);

        // Parse random (32 bytes)
        let mut random = [0u8; 32];
        cursor
            .read_exact(&mut random)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read random: {}", e),
            })?;

        // Parse session ID (1 byte length + N bytes data)
        let mut session_id_len = [0u8; 1];
        cursor
            .read_exact(&mut session_id_len)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read session ID length: {}", e),
            })?;
        let session_id_len = session_id_len[0] as usize;

        let mut session_id = vec![0u8; session_id_len];
        if session_id_len > 0 {
            cursor
                .read_exact(&mut session_id)
                .map_err(|e| TlsError::ParseError {
                    message: format!("Failed to read session ID: {}", e),
                })?;
        }

        // Parse cipher suite (2 bytes)
        let mut cipher_bytes = [0u8; 2];
        cursor
            .read_exact(&mut cipher_bytes)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read cipher suite: {}", e),
            })?;
        let cipher_suite = u16::from_be_bytes(cipher_bytes);

        // Parse compression method (1 byte)
        let mut compression = [0u8; 1];
        cursor
            .read_exact(&mut compression)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to read compression: {}", e),
            })?;
        let compression_method = compression[0];

        // Parse extensions (optional)
        let mut extensions = Vec::new();

        // Check if there are extensions (need at least 2 bytes for extensions length)
        let position = Self::cursor_position(&cursor);
        let remaining = data.len().saturating_sub(position);
        if remaining == 1 {
            return Err(TlsError::ParseError {
                message: "ServerHello truncated before extensions length".to_string(),
            });
        }
        if remaining >= 2 {
            // Read extensions length
            let mut ext_len_bytes = [0u8; 2];
            cursor
                .read_exact(&mut ext_len_bytes)
                .expect("two extension-length bytes were checked above");
            let extensions_length = usize::from(u16::from_be_bytes(ext_len_bytes));
            let ext_start = Self::cursor_position(&cursor);
            let ext_end = ext_start + extensions_length;

            if ext_end > data.len() {
                return Err(TlsError::ParseError {
                    message: "Extensions exceed ServerHello length".to_string(),
                });
            }
            if ext_end != data.len() {
                return Err(TlsError::ParseError {
                    message: "ServerHello extension block contains trailing bytes".to_string(),
                });
            }

            if extensions_length > 0 {
                while Self::cursor_position(&cursor) < ext_end {
                    // Parse extension type (2 bytes)
                    let mut ext_type_bytes = [0u8; 2];
                    cursor
                        .read_exact(&mut ext_type_bytes)
                        .map_err(|e| TlsError::ParseError {
                            message: format!("Failed to read extension type: {}", e),
                        })?;
                    let ext_type = u16::from_be_bytes(ext_type_bytes);

                    // Parse extension length (2 bytes)
                    let mut ext_data_len_bytes = [0u8; 2];
                    cursor.read_exact(&mut ext_data_len_bytes).map_err(|e| {
                        TlsError::ParseError {
                            message: format!("Failed to read extension length: {}", e),
                        }
                    })?;
                    let ext_data_len = usize::from(u16::from_be_bytes(ext_data_len_bytes));

                    // Parse extension data
                    let ext_data_start = Self::cursor_position(&cursor);
                    let ext_data_end = ext_data_start + ext_data_len;
                    if ext_data_end > ext_end {
                        return Err(TlsError::ParseError {
                            message: "Failed to read extension data".to_string(),
                        });
                    }
                    let ext_data = data[ext_data_start..ext_data_end].to_vec();
                    cursor.set_position(ext_data_end as u64);

                    extensions.push(Extension {
                        extension_type: ext_type,
                        data: ext_data,
                    });
                }
            }
        }

        Ok(ServerHelloCapture {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Get extension IDs in order (for JA3S)
    pub fn get_extension_ids(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .map(|ext| ext.extension_type)
            .collect()
    }

    /// Convert to bytes for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Version
        bytes.extend_from_slice(&self.version.to_be_bytes());

        // Random
        bytes.extend_from_slice(&self.random);

        // Session ID
        bytes.push(length::u8_len(self.session_id.len(), "Session ID")?);
        bytes.extend_from_slice(&self.session_id);

        // Cipher suite
        bytes.extend_from_slice(&self.cipher_suite.to_be_bytes());

        // Compression method
        bytes.push(self.compression_method);

        // Extensions
        if !self.extensions.is_empty() {
            let mut extensions_bytes = Vec::new();
            for ext in &self.extensions {
                extensions_bytes.extend_from_slice(&ext.extension_type.to_be_bytes());
                let ext_len = length::u16_len(ext.data.len(), "Extension data")?;
                extensions_bytes.extend_from_slice(&ext_len.to_be_bytes());
                extensions_bytes.extend_from_slice(&ext.data);
            }

            let ext_total_len = length::u16_len(extensions_bytes.len(), "Extensions")?;
            bytes.extend_from_slice(&ext_total_len.to_be_bytes());
            bytes.extend_from_slice(&extensions_bytes);
        }

        Ok(bytes)
    }

    /// Get human-readable TLS alert description
    fn get_alert_description(alert_code: u8) -> &'static str {
        match alert_code {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            21 => "decryption_failed",
            22 => "record_overflow",
            30 => "decompression_failure",
            40 => "handshake_failure",
            41 => "no_certificate",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            60 => "export_restriction",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            109 => "missing_extension",
            110 => "unsupported_extension",
            111 => "certificate_unobtainable",
            112 => "unrecognized_name",
            113 => "bad_certificate_status_response",
            114 => "bad_certificate_hash_value",
            115 => "unknown_psk_identity",
            116 => "certificate_required",
            120 => "no_application_protocol",
            _ => "unknown_alert",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with_fragment(content_type: u8, fragment: &[u8]) -> Vec<u8> {
        let mut record = vec![content_type, 0x03, 0x03];
        record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        record.extend_from_slice(fragment);
        record
    }

    fn server_hello_body() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x2f, 0]);
        body
    }

    fn server_hello_record(body: &[u8]) -> Vec<u8> {
        let mut fragment = vec![0x02];
        fragment.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        fragment.extend_from_slice(body);
        record_with_fragment(0x16, &fragment)
    }

    #[test]
    fn test_parse_serverhello_basic() {
        // Minimal ServerHello: TLS 1.2, no session ID, TLS_RSA_WITH_AES_128_CBC_SHA, no compression, no extensions
        let data = vec![
            // Record layer
            0x16, 0x03, 0x03, 0x00, 0x2A, // Handshake, TLS 1.2, length 42
            // Handshake header
            0x02, 0x00, 0x00, 0x26, // ServerHello, length 38
            // ServerHello
            0x03, 0x03, // TLS 1.2 (0x0303)
            // Random (32 bytes of zeros for simplicity)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Session ID
            0x00, // Length 0
            // Cipher suite
            0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA (47)
            // Compression
            0x00, // No compression
        ];

        let result = ServerHelloCapture::parse(&data);
        assert!(result.is_ok());

        let server_hello = result.expect("test assertion should succeed");
        assert_eq!(server_hello.version, 0x0303); // TLS 1.2
        assert_eq!(server_hello.cipher_suite, 0x002F);
        assert_eq!(server_hello.compression_method, 0);
        assert!(server_hello.extensions.is_empty());
    }

    #[test]
    fn test_parse_serverhello_with_extensions() {
        // ServerHello with one extension
        let data = vec![
            // Record layer
            0x16, 0x03, 0x03, 0x00, 0x35, // Handshake, TLS 1.2, length 53
            // Handshake header
            0x02, 0x00, 0x00, 0x31, // ServerHello, length 49
            // ServerHello
            0x03, 0x03, // TLS 1.2
            // Random
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Session ID
            0x00, // Cipher suite
            0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            // Compression
            0x00, // Extensions
            0x00, 0x09, // Extensions length: 9 bytes
            // Extension 1: renegotiation_info (0xFF01)
            0xFF, 0x01, // Type
            0x00, 0x01, // Length: 1
            0x00, // Data
            // Extension 2: server_name (0x0000)
            0x00, 0x00, // Type
            0x00, 0x00, // Length: 0
        ];

        let result = ServerHelloCapture::parse(&data);
        assert!(result.is_ok());

        let server_hello = result.expect("test assertion should succeed");
        assert_eq!(server_hello.version, 0x0303);
        assert_eq!(server_hello.cipher_suite, 0xC02F);
        assert_eq!(server_hello.extensions.len(), 2);
        assert_eq!(server_hello.extensions[0].extension_type, 0xFF01);
        assert_eq!(server_hello.extensions[1].extension_type, 0x0000);
    }

    #[test]
    fn test_parse_serverhello_rejects_truncated_extension_data() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x31, // Handshake, TLS 1.2, length 49
            0x02, 0x00, 0x00, 0x2D, // ServerHello, length 45
            0x03, 0x03, // TLS 1.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Session ID
            0x00, // Cipher suite
            0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0x00, // Compression
            0x00, 0x05, // Extensions length: 5 bytes
            0x00, 0x00, // Extension type: server_name
            0x00, 0x02, // Extension length: 2 bytes
            0x00, // Truncated extension data
        ];

        let err = ServerHelloCapture::parse(&data).unwrap_err();
        assert!(err.to_string().contains("Failed to read extension data"));
    }

    #[test]
    fn test_parse_serverhello_rejects_extension_after_handshake_end() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x30, // record includes trailing bytes
            0x02, 0x00, 0x00, 0x26, // ServerHello ends before extensions
            0x03, 0x03, // TLS 1.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x2F, // cipher suite
            0x00, // compression
            0x00, 0x04, // trailing extension block outside handshake
            0x00, 0x0f, 0x00, 0x00,
        ];

        let err = ServerHelloCapture::parse(&data).expect_err("trailing bytes should fail");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn test_parse_serverhello_rejects_truncated_extensions_length() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x2B, // Handshake, TLS 1.2, length 43
            0x02, 0x00, 0x00, 0x27, // ServerHello, length 39
            0x03, 0x03, // TLS 1.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x2F, // cipher suite
            0x00, // compression
            0x00, // truncated extensions length
        ];

        let err = ServerHelloCapture::parse(&data).expect_err("parser should reject");
        assert!(err.to_string().contains("extensions length"));
    }

    #[test]
    fn test_parse_serverhello_rejects_extension_block_trailing_bytes() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x2D, // Handshake, TLS 1.2, length 45
            0x02, 0x00, 0x00, 0x29, // ServerHello, length 41
            0x03, 0x03, // TLS 1.2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x2F, // cipher suite
            0x00, // compression
            0x00, 0x00, // zero-length extension block
            0x00, // trailing byte inside handshake
        ];

        let err = ServerHelloCapture::parse(&data).expect_err("parser should reject");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn test_parse_serverhello_rejects_body_after_handshake_end() {
        let data = vec![
            0x16, 0x03, 0x03, 0x00, 0x2A, // record contains a complete body
            0x02, 0x00, 0x00, 0x00, // ServerHello declares an empty body
            0x03, 0x03, // trailing bytes must not satisfy required fields
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x2F, // cipher suite
            0x00, // compression
        ];

        let err = ServerHelloCapture::parse(&data).expect_err("truncated handshake body must fail");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn test_parse_serverhello_alert_error() {
        let data = vec![
            0x15, 0x03, 0x03, 0x00, 0x02, // Alert record header
            0x02, 0x28, // level=fatal(2), description=40
        ];

        let result = ServerHelloCapture::parse(&data);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("TLS Alert"));
    }

    #[test]
    fn test_parse_serverhello_invalid_content_type() {
        let data = vec![
            0x14, 0x03, 0x03, 0x00, 0x00, // ChangeCipherSpec record
        ];

        let result = ServerHelloCapture::parse(&data);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Invalid content type"));
    }

    #[test]
    fn parse_rejects_truncated_records_and_invalid_handshakes() {
        for (data, expected) in [
            (Vec::new(), "Failed to read record header"),
            (
                record_with_fragment(0x16, &[0x02, 0, 0]),
                "Failed to read handshake header",
            ),
            (
                record_with_fragment(0x16, &[0x01, 0, 0, 0]),
                "Invalid handshake type",
            ),
            (
                record_with_fragment(0x16, &[0x02, 0, 0, 1]),
                "handshake length exceeds record length",
            ),
            (
                record_with_fragment(0x16, &[0x02, 0, 0, 0, 0xff]),
                "trailing bytes after handshake",
            ),
            (
                record_with_fragment(0x15, &[]),
                "TLS Alert received from server",
            ),
        ] {
            let error = ServerHelloCapture::parse(&data).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{error}: expected {expected}"
            );
        }

        let mut short_record = record_with_fragment(0x16, &[]);
        short_record[3..5].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            ServerHelloCapture::parse(&short_record)
                .unwrap_err()
                .to_string()
                .contains("record length exceeds available data")
        );
    }

    #[test]
    fn parse_rejects_truncated_server_hello_fields_and_extensions() {
        let mut body = server_hello_body();
        for (truncated, expected) in [
            (vec![0x03], "Failed to read version"),
            (
                {
                    let mut bytes = vec![0x03, 0x03];
                    bytes.extend_from_slice(&[0; 31]);
                    bytes
                },
                "Failed to read random",
            ),
            (
                {
                    let mut bytes = vec![0x03, 0x03];
                    bytes.extend_from_slice(&[0; 32]);
                    bytes
                },
                "Failed to read session ID length",
            ),
            (
                {
                    let mut bytes = vec![0x03, 0x03];
                    bytes.extend_from_slice(&[0; 32]);
                    bytes.push(1);
                    bytes
                },
                "Failed to read session ID",
            ),
            (body[..35].to_vec(), "Failed to read cipher suite"),
            (body[..37].to_vec(), "Failed to read compression"),
        ] {
            let error = ServerHelloCapture::parse(&server_hello_record(&truncated)).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{error}: expected {expected}"
            );
        }

        body.push(0);
        let error = ServerHelloCapture::parse(&server_hello_record(&body)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("truncated before extensions length")
        );

        for (extensions, expected) in [
            (vec![0, 4, 0, 0], "Extensions exceed ServerHello length"),
            (vec![0, 0, 0], "extension block contains trailing bytes"),
            (vec![0, 1, 0], "Failed to read extension type"),
            (vec![0, 2, 0, 1], "Failed to read extension length"),
            (vec![0, 5, 0, 1, 0, 2, 0], "Failed to read extension data"),
        ] {
            let mut body = server_hello_body();
            body.extend_from_slice(&extensions);
            let error = ServerHelloCapture::parse(&server_hello_record(&body)).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{error}: expected {expected}"
            );
        }
    }

    #[test]
    fn parse_accepts_an_explicit_empty_extension_block() {
        let mut body = server_hello_body();
        body.extend_from_slice(&[0, 0]);

        let parsed = ServerHelloCapture::parse(&server_hello_record(&body)).unwrap();

        assert!(parsed.extensions.is_empty());
    }

    #[test]
    fn server_hello_serialization_round_trips_and_checks_encoded_lengths() {
        let capture = ServerHelloCapture {
            version: 0x0303,
            random: [0x5a; 32],
            session_id: vec![1, 2, 3],
            cipher_suite: 0xc02f,
            compression_method: 0,
            extensions: vec![
                Extension {
                    extension_type: 0xff01,
                    data: vec![0],
                },
                Extension {
                    extension_type: 0x002b,
                    data: vec![0x03, 0x04],
                },
            ],
        };
        let decoded =
            ServerHelloCapture::parse(&server_hello_record(&capture.to_bytes().unwrap())).unwrap();
        assert_eq!(decoded.version, capture.version);
        assert_eq!(decoded.random, capture.random);
        assert_eq!(decoded.session_id, capture.session_id);
        assert_eq!(decoded.cipher_suite, capture.cipher_suite);
        assert_eq!(decoded.compression_method, capture.compression_method);
        assert_eq!(decoded.get_extension_ids(), vec![0xff01, 0x002b]);

        let without_extensions = ServerHelloCapture {
            extensions: Vec::new(),
            ..capture.clone()
        };
        let decoded = ServerHelloCapture::parse(&server_hello_record(
            &without_extensions.to_bytes().unwrap(),
        ))
        .unwrap();
        assert!(decoded.extensions.is_empty());

        let mut oversized_session = capture.clone();
        oversized_session.session_id = vec![0; 256];
        assert!(oversized_session.to_bytes().is_err());

        let mut oversized_extension = capture.clone();
        oversized_extension.extensions = vec![Extension {
            extension_type: 1,
            data: vec![0; usize::from(u16::MAX) + 1],
        }];
        assert!(oversized_extension.to_bytes().is_err());

        let mut oversized_extension_block = capture;
        oversized_extension_block.extensions = (0..16)
            .map(|extension_type| Extension {
                extension_type,
                data: vec![0; 4096],
            })
            .collect();
        assert!(oversized_extension_block.to_bytes().is_err());
    }

    #[test]
    fn alert_descriptions_have_stable_names() {
        for (code, name) in [
            (0, "close_notify"),
            (10, "unexpected_message"),
            (20, "bad_record_mac"),
            (21, "decryption_failed"),
            (22, "record_overflow"),
            (30, "decompression_failure"),
            (40, "handshake_failure"),
            (41, "no_certificate"),
            (42, "bad_certificate"),
            (43, "unsupported_certificate"),
            (44, "certificate_revoked"),
            (45, "certificate_expired"),
            (46, "certificate_unknown"),
            (47, "illegal_parameter"),
            (48, "unknown_ca"),
            (49, "access_denied"),
            (50, "decode_error"),
            (51, "decrypt_error"),
            (60, "export_restriction"),
            (70, "protocol_version"),
            (71, "insufficient_security"),
            (80, "internal_error"),
            (86, "inappropriate_fallback"),
            (90, "user_canceled"),
            (100, "no_renegotiation"),
            (109, "missing_extension"),
            (110, "unsupported_extension"),
            (111, "certificate_unobtainable"),
            (112, "unrecognized_name"),
            (113, "bad_certificate_status_response"),
            (114, "bad_certificate_hash_value"),
            (115, "unknown_psk_identity"),
            (116, "certificate_required"),
            (120, "no_application_protocol"),
            (255, "unknown_alert"),
        ] {
            assert_eq!(ServerHelloCapture::get_alert_description(code), name);
        }
    }
}
