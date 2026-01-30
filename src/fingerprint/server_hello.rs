// ServerHello capture and parsing module
//
// This module implements parsing of TLS ServerHello messages for JA3S fingerprinting

use crate::Result;
use crate::error::TlsError;
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

        // Check for TLS Alert (0x15) before expecting handshake
        if content_type == 0x15 {
            // Try to parse the alert to provide better error message
            if data.len() >= 7 {
                let alert_level = data[5];
                let alert_description = data[6];
                return Err(TlsError::ParseError {
                    message: format!(
                        "TLS Alert received (level: {}, description: {}): {}",
                        alert_level,
                        alert_description,
                        Self::get_alert_description(alert_description)
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
        let position = cursor.position() as usize;
        if position < data.len() - 1 {
            // Read extensions length
            let mut ext_len_bytes = [0u8; 2];
            if cursor.read_exact(&mut ext_len_bytes).is_ok() {
                let extensions_length = u16::from_be_bytes(ext_len_bytes) as usize;

                if extensions_length > 0 {
                    let ext_start = cursor.position() as usize;
                    let ext_end = ext_start + extensions_length;

                    if ext_end <= data.len() {
                        while (cursor.position() as usize) < ext_end {
                            // Parse extension type (2 bytes)
                            let mut ext_type_bytes = [0u8; 2];
                            if cursor.read_exact(&mut ext_type_bytes).is_err() {
                                break;
                            }
                            let ext_type = u16::from_be_bytes(ext_type_bytes);

                            // Parse extension length (2 bytes)
                            let mut ext_data_len_bytes = [0u8; 2];
                            if cursor.read_exact(&mut ext_data_len_bytes).is_err() {
                                break;
                            }
                            let ext_data_len = u16::from_be_bytes(ext_data_len_bytes) as usize;

                            // Parse extension data
                            let mut ext_data = vec![0u8; ext_data_len];
                            if ext_data_len > 0 && cursor.read_exact(&mut ext_data).is_err() {
                                break;
                            }

                            extensions.push(Extension {
                                extension_type: ext_type,
                                data: ext_data,
                            });
                        }
                    }
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version
        bytes.extend_from_slice(&self.version.to_be_bytes());

        // Random
        bytes.extend_from_slice(&self.random);

        // Session ID
        bytes.push(self.session_id.len() as u8);
        bytes.extend_from_slice(&self.session_id);

        // Cipher suite
        bytes.extend_from_slice(&self.cipher_suite.to_be_bytes());

        // Compression method
        bytes.push(self.compression_method);

        // Extensions
        if !self.extensions.is_empty() {
            let ext_total_len: u16 = self
                .extensions
                .iter()
                .map(|e| 4 + e.data.len() as u16)
                .sum();
            bytes.extend_from_slice(&ext_total_len.to_be_bytes());

            for ext in &self.extensions {
                bytes.extend_from_slice(&ext.extension_type.to_be_bytes());
                bytes.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&ext.data);
            }
        }

        bytes
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

    #[test]
    fn test_parse_serverhello_basic() {
        // Minimal ServerHello: TLS 1.2, no session ID, TLS_RSA_WITH_AES_128_CBC_SHA, no compression, no extensions
        let data = vec![
            // Record layer
            0x16, 0x03, 0x03, 0x00, 0x31, // Handshake, TLS 1.2, length 49
            // Handshake header
            0x02, 0x00, 0x00, 0x2D, // ServerHello, length 45
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
            0x16, 0x03, 0x03, 0x00, 0x3B, // Handshake, TLS 1.2, length 59
            // Handshake header
            0x02, 0x00, 0x00, 0x37, // ServerHello, length 55
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
            0x00, 0x08, // Extensions length: 8 bytes
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
}
