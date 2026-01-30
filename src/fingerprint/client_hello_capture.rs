// ClientHello Capture and Parsing
// Captures and parses TLS ClientHello messages for JA3 fingerprinting

use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, EXTENSION_ALPN, EXTENSION_EC_POINT_FORMATS, EXTENSION_SERVER_NAME,
    EXTENSION_SUPPORTED_GROUPS, HANDSHAKE_TYPE_CLIENT_HELLO, RANDOM_BYTES_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use crate::{Result, TlsError};
use serde::{Deserialize, Serialize};

/// TLS Extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    /// Extension type ID
    pub extension_type: u16,

    /// Extension data
    pub data: Vec<u8>,
}

/// Captured ClientHello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloCapture {
    /// TLS version from ClientHello
    pub version: u16,

    /// Random bytes (32 bytes)
    pub random: [u8; 32],

    /// Session ID
    pub session_id: Vec<u8>,

    /// Cipher suites
    pub cipher_suites: Vec<u16>,

    /// Compression methods
    pub compression_methods: Vec<u8>,

    /// Extensions
    pub extensions: Vec<Extension>,
}

impl ClientHelloCapture {
    /// Parse ClientHello from raw TLS record
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Parse TLS record layer
        if data.len() < TLS_RECORD_HEADER_SIZE {
            return Err(TlsError::ParseError {
                message: "Data too short for TLS record header".to_string(),
            });
        }

        let record_type = data[cursor];
        cursor += 1;

        if record_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsError::ParseError {
                message: format!("Not a handshake record (type: 0x{:02x})", record_type),
            });
        }

        // Skip TLS version (2 bytes) and length (2 bytes)
        cursor += 4;

        // Parse handshake protocol
        if data.len() < cursor + 4 {
            return Err(TlsError::ParseError {
                message: "Data too short for handshake header".to_string(),
            });
        }

        let handshake_type = data[cursor];
        cursor += 1;

        if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(TlsError::ParseError {
                message: format!("Not a ClientHello (type: 0x{:02x})", handshake_type),
            });
        }

        // Skip handshake length (3 bytes)
        cursor += 3;

        // Parse ClientHello
        if data.len() < cursor + 2 {
            return Err(TlsError::ParseError {
                message: "Data too short for ClientHello version".to_string(),
            });
        }

        let version = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;

        // Random (32 bytes)
        if data.len() < cursor + RANDOM_BYTES_SIZE {
            return Err(TlsError::ParseError {
                message: "Data too short for random".to_string(),
            });
        }

        let mut random = [0u8; RANDOM_BYTES_SIZE];
        random.copy_from_slice(&data[cursor..cursor + RANDOM_BYTES_SIZE]);
        cursor += RANDOM_BYTES_SIZE;

        // Session ID
        if data.len() < cursor + 1 {
            return Err(TlsError::ParseError {
                message: "Data too short for session ID length".to_string(),
            });
        }

        let session_id_len = data[cursor] as usize;
        cursor += 1;

        if data.len() < cursor + session_id_len {
            return Err(TlsError::ParseError {
                message: "Data too short for session ID".to_string(),
            });
        }

        let session_id = data[cursor..cursor + session_id_len].to_vec();
        cursor += session_id_len;

        // Cipher suites
        if data.len() < cursor + 2 {
            return Err(TlsError::ParseError {
                message: "Data too short for cipher suites length".to_string(),
            });
        }

        let cipher_suites_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;

        if data.len() < cursor + cipher_suites_len {
            return Err(TlsError::ParseError {
                message: "Data too short for cipher suites".to_string(),
            });
        }

        let mut cipher_suites = Vec::new();
        let mut i = 0;
        while i < cipher_suites_len {
            if cursor + i + 2 > data.len() {
                break;
            }
            let cipher = u16::from_be_bytes([data[cursor + i], data[cursor + i + 1]]);
            cipher_suites.push(cipher);
            i += 2;
        }
        cursor += cipher_suites_len;

        // Compression methods
        if data.len() < cursor + 1 {
            return Err(TlsError::ParseError {
                message: "Data too short for compression methods length".to_string(),
            });
        }

        let compression_methods_len = data[cursor] as usize;
        cursor += 1;

        if data.len() < cursor + compression_methods_len {
            return Err(TlsError::ParseError {
                message: "Data too short for compression methods".to_string(),
            });
        }

        let compression_methods = data[cursor..cursor + compression_methods_len].to_vec();
        cursor += compression_methods_len;

        // Extensions
        let mut extensions = Vec::new();

        if cursor < data.len() {
            // Extensions length
            if data.len() < cursor + 2 {
                return Err(TlsError::ParseError {
                    message: "Data too short for extensions length".to_string(),
                });
            }

            let extensions_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
            cursor += 2;

            if data.len() < cursor + extensions_len {
                return Err(TlsError::ParseError {
                    message: "Data too short for extensions".to_string(),
                });
            }

            let extensions_end = cursor + extensions_len;

            while cursor < extensions_end {
                if cursor + 4 > data.len() {
                    break;
                }

                let extension_type = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
                cursor += 2;

                let extension_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
                cursor += 2;

                if cursor + extension_len > data.len() {
                    break;
                }

                let extension_data = data[cursor..cursor + extension_len].to_vec();
                cursor += extension_len;

                extensions.push(Extension {
                    extension_type,
                    data: extension_data,
                });
            }
        }

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Create a synthetic ClientHello for testing
    pub fn synthetic(
        version: u16,
        cipher_suites: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    ) -> Self {
        let random = [0u8; 32];
        let session_id = vec![];
        let compression_methods = vec![0]; // No compression

        let extensions = extensions
            .into_iter()
            .map(|(extension_type, data)| Extension {
                extension_type,
                data,
            })
            .collect();

        Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        }
    }

    /// Get supported groups (curves) from extensions
    pub fn get_supported_groups(&self) -> Vec<u16> {
        for ext in &self.extensions {
            if ext.extension_type == EXTENSION_SUPPORTED_GROUPS {
                return Self::parse_supported_groups(&ext.data);
            }
        }
        vec![]
    }

    /// Parse supported groups extension data
    fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
        if data.len() < 2 {
            return vec![];
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + list_len {
            return vec![];
        }

        let mut groups = Vec::new();
        let mut i = 2;
        while i + 2 <= 2 + list_len {
            let group = u16::from_be_bytes([data[i], data[i + 1]]);
            groups.push(group);
            i += 2;
        }

        groups
    }

    /// Get EC point formats from extensions
    pub fn get_point_formats(&self) -> Vec<u8> {
        for ext in &self.extensions {
            if ext.extension_type == EXTENSION_EC_POINT_FORMATS {
                return Self::parse_point_formats(&ext.data);
            }
        }
        vec![]
    }

    /// Parse EC point formats extension data
    fn parse_point_formats(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![];
        }

        let list_len = data[0] as usize;
        if data.len() < 1 + list_len {
            return vec![];
        }

        data[1..1 + list_len].to_vec()
    }

    /// Convert ClientHello to bytes (for storage/transmission)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // TLS Record Header
        bytes.push(CONTENT_TYPE_HANDSHAKE);
        bytes.extend_from_slice(&self.version.to_be_bytes());

        // Placeholder for record length (will update later)
        let record_len_pos = bytes.len();
        bytes.extend_from_slice(&[0u8, 0u8]);

        // Handshake Header
        bytes.push(HANDSHAKE_TYPE_CLIENT_HELLO);

        // Placeholder for handshake length (will update later)
        let handshake_len_pos = bytes.len();
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);

        // ClientHello version
        bytes.extend_from_slice(&self.version.to_be_bytes());

        // Random
        bytes.extend_from_slice(&self.random);

        // Session ID
        bytes.push(self.session_id.len() as u8);
        bytes.extend_from_slice(&self.session_id);

        // Cipher Suites
        let cipher_suites_len = (self.cipher_suites.len() * 2) as u16;
        bytes.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for cipher in &self.cipher_suites {
            bytes.extend_from_slice(&cipher.to_be_bytes());
        }

        // Compression Methods
        bytes.push(self.compression_methods.len() as u8);
        bytes.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let _extensions_start = bytes.len() + 2;
            let mut extensions_bytes = Vec::new();

            for ext in &self.extensions {
                extensions_bytes.extend_from_slice(&ext.extension_type.to_be_bytes());
                extensions_bytes.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
                extensions_bytes.extend_from_slice(&ext.data);
            }

            let extensions_len = extensions_bytes.len() as u16;
            bytes.extend_from_slice(&extensions_len.to_be_bytes());
            bytes.extend_from_slice(&extensions_bytes);
        }

        // Update handshake length
        let handshake_len = (bytes.len() - handshake_len_pos - 3) as u32;
        bytes[handshake_len_pos] = ((handshake_len >> 16) & 0xff) as u8;
        bytes[handshake_len_pos + 1] = ((handshake_len >> 8) & 0xff) as u8;
        bytes[handshake_len_pos + 2] = (handshake_len & 0xff) as u8;

        // Update record length
        let record_len = (bytes.len() - record_len_pos - 2) as u16;
        bytes[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        bytes[record_len_pos + 1] = (record_len & 0xff) as u8;

        bytes
    }

    /// Get SNI (Server Name Indication) from extensions
    pub fn get_sni(&self) -> Option<String> {
        for ext in &self.extensions {
            if ext.extension_type == EXTENSION_SERVER_NAME {
                return Self::parse_sni(&ext.data);
            }
        }
        None
    }

    /// Parse SNI extension data
    fn parse_sni(data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // Skip server name list length (2 bytes)
        let mut cursor = 2;

        // Server name type (1 byte, should be 0 for hostname)
        if data[cursor] != 0 {
            return None;
        }
        cursor += 1;

        // Server name length (2 bytes)
        let name_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;

        if data.len() < cursor + name_len {
            return None;
        }

        // Server name
        let name_bytes = &data[cursor..cursor + name_len];
        String::from_utf8(name_bytes.to_vec()).ok()
    }

    /// Get ALPN (Application-Layer Protocol Negotiation) from extensions
    pub fn get_alpn(&self) -> Vec<String> {
        for ext in &self.extensions {
            if ext.extension_type == EXTENSION_ALPN {
                return Self::parse_alpn(&ext.data);
            }
        }
        vec![]
    }

    /// Parse ALPN extension data
    fn parse_alpn(data: &[u8]) -> Vec<String> {
        if data.len() < 2 {
            return vec![];
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + list_len {
            return vec![];
        }

        let mut protocols = Vec::new();
        let mut cursor = 2;

        while cursor < 2 + list_len {
            if cursor >= data.len() {
                break;
            }

            let proto_len = data[cursor] as usize;
            cursor += 1;

            if cursor + proto_len > data.len() {
                break;
            }

            if let Ok(proto) = String::from_utf8(data[cursor..cursor + proto_len].to_vec()) {
                protocols.push(proto);
            }
            cursor += proto_len;
        }

        protocols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_client_hello() {
        let client_hello = ClientHelloCapture::synthetic(
            0x0303, // TLS 1.2
            vec![0xc02f, 0xc030, 0x009e, 0x009f],
            vec![
                (0, vec![]),                    // server_name (empty for test)
                (10, vec![0, 4, 0, 23, 0, 24]), // supported_groups: secp256r1, secp384r1
                (11, vec![1, 0]),               // ec_point_formats: uncompressed
            ],
        );

        assert_eq!(client_hello.version, 0x0303);
        assert_eq!(client_hello.cipher_suites.len(), 4);
        assert_eq!(client_hello.extensions.len(), 3);

        let groups = client_hello.get_supported_groups();
        assert_eq!(groups, vec![23, 24]);

        let formats = client_hello.get_point_formats();
        assert_eq!(formats, vec![0]);
    }

    #[test]
    fn test_supported_groups_parsing() {
        let data = vec![0, 4, 0, 23, 0, 24]; // Length: 4, Groups: 23, 24
        let groups = ClientHelloCapture::parse_supported_groups(&data);
        assert_eq!(groups, vec![23, 24]);
    }

    #[test]
    fn test_point_formats_parsing() {
        let data = vec![1, 0]; // Length: 1, Format: 0 (uncompressed)
        let formats = ClientHelloCapture::parse_point_formats(&data);
        assert_eq!(formats, vec![0]);
    }

    #[test]
    fn test_round_trip_serialization() {
        let client_hello = ClientHelloCapture::synthetic(
            0x0303,
            vec![0xc02f, 0xc030],
            vec![(10, vec![0, 2, 0, 23])],
        );

        let bytes = client_hello.to_bytes();
        assert!(!bytes.is_empty());

        // Should be able to parse back
        let parsed = ClientHelloCapture::parse(&bytes);
        assert!(parsed.is_ok());

        let parsed = parsed.expect("test assertion should succeed");
        assert_eq!(parsed.version, client_hello.version);
        assert_eq!(parsed.cipher_suites, client_hello.cipher_suites);
    }
}
