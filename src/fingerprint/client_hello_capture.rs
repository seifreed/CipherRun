// ClientHello Capture and Parsing
// Captures and parses TLS ClientHello messages for JA3 fingerprinting

use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, EXTENSION_EC_POINT_FORMATS, EXTENSION_SERVER_NAME,
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
    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} too short"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let end = offset.checked_add(2).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        let bytes = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} too short"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
        let end = offset.checked_add(3).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        let [high, mid, low] = data
            .get(offset..end)
            .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: format!("{context} too short"),
            })?;
        Ok(((high as usize) << 16) | ((mid as usize) << 8) | low as usize)
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8]> {
        let end = start.checked_add(len).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} length overflow"),
        })?;
        data.get(start..end).ok_or_else(|| TlsError::ParseError {
            message: format!("{context} too short"),
        })
    }

    fn u8_len(len: usize, context: &str) -> Result<u8> {
        u8::try_from(len).map_err(|_| TlsError::ParseError {
            message: format!("{context} length is too large"),
        })
    }

    fn u16_len(len: usize, context: &str) -> Result<u16> {
        u16::try_from(len).map_err(|_| TlsError::ParseError {
            message: format!("{context} length is too large"),
        })
    }

    fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
        let len = u32::try_from(len).map_err(|_| TlsError::ParseError {
            message: format!("{context} length is too large"),
        })?;
        if len > 0x00FF_FFFF {
            return Err(TlsError::ParseError {
                message: format!("{context} length is too large"),
            });
        }
        let bytes = len.to_be_bytes();
        Ok([bytes[1], bytes[2], bytes[3]])
    }

    /// Parse ClientHello from raw TLS record
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Parse TLS record layer
        if data.len() < TLS_RECORD_HEADER_SIZE {
            return Err(TlsError::ParseError {
                message: "Data too short for TLS record header".to_string(),
            });
        }

        let record_type = Self::read_u8_at(data, cursor, "TLS record")?;
        cursor += 1;

        if record_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsError::ParseError {
                message: format!("Not a handshake record (type: 0x{:02x})", record_type),
            });
        }

        let record_len = Self::read_u16_at(data, 3, "TLS record length")? as usize;
        let record_end = TLS_RECORD_HEADER_SIZE
            .checked_add(record_len)
            .ok_or_else(|| TlsError::ParseError {
                message: "TLS record length overflow".to_string(),
            })?;
        if record_end > data.len() {
            return Err(TlsError::ParseError {
                message: "TLS record length exceeds available data".to_string(),
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

        let handshake_type = Self::read_u8_at(data, cursor, "Handshake header")?;
        cursor += 1;

        if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(TlsError::ParseError {
                message: format!("Not a ClientHello (type: 0x{:02x})", handshake_type),
            });
        }

        let handshake_len = Self::read_u24_at(data, cursor, "Handshake length")?;
        let handshake_end = cursor
            .checked_add(3)
            .and_then(|body_start| body_start.checked_add(handshake_len))
            .ok_or_else(|| TlsError::ParseError {
                message: "Handshake length overflow".to_string(),
            })?;
        if handshake_end > record_end {
            return Err(TlsError::ParseError {
                message: "Handshake length exceeds record length".to_string(),
            });
        }
        let data = data
            .get(..handshake_end)
            .ok_or_else(|| TlsError::ParseError {
                message: "Handshake length exceeds available data".to_string(),
            })?;

        // Skip handshake length (3 bytes)
        cursor += 3;

        // Parse ClientHello
        if data.len() < cursor + 2 {
            return Err(TlsError::ParseError {
                message: "Data too short for ClientHello version".to_string(),
            });
        }

        let version = Self::read_u16_at(data, cursor, "ClientHello version")?;
        cursor += 2;

        // Random (32 bytes)
        if data.len() < cursor + RANDOM_BYTES_SIZE {
            return Err(TlsError::ParseError {
                message: "Data too short for random".to_string(),
            });
        }

        let mut random = [0u8; RANDOM_BYTES_SIZE];
        random.copy_from_slice(Self::slice_range(
            data,
            cursor,
            RANDOM_BYTES_SIZE,
            "ClientHello random",
        )?);
        cursor += RANDOM_BYTES_SIZE;

        // Session ID
        if data.len() < cursor + 1 {
            return Err(TlsError::ParseError {
                message: "Data too short for session ID length".to_string(),
            });
        }

        let session_id_len = Self::read_u8_at(data, cursor, "Session ID length")? as usize;
        cursor += 1;

        if data.len() < cursor + session_id_len {
            return Err(TlsError::ParseError {
                message: "Data too short for session ID".to_string(),
            });
        }

        let session_id = Self::slice_range(data, cursor, session_id_len, "Session ID")?.to_vec();
        cursor += session_id_len;

        // Cipher suites
        if data.len() < cursor + 2 {
            return Err(TlsError::ParseError {
                message: "Data too short for cipher suites length".to_string(),
            });
        }

        let cipher_suites_len = Self::read_u16_at(data, cursor, "Cipher suites length")? as usize;
        cursor += 2;

        // Validate cipher suites length is even (each cipher suite is 2 bytes)
        if !cipher_suites_len.is_multiple_of(2) {
            return Err(TlsError::ParseError {
                message: format!(
                    "Invalid cipher suites length: {} (must be even, each cipher is 2 bytes)",
                    cipher_suites_len
                ),
            });
        }

        if data.len() < cursor + cipher_suites_len {
            return Err(TlsError::ParseError {
                message: "Data too short for cipher suites".to_string(),
            });
        }

        let mut cipher_suites = Vec::new();
        for chunk in
            Self::slice_range(data, cursor, cipher_suites_len, "Cipher suites")?.chunks_exact(2)
        {
            let bytes = <[u8; 2]>::try_from(chunk).map_err(|_| TlsError::ParseError {
                message: "Invalid cipher suite width".to_string(),
            })?;
            cipher_suites.push(u16::from_be_bytes(bytes));
        }
        cursor += cipher_suites_len;

        // Compression methods
        if data.len() < cursor + 1 {
            return Err(TlsError::ParseError {
                message: "Data too short for compression methods length".to_string(),
            });
        }

        let compression_methods_len =
            Self::read_u8_at(data, cursor, "Compression methods length")? as usize;
        cursor += 1;

        if data.len() < cursor + compression_methods_len {
            return Err(TlsError::ParseError {
                message: "Data too short for compression methods".to_string(),
            });
        }

        let compression_methods =
            Self::slice_range(data, cursor, compression_methods_len, "Compression methods")?
                .to_vec();
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

            let extensions_len = Self::read_u16_at(data, cursor, "Extensions length")? as usize;
            cursor += 2;

            if data.len() < cursor + extensions_len {
                return Err(TlsError::ParseError {
                    message: "Data too short for extensions".to_string(),
                });
            }

            let extensions_end = cursor + extensions_len;

            while cursor < extensions_end {
                if cursor + 4 > extensions_end {
                    return Err(TlsError::ParseError {
                        message: "Data too short for extension header".to_string(),
                    });
                }

                let extension_type = Self::read_u16_at(data, cursor, "Extension type")?;
                cursor += 2;

                let extension_len = Self::read_u16_at(data, cursor, "Extension length")? as usize;
                cursor += 2;

                if cursor + extension_len > extensions_end {
                    return Err(TlsError::ParseError {
                        message: "Data too short for extension data".to_string(),
                    });
                }

                let extension_data =
                    Self::slice_range(data, cursor, extension_len, "Extension data")?.to_vec();
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
        let Ok(list_len) = Self::read_u16_at(data, 0, "Supported groups length") else {
            return vec![];
        };
        let list_len = list_len as usize;

        let Some(list_end) = 2usize.checked_add(list_len) else {
            return vec![];
        };
        data.get(2..list_end)
            .map(|groups| {
                groups
                    .chunks_exact(2)
                    .filter_map(|chunk| <[u8; 2]>::try_from(chunk).ok())
                    .map(u16::from_be_bytes)
                    .collect()
            })
            .unwrap_or_default()
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

        let list_len = data.first().copied().unwrap_or_default() as usize;
        let Some(list_end) = 1usize.checked_add(list_len) else {
            return vec![];
        };
        data.get(1..list_end).unwrap_or_default().to_vec()
    }

    /// Convert ClientHello to bytes (for storage/transmission)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // TLS Record Header — always use TLS 1.0 (0x0301) for record layer compatibility
        bytes.push(CONTENT_TYPE_HANDSHAKE);
        bytes.extend_from_slice(&0x0301u16.to_be_bytes());

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
        bytes.push(Self::u8_len(self.session_id.len(), "Session ID")?);
        bytes.extend_from_slice(&self.session_id);

        // Cipher Suites
        let cipher_suites_len = self
            .cipher_suites
            .len()
            .checked_mul(2)
            .and_then(|len| Self::u16_len(len, "Cipher suites").ok())
            .ok_or_else(|| TlsError::ParseError {
                message: "Cipher suites length is too large".to_string(),
            })?;
        bytes.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for cipher in &self.cipher_suites {
            bytes.extend_from_slice(&cipher.to_be_bytes());
        }

        // Compression Methods
        bytes.push(Self::u8_len(
            self.compression_methods.len(),
            "Compression methods",
        )?);
        bytes.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let mut extensions_bytes = Vec::new();

            for ext in &self.extensions {
                extensions_bytes.extend_from_slice(&ext.extension_type.to_be_bytes());
                let ext_data_len = Self::u16_len(ext.data.len(), "Extension data")?;
                extensions_bytes.extend_from_slice(&ext_data_len.to_be_bytes());
                extensions_bytes.extend_from_slice(&ext.data);
            }

            let extensions_len = Self::u16_len(extensions_bytes.len(), "Extensions")?;
            bytes.extend_from_slice(&extensions_len.to_be_bytes());
            bytes.extend_from_slice(&extensions_bytes);
        }

        // Update handshake length
        let handshake_len = Self::u24_len(bytes.len() - handshake_len_pos - 3, "Handshake")?;
        if let Some(len_bytes) = bytes.get_mut(handshake_len_pos..handshake_len_pos + 3) {
            len_bytes.copy_from_slice(&handshake_len);
        }

        // Update record length
        let record_len = Self::u16_len(bytes.len() - record_len_pos - 2, "TLS record")?;
        if let Some(len_bytes) = bytes.get_mut(record_len_pos..record_len_pos + 2) {
            len_bytes.copy_from_slice(&record_len.to_be_bytes());
        }

        Ok(bytes)
    }

    /// Get SNI (Server Name Indication) from extensions
    pub fn get_sni(&self) -> Result<Option<String>> {
        for ext in &self.extensions {
            if ext.extension_type == EXTENSION_SERVER_NAME {
                return Self::parse_sni(&ext.data);
            }
        }
        Ok(None)
    }

    /// Parse SNI extension data
    fn parse_sni(data: &[u8]) -> Result<Option<String>> {
        if data.len() < 5 {
            return Err(TlsError::ParseError {
                message: "SNI extension too short".to_string(),
            });
        }

        // Skip server name list length (2 bytes)
        let mut cursor = 2;

        // Server name type (1 byte, should be 0 for hostname)
        let name_type = Self::read_u8_at(data, cursor, "SNI name type")?;
        if name_type != 0 {
            return Err(TlsError::ParseError {
                message: format!("Invalid SNI name type: {}", name_type),
            });
        }
        cursor += 1;

        // Server name length (2 bytes)
        let name_len = Self::read_u16_at(data, cursor, "SNI name length")? as usize;
        cursor += 2;

        if data.len() < cursor + name_len {
            return Err(TlsError::ParseError {
                message: "SNI name length exceeds extension data".to_string(),
            });
        }

        // Server name
        let name_bytes = Self::slice_range(data, cursor, name_len, "SNI name")?;
        let sni = String::from_utf8(name_bytes.to_vec()).map_err(|error| TlsError::ParseError {
            message: format!("Invalid SNI UTF-8: {}", error),
        })?;
        Ok(Some(sni))
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
    fn test_parse_rejects_malformed_extension_length() {
        let capture = ClientHelloCapture::synthetic(0x0303, vec![0x1301], vec![(0x0000, vec![])]);
        let mut bytes = capture.to_bytes().expect("ClientHello should serialize");

        let ext_len_pos = bytes.len() - 2;
        bytes[ext_len_pos] = 0x00;
        bytes[ext_len_pos + 1] = 0x01;

        let err = ClientHelloCapture::parse(&bytes).expect_err("malformed extension should fail");
        assert!(
            err.to_string()
                .contains("Data too short for extension data")
        );
    }

    #[test]
    fn test_parse_rejects_body_after_handshake_end() {
        let capture = ClientHelloCapture::synthetic(0x0303, vec![0x1301], vec![]);
        let mut bytes = capture.to_bytes().expect("ClientHello should serialize");
        bytes[6..9].copy_from_slice(&[0x00, 0x00, 0x00]);

        let err =
            ClientHelloCapture::parse(&bytes).expect_err("truncated handshake body must fail");
        assert!(
            err.to_string()
                .contains("Data too short for ClientHello version")
        );
    }

    #[test]
    fn test_parse_ignores_extensions_after_handshake_end() {
        let capture = ClientHelloCapture::synthetic(0x0303, vec![0x1301], vec![(0x0000, vec![])]);
        let mut bytes = capture.to_bytes().expect("ClientHello should serialize");
        bytes[6..9].copy_from_slice(&[0x00, 0x00, 0x29]);

        let parsed = ClientHelloCapture::parse(&bytes).expect("ClientHello body should parse");
        assert!(parsed.extensions.is_empty());
    }

    #[test]
    fn test_get_sni_rejects_invalid_utf8() {
        let capture = ClientHelloCapture::synthetic(
            0x0303,
            vec![0x1301],
            vec![(
                EXTENSION_SERVER_NAME,
                vec![0x00, 0x04, 0x00, 0x00, 0x01, 0xff],
            )],
        );

        let err = capture.get_sni().unwrap_err();
        assert!(err.to_string().contains("Invalid SNI UTF-8"));
    }

    #[test]
    fn test_get_sni_rejects_invalid_name_type() {
        let capture = ClientHelloCapture::synthetic(
            0x0303,
            vec![0x1301],
            vec![(
                EXTENSION_SERVER_NAME,
                vec![0x00, 0x04, 0x01, 0x00, 0x01, b'a'],
            )],
        );

        let err = capture.get_sni().expect_err("invalid SNI type should fail");
        assert!(err.to_string().contains("Invalid SNI name type"));
    }

    #[test]
    fn test_round_trip_serialization() {
        let client_hello = ClientHelloCapture::synthetic(
            0x0303,
            vec![0xc02f, 0xc030],
            vec![(10, vec![0, 2, 0, 23])],
        );

        let bytes = client_hello
            .to_bytes()
            .expect("ClientHello should serialize");
        assert!(!bytes.is_empty());

        // Should be able to parse back
        let parsed = ClientHelloCapture::parse(&bytes);
        assert!(parsed.is_ok());

        let parsed = parsed.expect("test assertion should succeed");
        assert_eq!(parsed.version, client_hello.version);
        assert_eq!(parsed.cipher_suites, client_hello.cipher_suites);
    }
}
