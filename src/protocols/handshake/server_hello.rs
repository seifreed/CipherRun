use crate::Result;
use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO};
use crate::protocols::{Extension, Protocol};

pub struct ServerHelloParser;

impl ServerHelloParser {
    pub fn parse(data: &[u8]) -> Result<ServerHello> {
        // Minimum ServerHello: 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) = 43 bytes
        if data.len() < 43 {
            crate::tls_bail!("ServerHello too short");
        }

        let mut offset = 0;

        if data[0] != CONTENT_TYPE_HANDSHAKE {
            crate::tls_bail!("Not a handshake record");
        }
        // Compute record boundary from the TLS record header length field
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let record_end = (5 + record_len).min(data.len());
        offset += 5;

        if data[offset] != HANDSHAKE_TYPE_SERVER_HELLO {
            crate::tls_bail!("Not a ServerHello");
        }
        offset += 1;
        offset += 3;

        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Session ID length with bounds check
        if offset >= data.len() {
            crate::tls_bail!("ServerHello truncated before session_id_len");
        }
        let session_id_len = data[offset] as usize;
        offset += 1;

        // Validate session_id_len before using it
        if offset + session_id_len > data.len() {
            crate::tls_bail!("ServerHello session_id extends beyond data");
        }
        let session_id = data[offset..offset + session_id_len].to_vec();
        offset += session_id_len;

        // Cipher suite (2 bytes)
        if offset + 2 > data.len() {
            crate::tls_bail!("ServerHello truncated before cipher_suite");
        }
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Compression method (1 byte)
        if offset >= data.len() {
            crate::tls_bail!("ServerHello truncated before compression");
        }
        let compression = data[offset];
        offset += 1;

        let mut extensions = Vec::new();
        let mut ocsp_stapling_detected = None;
        let mut heartbeat_enabled = None;
        let mut secure_renegotiation = None;

        if offset + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_len).min(record_end).min(data.len());
            while offset < ext_end && offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;

                let ext_data_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;

                if offset + ext_data_len <= ext_end {
                    let ext_data = data[offset..offset + ext_data_len].to_vec();

                    if ext_type == 0x0005 {
                        ocsp_stapling_detected = Some(true);
                    }

                    if ext_type == 0x000f {
                        heartbeat_enabled = Some(true);
                    }

                    if ext_type == 0xff01 {
                        secure_renegotiation = Some(true);
                    }

                    extensions.push(Extension::new(ext_type, ext_data));
                    offset += ext_data_len;
                } else {
                    break; // Extension data overflows — stop parsing
                }
            }
        }

        if !extensions.is_empty() && ocsp_stapling_detected.is_none() {
            ocsp_stapling_detected = Some(false);
        }
        if !extensions.is_empty() && heartbeat_enabled.is_none() {
            heartbeat_enabled = Some(false);
        }
        if !extensions.is_empty() && secure_renegotiation.is_none() {
            secure_renegotiation = Some(false);
        }

        Ok(ServerHello {
            version: Protocol::from(version),
            random,
            session_id,
            cipher_suite,
            compression,
            extensions,
            ocsp_stapling_detected,
            heartbeat_enabled,
            secure_renegotiation,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub version: Protocol,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<Extension>,
    pub ocsp_stapling_detected: Option<bool>,
    pub heartbeat_enabled: Option<bool>,
    pub secure_renegotiation: Option<bool>,
}

impl ServerHello {
    pub fn cipher_hex(&self) -> String {
        format!("{:04x}", self.cipher_suite)
    }

    pub fn has_extension(&self, ext_type: u16) -> bool {
        self.extensions.iter().any(|e| e.extension_type == ext_type)
    }

    pub fn get_extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions
            .iter()
            .find(|e| e.extension_type == ext_type)
    }

    pub fn supports_ocsp_stapling(&self) -> Option<bool> {
        self.ocsp_stapling_detected
    }

    pub fn supports_heartbeat(&self) -> Option<bool> {
        self.heartbeat_enabled
    }

    pub fn supports_secure_renegotiation(&self) -> Option<bool> {
        self.secure_renegotiation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_ocsp_stapling_detected() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x00, 0x01, 0x00]);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.ocsp_stapling_detected, Some(true));
        assert!(parsed.supports_ocsp_stapling().unwrap());
        assert!(parsed.has_extension(0x0005));
    }

    #[test]
    fn test_server_hello_no_ocsp_stapling() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello
            .extend_from_slice(&[0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00]);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.ocsp_stapling_detected, Some(false));
        assert!(!parsed.supports_ocsp_stapling().unwrap());
        assert!(!parsed.has_extension(0x0005));
    }

    #[test]
    fn test_server_hello_no_extensions() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x44, 0x02, 0x00, 0x00, 0x40, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.ocsp_stapling_detected, None);
        assert!(parsed.supports_ocsp_stapling().is_none());
        assert_eq!(parsed.heartbeat_enabled, None);
        assert!(parsed.supports_heartbeat().is_none());
    }

    #[test]
    fn test_server_hello_heartbeat_detected() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0x00, 0x05, 0x00, 0x0f, 0x00, 0x01, 0x01]);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.heartbeat_enabled, Some(true));
        assert!(parsed.supports_heartbeat().unwrap());
        assert!(parsed.has_extension(0x000f));
    }

    #[test]
    fn test_server_hello_no_heartbeat() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello
            .extend_from_slice(&[0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.heartbeat_enabled, Some(false));
        assert!(!parsed.has_extension(0x000f));
    }

    #[test]
    fn test_server_hello_heartbeat_and_ocsp() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4f, 0x02, 0x00, 0x00, 0x4b, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x01, 0x01,
        ]);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.ocsp_stapling_detected, Some(true));
        assert_eq!(parsed.heartbeat_enabled, Some(true));
        assert!(parsed.supports_ocsp_stapling().unwrap());
        assert!(parsed.supports_heartbeat().unwrap());
    }
}
