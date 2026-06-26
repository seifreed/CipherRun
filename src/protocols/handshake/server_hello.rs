use crate::Result;
use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO};
use crate::protocols::{Extension, Protocol};

pub struct ServerHelloParser;

impl ServerHelloParser {
    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let bytes = data
            .get(offset..offset + 2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        data.get(start..end)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    pub fn parse(data: &[u8]) -> Result<ServerHello> {
        // Minimum ServerHello: 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) = 43 bytes
        if data.len() < 43 {
            crate::tls_bail!("ServerHello too short");
        }

        let mut offset = 0;

        if Self::read_u8_at(data, 0, "TLS record type")? != CONTENT_TYPE_HANDSHAKE {
            crate::tls_bail!("Not a handshake record");
        }
        // Compute record boundary from the TLS record header length field
        let record_len = Self::read_u16_at(data, 3, "TLS record length")? as usize;
        let record_end = 5 + record_len;
        if record_end > data.len() {
            crate::tls_bail!("ServerHello record length exceeds available data");
        }
        let record = Self::slice_range(data, 0, record_end, "TLS record")?;
        offset += 5;

        if Self::read_u8_at(record, offset, "Handshake message type")?
            != HANDSHAKE_TYPE_SERVER_HELLO
        {
            crate::tls_bail!("Not a ServerHello");
        }
        offset += 1;
        offset += 3;

        let version = Self::read_u16_at(record, offset, "ServerHello version")?;
        offset += 2;

        let mut random = [0u8; 32];
        random.copy_from_slice(Self::slice_range(record, offset, 32, "ServerHello random")?);
        offset += 32;

        // Session ID length with bounds check
        if offset >= record.len() {
            crate::tls_bail!("ServerHello truncated before session_id_len");
        }
        let session_id_len =
            Self::read_u8_at(record, offset, "ServerHello session ID length")? as usize;
        offset += 1;

        // Validate session_id_len before using it
        if offset + session_id_len > record.len() {
            crate::tls_bail!("ServerHello session_id extends beyond data");
        }
        let session_id =
            Self::slice_range(record, offset, session_id_len, "ServerHello session ID")?.to_vec();
        offset += session_id_len;

        // Cipher suite (2 bytes)
        if offset + 2 > record.len() {
            crate::tls_bail!("ServerHello truncated before cipher_suite");
        }
        let cipher_suite = Self::read_u16_at(record, offset, "ServerHello cipher suite")?;
        offset += 2;

        // Compression method (1 byte)
        if offset >= record.len() {
            crate::tls_bail!("ServerHello truncated before compression");
        }
        let compression = Self::read_u8_at(record, offset, "ServerHello compression")?;
        offset += 1;

        let mut extensions = Vec::new();
        let mut ocsp_stapling_detected = None;
        let mut heartbeat_enabled = None;
        let mut secure_renegotiation = None;
        // For TLS 1.3 the negotiated version lives in the supported_versions
        // extension (0x002b); the legacy `version` field above is pinned to
        // 0x0303 (TLS 1.2). Track the real negotiated version here.
        let mut negotiated_version = None;

        if offset + 2 <= record.len() {
            let ext_len =
                Self::read_u16_at(record, offset, "ServerHello extensions length")? as usize;
            offset += 2;

            let ext_end =
                offset
                    .checked_add(ext_len)
                    .ok_or_else(|| crate::TlsError::ParseError {
                        message: "ServerHello extensions length overflow".to_string(),
                    })?;
            if ext_end > record.len() {
                crate::tls_bail!("ServerHello extension block extends beyond declared length");
            }
            while offset < ext_end && offset + 4 <= ext_end {
                let ext_type = Self::read_u16_at(record, offset, "ServerHello extension type")?;
                offset += 2;

                let ext_data_len =
                    Self::read_u16_at(record, offset, "ServerHello extension length")? as usize;
                offset += 2;

                let ext_data_end = offset.checked_add(ext_data_len).ok_or_else(|| {
                    crate::TlsError::ParseError {
                        message: "ServerHello extension length overflow".to_string(),
                    }
                })?;

                if ext_data_end <= ext_end {
                    let ext_data =
                        Self::slice_range(record, offset, ext_data_len, "ServerHello extension")?
                            .to_vec();

                    if ext_type == 0x0005 {
                        ocsp_stapling_detected = Some(true);
                    }

                    if ext_type == 0x000f {
                        heartbeat_enabled = Some(true);
                    }

                    if ext_type == 0xff01 {
                        secure_renegotiation = Some(true);
                    }

                    // supported_versions in a ServerHello carries exactly one
                    // 2-byte selected version (RFC 8446 §4.2.1).
                    if ext_type == 0x002b && ext_data.len() >= 2 {
                        negotiated_version =
                            Some(Self::read_u16_at(&ext_data, 0, "supported_versions")?);
                    }

                    extensions.push(Extension::new(ext_type, ext_data));
                    offset = ext_data_end;
                } else {
                    crate::tls_bail!("ServerHello extension data extends beyond declared length");
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
            version: Protocol::from(negotiated_version.unwrap_or(version)),
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

    fn patch_lengths(server_hello: &mut [u8]) {
        let record_len = (server_hello.len() - 5) as u16;
        server_hello[3] = (record_len >> 8) as u8;
        server_hello[4] = (record_len & 0xff) as u8;
        let hs_len = (server_hello.len() - 9) as u32;
        server_hello[6] = ((hs_len >> 16) & 0xff) as u8;
        server_hello[7] = ((hs_len >> 8) & 0xff) as u8;
        server_hello[8] = (hs_len & 0xff) as u8;
    }

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
        patch_lengths(&mut server_hello);

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
        patch_lengths(&mut server_hello);

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
        patch_lengths(&mut server_hello);

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
        patch_lengths(&mut server_hello);

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
        patch_lengths(&mut server_hello);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.heartbeat_enabled, Some(false));
        assert!(!parsed.has_extension(0x000f));
    }

    #[test]
    fn test_server_hello_tls13_version_from_supported_versions_extension() {
        // Legacy version field is 0x0303 (TLS 1.2), but supported_versions
        // (0x002b) selects 0x0304 (TLS 1.3). The parsed version must be TLS 1.3.
        // record_len 0x0032 (50), handshake_len 0x00002e (46), legacy version 0x0303
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x32, 0x02, 0x00, 0x00, 0x2e, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00); // session_id length
        server_hello.extend_from_slice(&[0x13, 0x01]); // cipher suite
        server_hello.push(0x00); // compression
        // extensions: length 6, supported_versions (0x002b) body 0x0304
        server_hello.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        patch_lengths(&mut server_hello);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.version, Protocol::TLS13);
        assert!(parsed.has_extension(0x002b));
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
        patch_lengths(&mut server_hello);

        let parsed =
            ServerHelloParser::parse(&server_hello).expect("test assertion should succeed");
        assert_eq!(parsed.ocsp_stapling_detected, Some(true));
        assert_eq!(parsed.heartbeat_enabled, Some(true));
        assert!(parsed.supports_ocsp_stapling().unwrap());
        assert!(parsed.supports_heartbeat().unwrap());
    }

    #[test]
    fn test_server_hello_rejects_truncated_extension_data() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x4A, 0x02, 0x00, 0x00, 0x46, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0x00, 0x04, 0x00, 0x05, 0x00, 0x02, 0x01]);
        patch_lengths(&mut server_hello);

        let err = ServerHelloParser::parse(&server_hello).unwrap_err();
        assert!(format!("{err}").contains("extension data extends beyond declared length"));
    }

    #[test]
    fn test_server_hello_rejects_truncated_extension_block() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0x00, 0x06, 0x00, 0x0f, 0x00, 0x01]); // claims 6 bytes, only 4 follow

        let rec_len = (server_hello.len() - 5) as u16;
        server_hello[3] = (rec_len >> 8) as u8;
        server_hello[4] = (rec_len & 0xff) as u8;
        let hs_len = (server_hello.len() - 9) as u32;
        server_hello[6] = ((hs_len >> 16) & 0xff) as u8;
        server_hello[7] = ((hs_len >> 8) & 0xff) as u8;
        server_hello[8] = (hs_len & 0xff) as u8;

        let err = ServerHelloParser::parse(&server_hello).unwrap_err();
        assert!(format!("{err}").contains("extension block extends beyond declared length"));
    }

    #[test]
    fn test_server_hello_rejects_inflated_record_length() {
        let mut server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x40, 0x02, 0x00, 0x00, 0x3c, 0x03, 0x03,
        ];
        server_hello.extend_from_slice(&[0u8; 32]);
        server_hello.push(0x00);
        server_hello.extend_from_slice(&[0xc0, 0x2f]);
        server_hello.push(0x00);

        let err = ServerHelloParser::parse(&server_hello).unwrap_err();
        assert!(format!("{err}").contains("record length exceeds available data"));
    }
}
