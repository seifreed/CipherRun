use super::PreHandshakeScanner;
use crate::{Result, TlsError};

impl PreHandshakeScanner {
    pub(super) fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut client_hello = Vec::new();

        client_hello.push(0x16);
        client_hello.push(0x03);
        client_hello.push(0x01);

        let record_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]);

        client_hello.push(0x01);

        let handshake_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        client_hello.push(0x03);
        client_hello.push(0x03);

        let random = self.generate_client_random();
        client_hello.extend_from_slice(&random);

        client_hello.push(0x00);

        let cipher_suites = self.get_cipher_suites();
        let cipher_suites_len = Self::u16_byte_len(cipher_suites.len(), "cipher suites")?;
        client_hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for cipher in cipher_suites {
            client_hello.extend_from_slice(&cipher.to_be_bytes());
        }

        client_hello.push(0x01);
        client_hello.push(0x00);

        let extensions = self.build_extensions()?;
        let extensions_len = Self::u16_len(extensions.len(), "extensions")?;
        client_hello.extend_from_slice(&extensions_len.to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        let handshake_body_len = client_hello.len() - handshake_length_pos - 3;
        if let Some(len_bytes) =
            client_hello.get_mut(handshake_length_pos..handshake_length_pos + 3)
        {
            len_bytes.copy_from_slice(&Self::u24_len(handshake_body_len, "handshake")?);
        }

        let record_body_len = client_hello.len() - record_length_pos - 2;
        if let Some(len_bytes) = client_hello.get_mut(record_length_pos..record_length_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(record_body_len, "record")?.to_be_bytes());
        }

        Ok(client_hello)
    }

    fn generate_client_random(&self) -> [u8; 32] {
        use rand::Rng;
        let mut random = [0u8; 32];
        rand::rng().fill_bytes(&mut random);
        random
    }

    fn get_cipher_suites(&self) -> Vec<u16> {
        vec![
            0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xcca8, 0xc02b, 0xc02c, 0xcca9, 0x009c, 0x009d,
            0x002f, 0x0035,
        ]
    }

    fn build_extensions(&self) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();
        let sni_ext = self.build_sni_extension()?;
        extensions.extend_from_slice(&sni_ext);

        extensions.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
            0x01, 0x00,
        ]);

        extensions.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
            0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        ]);

        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
        extensions.extend_from_slice(&[
            0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01,
        ]);

        Ok(extensions)
    }

    pub(super) fn build_sni_extension(&self) -> Result<Vec<u8>> {
        let hostname = self.target.hostname.as_bytes();
        let hostname_len = Self::u16_len(hostname.len(), "SNI hostname")?;
        let list_len = hostname_len
            .checked_add(3)
            .ok_or_else(|| TlsError::Other("SNI hostname exceeds maximum length".to_string()))?;
        let ext_len = list_len
            .checked_add(2)
            .ok_or_else(|| TlsError::Other("SNI extension exceeds maximum length".to_string()))?;

        let mut sni = Vec::new();
        sni.extend_from_slice(&[0x00, 0x00]);
        sni.extend_from_slice(&ext_len.to_be_bytes());
        sni.extend_from_slice(&list_len.to_be_bytes());
        sni.push(0x00);
        sni.extend_from_slice(&hostname_len.to_be_bytes());
        sni.extend_from_slice(hostname);

        Ok(sni)
    }

    fn u16_len(len: usize, context: &str) -> Result<u16> {
        u16::try_from(len).map_err(|_| TlsError::Other(format!("{context} exceeds maximum length")))
    }

    fn u16_byte_len(items: usize, context: &str) -> Result<u16> {
        let bytes = items
            .checked_mul(2)
            .ok_or_else(|| TlsError::Other(format!("{context} exceeds maximum length")))?;
        Self::u16_len(bytes, context)
    }

    fn u24_len(len: usize, context: &str) -> Result<[u8; 3]> {
        let len = u32::try_from(len)
            .map_err(|_| TlsError::Other(format!("{context} exceeds maximum length")))?;
        if len > 0x00ff_ffff {
            return Err(TlsError::Other(format!("{context} exceeds maximum length")));
        }
        let bytes = len.to_be_bytes();
        Ok([bytes[1], bytes[2], bytes[3]])
    }
}
