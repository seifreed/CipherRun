use super::IntoleranceTester;
use crate::Result;
use crate::TlsError;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, EXTENSION_EC_POINT_FORMATS, EXTENSION_SERVER_NAME,
    EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_GROUPS, HANDSHAKE_TYPE_CLIENT_HELLO,
    VERSION_TLS_1_0, VERSION_TLS_1_2,
};
use bytes::{BufMut, BytesMut};

impl IntoleranceTester {
    pub(super) fn build_minimal_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d])?;
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_extended_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d])?;

        let mut extensions = BytesMut::new();
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            self.add_sni_extension(&mut extensions, &hostname)?;
        }
        self.add_supported_groups_extension(&mut extensions)?;
        self.add_ec_point_formats_extension(&mut extensions);
        self.add_signature_algorithms_extension(&mut extensions)?;

        buf.put_u16(Self::u16_len(extensions.len(), "extensions")?);
        buf.put_slice(&extensions);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_versioned_client_hello(&self, record_version: u16) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(record_version);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030])?;
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_long_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d])?;

        let mut extensions = BytesMut::new();
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            self.add_sni_extension(&mut extensions, &hostname)?;
        }

        let current_size = buf.len() + 2 + extensions.len();
        let padding_needed = if current_size < 300 {
            300 - current_size
        } else {
            100
        };

        extensions.put_u16(0x0015);
        extensions.put_u16(Self::u16_len(padding_needed, "padding extension")?);
        extensions.put_slice(&vec![0u8; padding_needed]);

        buf.put_u16(Self::u16_len(extensions.len(), "extensions")?);
        buf.put_slice(&extensions);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_invalid_sni_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030])?;

        let mut extensions = BytesMut::new();
        self.add_sni_extension(&mut extensions, "invalid.nonexistent.example.com")?;

        buf.put_u16(Self::u16_len(extensions.len(), "extensions")?);
        buf.put_slice(&extensions);
        self.finalize_client_hello(buf)
    }

    fn begin_client_hello(&self, record_version: u16) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(CONTENT_TYPE_HANDSHAKE);
        buf.put_u16(record_version);
        buf.put_u16(0);
        buf.put_u8(HANDSHAKE_TYPE_CLIENT_HELLO);
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_u16(VERSION_TLS_1_2);
        buf
    }

    fn write_randomized_hello_prefix(&self, buf: &mut BytesMut, ciphers: Vec<u16>) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        let timestamp = u32::try_from(timestamp).unwrap_or(u32::MAX);
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);
        buf.put_u8(0);

        buf.put_u16(Self::u16_byte_len(ciphers.len(), "cipher suites")?);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        buf.put_u8(1);
        buf.put_u8(0);
        Ok(())
    }

    fn finalize_client_hello(&self, buf: BytesMut) -> Result<Vec<u8>> {
        let mut result = buf.to_vec();
        let length_pos = 3;
        let hs_length_pos = 6;

        let total_length = result.len() - length_pos - 2;
        let hs_length = result.len() - hs_length_pos - 3;

        if let Some(len_bytes) = result.get_mut(length_pos..length_pos + 2) {
            len_bytes.copy_from_slice(&Self::u16_len(total_length, "TLS record")?.to_be_bytes());
        }

        if let Some(len_bytes) = result.get_mut(hs_length_pos..hs_length_pos + 3) {
            len_bytes.copy_from_slice(&Self::u24_len(hs_length, "handshake")?);
        }

        Ok(result)
    }

    pub(super) fn add_sni_extension(&self, buf: &mut BytesMut, hostname: &str) -> Result<()> {
        buf.put_u16(EXTENSION_SERVER_NAME);

        let hostname_len = Self::u16_len(hostname.len(), "SNI hostname")?;
        let list_len = hostname_len
            .checked_add(3)
            .ok_or_else(|| TlsError::Other("SNI hostname exceeds maximum length".to_string()))?;
        let ext_data_len = list_len
            .checked_add(2)
            .ok_or_else(|| TlsError::Other("SNI extension exceeds maximum length".to_string()))?;
        buf.put_u16(ext_data_len);

        buf.put_u16(list_len);
        buf.put_u8(0);
        buf.put_u16(hostname_len);
        buf.put_slice(hostname.as_bytes());
        Ok(())
    }

    pub(super) fn add_supported_groups_extension(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16(EXTENSION_SUPPORTED_GROUPS);
        let curves = vec![0x0017, 0x0018, 0x0019];
        let curves_len = Self::u16_byte_len(curves.len(), "supported groups")?;
        buf.put_u16(curves_len.checked_add(2).ok_or_else(|| {
            TlsError::Other("supported groups extension exceeds maximum length".to_string())
        })?);
        buf.put_u16(curves_len);
        for curve in curves {
            buf.put_u16(curve);
        }
        Ok(())
    }

    pub(super) fn add_ec_point_formats_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(EXTENSION_EC_POINT_FORMATS);
        buf.put_u16(2);
        buf.put_u8(1);
        buf.put_u8(0);
    }

    pub(super) fn add_signature_algorithms_extension(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16(EXTENSION_SIGNATURE_ALGORITHMS);
        let algorithms = vec![
            (0x04, 0x01),
            (0x05, 0x01),
            (0x06, 0x01),
            (0x04, 0x03),
            (0x05, 0x03),
        ];

        let algorithms_len = Self::u16_byte_len(algorithms.len(), "signature algorithms")?;
        buf.put_u16(algorithms_len.checked_add(2).ok_or_else(|| {
            TlsError::Other("signature algorithms extension exceeds maximum length".to_string())
        })?);
        buf.put_u16(algorithms_len);
        for (hash, sig) in algorithms {
            buf.put_u8(hash);
            buf.put_u8(sig);
        }
        Ok(())
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
