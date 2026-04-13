use super::IntoleranceTester;
use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, EXTENSION_EC_POINT_FORMATS, EXTENSION_SERVER_NAME,
    EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_GROUPS, HANDSHAKE_TYPE_CLIENT_HELLO,
    VERSION_TLS_1_0, VERSION_TLS_1_2,
};
use bytes::{BufMut, BytesMut};

impl IntoleranceTester {
    pub(super) fn build_minimal_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d]);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_extended_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d]);

        let mut extensions = BytesMut::new();
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            self.add_sni_extension(&mut extensions, &hostname);
        }
        self.add_supported_groups_extension(&mut extensions);
        self.add_ec_point_formats_extension(&mut extensions);
        self.add_signature_algorithms_extension(&mut extensions);

        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_versioned_client_hello(&self, record_version: u16) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(record_version);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030]);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_long_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030, 0x009c, 0x009d]);

        let mut extensions = BytesMut::new();
        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            self.add_sni_extension(&mut extensions, &hostname);
        }

        let current_size = buf.len() + 2 + extensions.len();
        let padding_needed = if current_size < 300 {
            300 - current_size
        } else {
            100
        };

        extensions.put_u16(0x0015);
        extensions.put_u16(padding_needed as u16);
        extensions.put_slice(&vec![0u8; padding_needed]);

        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);
        self.finalize_client_hello(buf)
    }

    pub(super) fn build_invalid_sni_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = self.begin_client_hello(VERSION_TLS_1_0);
        self.write_randomized_hello_prefix(&mut buf, vec![0xc02f, 0xc030]);

        let mut extensions = BytesMut::new();
        self.add_sni_extension(&mut extensions, "invalid.nonexistent.example.com");

        buf.put_u16(extensions.len() as u16);
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

    fn write_randomized_hello_prefix(&self, buf: &mut BytesMut, ciphers: Vec<u16>) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);
        buf.put_u8(0);

        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        buf.put_u8(1);
        buf.put_u8(0);
    }

    fn finalize_client_hello(&self, buf: BytesMut) -> Result<Vec<u8>> {
        let mut result = buf.to_vec();
        let length_pos = 3;
        let hs_length_pos = 6;

        let total_length = result.len() - length_pos - 2;
        let hs_length = result.len() - hs_length_pos - 3;

        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    pub(super) fn add_sni_extension(&self, buf: &mut BytesMut, hostname: &str) {
        buf.put_u16(EXTENSION_SERVER_NAME);

        let ext_data_len = 2 + 1 + 2 + hostname.len();
        buf.put_u16(ext_data_len as u16);

        let list_len = 1 + 2 + hostname.len();
        buf.put_u16(list_len as u16);
        buf.put_u8(0);
        buf.put_u16(hostname.len() as u16);
        buf.put_slice(hostname.as_bytes());
    }

    pub(super) fn add_supported_groups_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(EXTENSION_SUPPORTED_GROUPS);
        let curves = vec![0x0017, 0x0018, 0x0019];
        buf.put_u16((2 + curves.len() * 2) as u16);
        buf.put_u16((curves.len() * 2) as u16);
        for curve in curves {
            buf.put_u16(curve);
        }
    }

    pub(super) fn add_ec_point_formats_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(EXTENSION_EC_POINT_FORMATS);
        buf.put_u16(2);
        buf.put_u8(1);
        buf.put_u8(0);
    }

    pub(super) fn add_signature_algorithms_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(EXTENSION_SIGNATURE_ALGORITHMS);
        let algorithms = vec![
            (0x04, 0x01),
            (0x05, 0x01),
            (0x06, 0x01),
            (0x04, 0x03),
            (0x05, 0x03),
        ];

        buf.put_u16((2 + algorithms.len() * 2) as u16);
        buf.put_u16((algorithms.len() * 2) as u16);
        for (hash, sig) in algorithms {
            buf.put_u8(hash);
            buf.put_u8(sig);
        }
    }
}
