use super::ClientHelloBuilder;
use crate::Result;
use crate::constants::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO, VERSION_SSL_3_0, VERSION_TLS_1_0,
    VERSION_TLS_1_2,
};
use crate::protocols::Protocol;
use bytes::{BufMut, BytesMut};

impl ClientHelloBuilder {
    pub fn build_minimal(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        self.begin_handshake_record(&mut buf);
        let (length_pos, handshake_start, handshake_length_pos, hello_start) =
            Self::handshake_offsets(&mut buf);

        self.write_client_hello_body(&mut buf);
        self.fill_lengths(
            &mut buf,
            length_pos,
            handshake_start,
            handshake_length_pos,
            hello_start,
        );

        Ok(buf.to_vec())
    }

    pub fn build(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        self.begin_handshake_record(&mut buf);
        let (length_pos, handshake_start, handshake_length_pos, hello_start) =
            Self::handshake_offsets(&mut buf);

        self.write_client_hello_body(&mut buf);
        self.write_extensions(&mut buf);
        self.fill_lengths(
            &mut buf,
            length_pos,
            handshake_start,
            handshake_length_pos,
            hello_start,
        );

        Ok(buf.to_vec())
    }

    fn begin_handshake_record(&self, buf: &mut BytesMut) {
        buf.put_u8(CONTENT_TYPE_HANDSHAKE);
        buf.put_u16(match self.protocol {
            Protocol::SSLv3 => VERSION_SSL_3_0,
            _ => VERSION_TLS_1_0,
        });
    }

    fn handshake_offsets(buf: &mut BytesMut) -> (usize, usize, usize, usize) {
        let length_pos = buf.len();
        buf.put_u16(0);

        let handshake_start = buf.len();
        buf.put_u8(HANDSHAKE_TYPE_CLIENT_HELLO);

        let handshake_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        let hello_start = buf.len();
        (length_pos, handshake_start, handshake_length_pos, hello_start)
    }

    fn write_client_hello_body(&self, buf: &mut BytesMut) {
        let client_version = if matches!(self.protocol, Protocol::TLS13) {
            VERSION_TLS_1_2
        } else {
            self.protocol.as_hex()
        };
        buf.put_u16(client_version);
        buf.put_slice(&self.random);
        buf.put_u8(self.session_id.len() as u8);
        if !self.session_id.is_empty() {
            buf.put_slice(&self.session_id);
        }

        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for cipher in &self.cipher_suites {
            buf.put_u16(*cipher);
        }

        buf.put_u8(self.compression_methods.len() as u8);
        buf.put_slice(&self.compression_methods);
    }

    fn write_extensions(&self, buf: &mut BytesMut) {
        if self.extensions.is_empty() {
            return;
        }

        let extensions_start = buf.len();
        buf.put_u16(0);
        for ext in &self.extensions {
            buf.put_u16(ext.extension_type);
            buf.put_u16(ext.data.len() as u16);
            buf.put_slice(&ext.data);
        }

        let extensions_len = buf.len() - extensions_start - 2;
        buf[extensions_start..extensions_start + 2]
            .copy_from_slice(&(extensions_len as u16).to_be_bytes());
    }

    fn fill_lengths(
        &self,
        buf: &mut BytesMut,
        length_pos: usize,
        handshake_start: usize,
        handshake_length_pos: usize,
        hello_start: usize,
    ) {
        let handshake_len = buf.len() - hello_start;
        buf[handshake_length_pos] = ((handshake_len >> 16) & 0xff) as u8;
        buf[handshake_length_pos + 1..handshake_length_pos + 3]
            .copy_from_slice(&((handshake_len & 0xffff) as u16).to_be_bytes());

        let record_len = buf.len() - handshake_start;
        buf[length_pos..length_pos + 2].copy_from_slice(&(record_len as u16).to_be_bytes());
    }
}
