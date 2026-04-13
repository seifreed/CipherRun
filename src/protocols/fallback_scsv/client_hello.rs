use super::FallbackScsvTester;
use crate::constants::{COMPRESSION_NULL, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};

impl FallbackScsvTester<'_> {
    pub(super) fn build_client_hello_with_scsv(&self, version: u16, include_scsv: bool) -> Vec<u8> {
        let mut hello = Vec::new();

        hello.push(CONTENT_TYPE_HANDSHAKE);
        hello.push(((version >> 8) & 0xff) as u8);
        hello.push((version & 0xff) as u8);

        let len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        hello.push(HANDSHAKE_TYPE_CLIENT_HELLO);

        let hs_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        hello.push(((version >> 8) & 0xff) as u8);
        hello.push((version & 0xff) as u8);

        for i in 0..32 {
            hello.push((i * 11) as u8);
        }

        hello.push(0x00);

        let cipher_count = if include_scsv { 3 } else { 2 };
        hello.push(0x00);
        hello.push(cipher_count * 2);
        hello.extend_from_slice(&[0xc0, 0x2f, 0x00, 0x9c]);

        if include_scsv {
            hello.extend_from_slice(&[0x56, 0x00]);
        }

        hello.push(0x01);
        hello.push(COMPRESSION_NULL);

        let ext_start_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        if let Some(hostname) = crate::utils::network::sni_hostname_for_target(
            &self.target.hostname,
            self.sni_hostname.as_deref(),
        ) {
            hello.extend_from_slice(&[0x00, 0x00]);
            let sni_len = hostname.len() + 5;
            hello.push(((sni_len >> 8) & 0xff) as u8);
            hello.push((sni_len & 0xff) as u8);

            let sni_list_len = hostname.len() + 3;
            hello.push(((sni_list_len >> 8) & 0xff) as u8);
            hello.push((sni_list_len & 0xff) as u8);

            hello.push(0x00);
            hello.push(((hostname.len() >> 8) & 0xff) as u8);
            hello.push((hostname.len() & 0xff) as u8);
            hello.extend_from_slice(hostname.as_bytes());
        }

        let ext_len = hello.len() - ext_start_pos - 2;
        hello[ext_start_pos] = ((ext_len >> 8) & 0xff) as u8;
        hello[ext_start_pos + 1] = (ext_len & 0xff) as u8;

        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        let rec_len = hello.len() - len_pos - 2;
        hello[len_pos] = ((rec_len >> 8) & 0xff) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        hello
    }
}
