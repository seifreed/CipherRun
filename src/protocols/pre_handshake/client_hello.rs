use super::PreHandshakeScanner;
use crate::Result;

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
        let cipher_suites_len = (cipher_suites.len() * 2) as u16;
        client_hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for cipher in cipher_suites {
            client_hello.extend_from_slice(&cipher.to_be_bytes());
        }

        client_hello.push(0x01);
        client_hello.push(0x00);

        let extensions = self.build_extensions()?;
        let extensions_len = extensions.len() as u16;
        client_hello.extend_from_slice(&extensions_len.to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        let handshake_body_len = client_hello.len() - handshake_length_pos - 3;
        client_hello[handshake_length_pos] = ((handshake_body_len >> 16) & 0xFF) as u8;
        client_hello[handshake_length_pos + 1] = ((handshake_body_len >> 8) & 0xFF) as u8;
        client_hello[handshake_length_pos + 2] = (handshake_body_len & 0xFF) as u8;

        let record_body_len = client_hello.len() - record_length_pos - 2;
        client_hello[record_length_pos] = ((record_body_len >> 8) & 0xFF) as u8;
        client_hello[record_length_pos + 1] = (record_body_len & 0xFF) as u8;

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
        let sni_ext = self.build_sni_extension();
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

    pub(super) fn build_sni_extension(&self) -> Vec<u8> {
        let hostname = self.target.hostname.as_bytes();
        let hostname_len = hostname.len() as u16;
        let list_len = hostname_len + 3;
        let ext_len = list_len + 2;

        let mut sni = Vec::new();
        sni.extend_from_slice(&[0x00, 0x00]);
        sni.extend_from_slice(&ext_len.to_be_bytes());
        sni.extend_from_slice(&list_len.to_be_bytes());
        sni.push(0x00);
        sni.extend_from_slice(&hostname_len.to_be_bytes());
        sni.extend_from_slice(hostname);

        sni
    }
}
