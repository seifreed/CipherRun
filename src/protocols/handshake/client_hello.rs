#[path = "client_hello/defaults.rs"]
mod defaults;
#[path = "client_hello/encoding.rs"]
mod encoding;

use crate::constants::{
    COMPRESSION_DEFLATE, COMPRESSION_NULL, EXTENSION_ALPN,
    EXTENSION_EC_POINT_FORMATS, EXTENSION_ENCRYPT_THEN_MAC, EXTENSION_EXTENDED_MASTER_SECRET,
    EXTENSION_KEY_SHARE, EXTENSION_RENEGOTIATION_INFO, EXTENSION_SERVER_NAME,
    EXTENSION_SESSION_TICKET, EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_GROUPS,
    EXTENSION_SUPPORTED_VERSIONS,
};
use crate::protocols::{Extension, Protocol};
use bytes::{BufMut, BytesMut};

/// ClientHello message builder
pub struct ClientHelloBuilder {
    pub(super) protocol: Protocol,
    pub(super) cipher_suites: Vec<u16>,
    pub(super) extensions: Vec<Extension>,
    pub(super) session_id: Vec<u8>,
    pub(super) compression_methods: Vec<u8>,
    pub(super) random: [u8; 32],
}

impl ClientHelloBuilder {
    pub fn new(protocol: Protocol) -> Self {
        let mut random = [0u8; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32;
        random[0..4].copy_from_slice(&timestamp.to_be_bytes());
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut random[4..]);

        Self {
            protocol,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            session_id: Vec::new(),
            compression_methods: vec![COMPRESSION_NULL],
            random,
        }
    }

    pub fn add_cipher(&mut self, hexcode: u16) -> &mut Self {
        self.cipher_suites.push(hexcode);
        self
    }

    pub fn add_ciphers(&mut self, hexcodes: &[u16]) -> &mut Self {
        self.cipher_suites.extend_from_slice(hexcodes);
        self
    }

    pub fn add_extension(&mut self, extension: Extension) -> &mut Self {
        self.extensions.push(extension);
        self
    }

    pub fn add_sni(&mut self, hostname: &str) -> &mut Self {
        let mut data = BytesMut::new();
        let list_len = 3 + hostname.len();
        data.put_u16(list_len as u16);
        data.put_u8(0);
        data.put_u16(hostname.len() as u16);
        data.put_slice(hostname.as_bytes());
        self.extensions
            .push(Extension::new(EXTENSION_SERVER_NAME, data.to_vec()));
        self
    }

    pub fn add_supported_groups(&mut self, curves: &[u16]) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u16((curves.len() * 2) as u16);
        for curve in curves {
            data.put_u16(*curve);
        }
        self.extensions
            .push(Extension::new(EXTENSION_SUPPORTED_GROUPS, data.to_vec()));
        self
    }

    pub fn add_signature_algorithms(&mut self, algorithms: &[(u8, u8)]) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u16((algorithms.len() * 2) as u16);
        for (hash, sig) in algorithms {
            data.put_u8(*hash);
            data.put_u8(*sig);
        }
        self.extensions.push(Extension::new(
            EXTENSION_SIGNATURE_ALGORITHMS,
            data.to_vec(),
        ));
        self
    }

    pub fn add_alpn(&mut self, protocols: &[&str]) -> &mut Self {
        let mut data = BytesMut::new();
        let total_len: usize = protocols.iter().map(|p| 1 + p.len()).sum();
        data.put_u16(total_len as u16);
        for protocol in protocols {
            data.put_u8(protocol.len() as u8);
            data.put_slice(protocol.as_bytes());
        }
        self.extensions
            .push(Extension::new(EXTENSION_ALPN, data.to_vec()));
        self
    }

    pub fn add_ec_point_formats(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8(1);
        data.put_u8(0);
        self.extensions
            .push(Extension::new(EXTENSION_EC_POINT_FORMATS, data.to_vec()));
        self
    }

    pub fn add_session_ticket(&mut self) -> &mut Self {
        self.extensions
            .push(Extension::new(EXTENSION_SESSION_TICKET, vec![]));
        self
    }

    pub fn add_encrypt_then_mac(&mut self) -> &mut Self {
        self.extensions
            .push(Extension::new(EXTENSION_ENCRYPT_THEN_MAC, vec![]));
        self
    }

    pub fn add_extended_master_secret(&mut self) -> &mut Self {
        self.extensions
            .push(Extension::new(EXTENSION_EXTENDED_MASTER_SECRET, vec![]));
        self
    }

    pub fn add_renegotiation_info(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8(0);
        self.extensions
            .push(Extension::new(EXTENSION_RENEGOTIATION_INFO, data.to_vec()));
        self
    }

    pub fn add_status_request(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8(1);
        data.put_u16(0);
        data.put_u16(0);
        self.extensions.push(Extension::new(0x0005, data.to_vec()));
        self
    }

    pub fn add_supported_versions(&mut self, versions: &[u16]) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8((versions.len() * 2) as u8);
        for version in versions {
            data.put_u16(*version);
        }
        self.extensions
            .push(Extension::new(EXTENSION_SUPPORTED_VERSIONS, data.to_vec()));
        self
    }

    pub fn add_key_share(&mut self, group: u16) -> &mut Self {
        let mut data = BytesMut::new();
        let public_key = if group == 0x001d {
            use rand::rngs::OsRng;
            use x25519_dalek::{EphemeralSecret, PublicKey};

            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            public.as_bytes().to_vec()
        } else if group == 0x0017 {
            use rand::RngCore;
            let mut key = vec![0u8; 65];
            rand::thread_rng().fill_bytes(&mut key);
            key
        } else {
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };

        let share_len = 4 + public_key.len();
        data.put_u16(share_len as u16);
        data.put_u16(group);
        data.put_u16(public_key.len() as u16);
        data.put_slice(&public_key);
        self.extensions
            .push(Extension::new(EXTENSION_KEY_SHARE, data.to_vec()));
        self
    }

    pub fn add_psk_key_exchange_modes(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8(1);
        data.put_u8(1);
        self.extensions.push(Extension::new(0x002d, data.to_vec()));
        self
    }

    pub fn add_npn(&mut self) -> &mut Self {
        self.extensions.push(Extension::new(0x3374, vec![]));
        self
    }

    pub fn with_compression(&mut self, enable_deflate: bool) -> &mut Self {
        if enable_deflate {
            self.compression_methods = vec![COMPRESSION_DEFLATE, COMPRESSION_NULL];
        } else {
            self.compression_methods = vec![COMPRESSION_NULL];
        }
        self
    }

    pub fn add_signature_algorithms_cert(&mut self, algorithms: &[(u8, u8)]) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u16((algorithms.len() * 2) as u16);
        for (hash, sig) in algorithms {
            data.put_u8(*hash);
            data.put_u8(*sig);
        }
        self.extensions.push(Extension::new(0x0050, data.to_vec()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CLIENT_HELLO};

    #[test]
    fn test_client_hello_basic() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030, 0xc02f, 0x009e]);
        let hello = builder.build().expect("test assertion should succeed");
        assert!(hello.len() > 40);
        assert_eq!(hello[0], CONTENT_TYPE_HANDSHAKE);
        assert_eq!(hello[5], HANDSHAKE_TYPE_CLIENT_HELLO);
    }

    #[test]
    fn test_client_hello_with_sni() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030]);
        builder.add_sni("example.com");
        let hello = builder.build().expect("test assertion should succeed");
        assert!(hello.len() > 60);
    }

    #[test]
    fn test_client_hello_defaults() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030, 0xc02f]);
        let hello = builder
            .build_with_defaults(Some("example.com"))
            .expect("test assertion should succeed");
        assert!(hello.len() > 100);
    }

    #[test]
    fn test_client_hello_defaults_without_sni() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030]);
        let hello = builder
            .build_with_defaults(None)
            .expect("test assertion should succeed");
        assert!(hello.len() > 40);
    }

    #[test]
    fn test_client_hello_with_status_request() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030]);
        builder.add_status_request();
        let hello = builder.build().expect("test assertion should succeed");
        assert!(hello.len() > 40);
        assert!(hello.windows(2).any(|w| w == [0x00, 0x05]));
    }

    #[test]
    fn test_build_minimal_record_length_matches() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_cipher(0x1301);
        let hello = builder
            .build_minimal()
            .expect("test assertion should succeed");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);
    }

    #[test]
    fn test_client_hello_with_alpn_extension_present() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_cipher(0xc02f);
        builder.add_alpn(&["h2", "http/1.1"]);
        let hello = builder.build().expect("test assertion should succeed");
        assert!(hello.windows(2).any(|w| w == EXTENSION_ALPN.to_be_bytes()));
    }
}
