// TLS Handshake Builder - Constructs ClientHello messages

use super::{Extension, Protocol};
use crate::Result;
use bytes::{BufMut, BytesMut};

/// ClientHello message builder
pub struct ClientHelloBuilder {
    protocol: Protocol,
    cipher_suites: Vec<u16>,
    extensions: Vec<Extension>,
    session_id: Vec<u8>,
    compression_methods: Vec<u8>,
    random: [u8; 32],
}

impl ClientHelloBuilder {
    /// Create new ClientHello builder
    pub fn new(protocol: Protocol) -> Self {
        let mut random = [0u8; 32];
        // First 4 bytes are Unix time
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        random[0..4].copy_from_slice(&timestamp.to_be_bytes());
        // Rest is random
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut random[4..]);

        Self {
            protocol,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            session_id: Vec::new(),
            compression_methods: vec![0], // No compression
            random,
        }
    }

    /// Add cipher suite by hex code
    pub fn add_cipher(&mut self, hexcode: u16) -> &mut Self {
        self.cipher_suites.push(hexcode);
        self
    }

    /// Add multiple cipher suites
    pub fn add_ciphers(&mut self, hexcodes: &[u16]) -> &mut Self {
        self.cipher_suites.extend_from_slice(hexcodes);
        self
    }

    /// Add TLS extension
    pub fn add_extension(&mut self, extension: Extension) -> &mut Self {
        self.extensions.push(extension);
        self
    }

    /// Add Server Name Indication (SNI)
    pub fn add_sni(&mut self, hostname: &str) -> &mut Self {
        let mut data = BytesMut::new();

        // Server name list length
        let list_len = 3 + hostname.len();
        data.put_u16(list_len as u16);

        // Name type (0 = hostname)
        data.put_u8(0);

        // Hostname length and value
        data.put_u16(hostname.len() as u16);
        data.put_slice(hostname.as_bytes());

        self.extensions.push(Extension::new(0x0000, data.to_vec()));
        self
    }

    /// Add supported groups (elliptic curves)
    pub fn add_supported_groups(&mut self, curves: &[u16]) -> &mut Self {
        let mut data = BytesMut::new();

        // List length
        data.put_u16((curves.len() * 2) as u16);

        // Curve IDs
        for curve in curves {
            data.put_u16(*curve);
        }

        self.extensions.push(Extension::new(0x000a, data.to_vec()));
        self
    }

    /// Add signature algorithms
    pub fn add_signature_algorithms(&mut self, algorithms: &[(u8, u8)]) -> &mut Self {
        let mut data = BytesMut::new();

        // List length
        data.put_u16((algorithms.len() * 2) as u16);

        // Algorithm pairs (hash, signature)
        for (hash, sig) in algorithms {
            data.put_u8(*hash);
            data.put_u8(*sig);
        }

        self.extensions.push(Extension::new(0x000d, data.to_vec()));
        self
    }

    /// Add ALPN (Application-Layer Protocol Negotiation)
    pub fn add_alpn(&mut self, protocols: &[&str]) -> &mut Self {
        let mut data = BytesMut::new();

        // Calculate total length
        let total_len: usize = protocols.iter().map(|p| 1 + p.len()).sum();
        data.put_u16(total_len as u16);

        // Add protocols
        for protocol in protocols {
            data.put_u8(protocol.len() as u8);
            data.put_slice(protocol.as_bytes());
        }

        self.extensions.push(Extension::new(0x0010, data.to_vec()));
        self
    }

    /// Add ec_point_formats extension
    pub fn add_ec_point_formats(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        // EC point formats length
        data.put_u8(1);
        // uncompressed (0)
        data.put_u8(0);
        self.extensions.push(Extension::new(0x000b, data.to_vec()));
        self
    }

    /// Add session_ticket extension (empty for new ticket)
    pub fn add_session_ticket(&mut self) -> &mut Self {
        self.extensions.push(Extension::new(0x0023, vec![]));
        self
    }

    /// Add encrypt_then_mac extension
    pub fn add_encrypt_then_mac(&mut self) -> &mut Self {
        self.extensions.push(Extension::new(0x0016, vec![]));
        self
    }

    /// Add extended master secret extension
    pub fn add_extended_master_secret(&mut self) -> &mut Self {
        self.extensions.push(Extension::new(0x0017, vec![]));
        self
    }

    /// Add renegotiation info extension
    pub fn add_renegotiation_info(&mut self) -> &mut Self {
        let mut data = BytesMut::new();
        data.put_u8(0); // Empty renegotiation info
        self.extensions.push(Extension::new(0xff01, data.to_vec()));
        self
    }

    /// Add supported versions (TLS 1.3)
    pub fn add_supported_versions(&mut self, versions: &[u16]) -> &mut Self {
        let mut data = BytesMut::new();

        // List length
        data.put_u8((versions.len() * 2) as u8);

        // Versions
        for version in versions {
            data.put_u16(*version);
        }

        self.extensions.push(Extension::new(0x002b, data.to_vec()));
        self
    }

    /// Add key_share extension (TLS 1.3)
    pub fn add_key_share(&mut self, group: u16) -> &mut Self {
        let mut data = BytesMut::new();

        // Generate a valid key share
        let public_key = if group == 0x001d {
            // X25519 - Generate a real cryptographic key pair
            use rand::rngs::OsRng;
            use x25519_dalek::{EphemeralSecret, PublicKey};

            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            public.as_bytes().to_vec()
        } else if group == 0x0017 {
            // secp256r1 - For now use random (would need another crate for proper impl)
            use rand::RngCore;
            let mut key = vec![0u8; 65];
            rand::thread_rng().fill_bytes(&mut key);
            key
        } else {
            // Default to random for unsupported groups
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };

        // Client key share length
        let share_len = 4 + public_key.len(); // 2 bytes group + 2 bytes length + key
        data.put_u16(share_len as u16);

        // Named group
        data.put_u16(group);

        // Key exchange data length
        data.put_u16(public_key.len() as u16);

        // Key exchange data
        data.put_slice(&public_key);

        self.extensions.push(Extension::new(0x0033, data.to_vec()));
        self
    }

    /// Add PSK key exchange modes (TLS 1.3)
    pub fn add_psk_key_exchange_modes(&mut self) -> &mut Self {
        let mut data = BytesMut::new();

        // Length of modes
        data.put_u8(1);

        // PSK with (EC)DHE key establishment (psk_dhe_ke)
        data.put_u8(1);

        self.extensions.push(Extension::new(0x002d, data.to_vec()));
        self
    }

    /// Add signature algorithms cert (TLS 1.3)
    pub fn add_signature_algorithms_cert(&mut self, algorithms: &[(u8, u8)]) -> &mut Self {
        let mut data = BytesMut::new();

        // List length
        data.put_u16((algorithms.len() * 2) as u16);

        // Algorithm pairs (hash, signature)
        for (hash, sig) in algorithms {
            data.put_u8(*hash);
            data.put_u8(*sig);
        }

        self.extensions.push(Extension::new(0x0050, data.to_vec()));
        self
    }

    /// Build the complete ClientHello message
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // Record Layer
        // Content Type: Handshake (22)
        buf.put_u8(0x16);

        // Legacy version (0x0301 for TLS 1.0, compatibility)
        let record_version = match self.protocol {
            Protocol::SSLv3 => 0x0300,
            _ => 0x0301,
        };
        buf.put_u16(record_version);

        // Length placeholder (will be filled later)
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Protocol
        let handshake_start = buf.len();

        // Handshake Type: ClientHello (1)
        buf.put_u8(0x01);

        // Length placeholder
        let handshake_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello content
        let hello_start = buf.len();

        // Protocol version
        // For TLS 1.3, use 0x0303 (TLS 1.2) for compatibility (RFC 8446)
        // The actual version is negotiated via supported_versions extension
        let client_version = if matches!(self.protocol, Protocol::TLS13) {
            0x0303
        } else {
            self.protocol.as_hex()
        };
        buf.put_u16(client_version);

        // Random (32 bytes)
        buf.put_slice(&self.random);

        // Session ID
        buf.put_u8(self.session_id.len() as u8);
        if !self.session_id.is_empty() {
            buf.put_slice(&self.session_id);
        }

        // Cipher suites
        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for cipher in &self.cipher_suites {
            buf.put_u16(*cipher);
        }

        // Compression methods
        buf.put_u8(self.compression_methods.len() as u8);
        buf.put_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let extensions_start = buf.len();
            buf.put_u16(0); // Placeholder for total extensions length

            for ext in &self.extensions {
                buf.put_u16(ext.extension_type);
                buf.put_u16(ext.data.len() as u16);
                buf.put_slice(&ext.data);
            }

            // Fill in extensions length
            let extensions_len = buf.len() - extensions_start - 2;
            buf[extensions_start..extensions_start + 2]
                .copy_from_slice(&(extensions_len as u16).to_be_bytes());
        }

        // Fill in handshake length
        let handshake_len = buf.len() - hello_start;
        buf[handshake_length_pos] = ((handshake_len >> 16) & 0xff) as u8;
        buf[handshake_length_pos + 1..handshake_length_pos + 3]
            .copy_from_slice(&((handshake_len & 0xffff) as u16).to_be_bytes());

        // Fill in record length
        let record_len = buf.len() - handshake_start;
        buf[length_pos..length_pos + 2].copy_from_slice(&(record_len as u16).to_be_bytes());

        Ok(buf.to_vec())
    }

    /// Build with default extensions
    pub fn build_with_defaults(&mut self, hostname: Option<&str>) -> Result<Vec<u8>> {
        // For TLS 1.3, add extensions in OpenSSL order for maximum compatibility
        if matches!(self.protocol, Protocol::TLS13) {
            // Extension order matches OpenSSL for strict servers

            // 1. SNI (0x0000)
            if let Some(host) = hostname {
                self.add_sni(host);
            }

            // 2. ec_point_formats (0x000b)
            self.add_ec_point_formats();

            // 3. supported_groups (0x000a) - Match OpenSSL with ffdhe groups
            self.add_supported_groups(&[
                0x001d, // x25519
                0x0017, // secp256r1
                0x001e, // x448
                0x0019, // secp521r1
                0x0018, // secp384r1
                0x0100, // ffdhe2048
                0x0101, // ffdhe3072
                0x0102, // ffdhe4096
                0x0103, // ffdhe6144
                0x0104, // ffdhe8192
            ]);

            // 4. session_ticket (0x0023)
            self.add_session_ticket();

            // 5. encrypt_then_mac (0x0016)
            self.add_encrypt_then_mac();

            // 6. extended_master_secret (0x0017)
            self.add_extended_master_secret();

            // 7. signature_algorithms (0x000d) - Extended list matching OpenSSL
            self.add_signature_algorithms(&[
                (0x04, 0x03), // ecdsa_secp256r1_sha256
                (0x05, 0x03), // ecdsa_secp384r1_sha384
                (0x06, 0x03), // ecdsa_secp521r1_sha512
                (0x08, 0x07), // ed25519
                (0x08, 0x08), // rsa_pss_rsae_sha256
                (0x08, 0x09), // rsa_pss_rsae_sha384
                (0x08, 0x0a), // rsa_pss_rsae_sha512
                (0x08, 0x0b), // rsa_pss_pss_sha256
                (0x08, 0x04), // rsa_pss_pss_sha256
                (0x08, 0x05), // rsa_pss_pss_sha384
                (0x08, 0x06), // rsa_pss_pss_sha512
                (0x04, 0x01), // rsa_pkcs1_sha256
                (0x05, 0x01), // rsa_pkcs1_sha384
                (0x06, 0x01), // rsa_pkcs1_sha512
            ]);

            // 8. supported_versions (0x002b) - ONLY TLS 1.3 for TLS 1.3 tests
            self.add_supported_versions(&[0x0304]);

            // 9. psk_key_exchange_modes (0x002d)
            self.add_psk_key_exchange_modes();

            // 10. key_share (0x0033)
            self.add_key_share(0x001d); // X25519
        } else {
            // TLS 1.2 and earlier - traditional order

            // SNI
            if let Some(host) = hostname {
                self.add_sni(host);
            }

            // Supported groups
            self.add_supported_groups(&[
                0x001d, // X25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
            ]);

            // Signature algorithms
            self.add_signature_algorithms(&[
                (0x04, 0x03), // SHA256-ECDSA
                (0x05, 0x03), // SHA384-ECDSA
                (0x06, 0x03), // SHA512-ECDSA
                (0x04, 0x01), // SHA256-RSA
                (0x05, 0x01), // SHA384-RSA
                (0x06, 0x01), // SHA512-RSA
            ]);

            // TLS 1.2 specific extensions
            self.add_extended_master_secret();
            self.add_renegotiation_info();
        }

        self.build()
    }
}

/// Parse ServerHello message
pub struct ServerHelloParser;

impl ServerHelloParser {
    /// Parse ServerHello from bytes
    pub fn parse(data: &[u8]) -> Result<ServerHello> {
        if data.len() < 6 {
            anyhow::bail!("ServerHello too short");
        }

        let mut offset = 0;

        // Skip record header (5 bytes)
        if data[0] != 0x16 {
            anyhow::bail!("Not a handshake record");
        }
        offset += 5;

        // Handshake type
        if data[offset] != 0x02 {
            anyhow::bail!("Not a ServerHello");
        }
        offset += 1;

        // Handshake length (3 bytes)
        offset += 3;

        // Protocol version
        let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Random (32 bytes)
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Session ID
        let session_id_len = data[offset] as usize;
        offset += 1;
        let session_id = data[offset..offset + session_id_len].to_vec();
        offset += session_id_len;

        // Cipher suite
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Compression method
        let compression = data[offset];
        offset += 1;

        // Extensions (if present)
        let mut extensions = Vec::new();
        if offset < data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            let ext_end = offset + ext_len;
            while offset < ext_end && offset + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;

                let ext_data_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;

                if offset + ext_data_len <= data.len() {
                    let ext_data = data[offset..offset + ext_data_len].to_vec();
                    extensions.push(Extension::new(ext_type, ext_data));
                    offset += ext_data_len;
                }
            }
        }

        Ok(ServerHello {
            version: Protocol::from(version),
            random,
            session_id,
            cipher_suite,
            compression,
            extensions,
        })
    }
}

/// ServerHello message
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub version: Protocol,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Get cipher suite as hex string
    pub fn cipher_hex(&self) -> String {
        format!("{:04x}", self.cipher_suite)
    }

    /// Check if extension is present
    pub fn has_extension(&self, ext_type: u16) -> bool {
        self.extensions.iter().any(|e| e.extension_type == ext_type)
    }

    /// Get extension by type
    pub fn get_extension(&self, ext_type: u16) -> Option<&Extension> {
        self.extensions
            .iter()
            .find(|e| e.extension_type == ext_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_basic() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030, 0xc02f, 0x009e]);

        let hello = builder.build().unwrap();

        assert!(hello.len() > 40);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_client_hello_with_sni() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030]);
        builder.add_sni("example.com");

        let hello = builder.build().unwrap();
        assert!(hello.len() > 60);
    }

    #[test]
    fn test_client_hello_defaults() {
        let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
        builder.add_ciphers(&[0xc030, 0xc02f]);

        let hello = builder.build_with_defaults(Some("example.com")).unwrap();
        assert!(hello.len() > 100); // Should have several extensions
    }
}
