// Custom TLS Handshake - Build and send real TLS ClientHello messages
// Allows precise control over extensions, cipher suites, and TLS version

use crate::Result;
use crate::data::client_data::ClientProfile;
use crate::protocols::Protocol;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TLS Extension builder
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Server Name Indication (SNI) extension
    pub fn server_name(hostname: &str) -> Self {
        let mut data = Vec::new();

        // Server name list length
        let list_len = hostname.len() + 5;
        data.push(((list_len >> 8) & 0xff) as u8);
        data.push((list_len & 0xff) as u8);

        // Name type: host_name (0)
        data.push(0x00);

        // Hostname length
        data.push(((hostname.len() >> 8) & 0xff) as u8);
        data.push((hostname.len() & 0xff) as u8);

        // Hostname
        data.extend_from_slice(hostname.as_bytes());

        Self {
            extension_type: 0x0000, // server_name
            data,
        }
    }

    /// Supported Groups (formerly Elliptic Curves)
    pub fn supported_groups(groups: &[u16]) -> Self {
        let mut data = Vec::new();

        // List length
        let list_len = groups.len() * 2;
        data.push(((list_len >> 8) & 0xff) as u8);
        data.push((list_len & 0xff) as u8);

        // Groups
        for &group in groups {
            data.push(((group >> 8) & 0xff) as u8);
            data.push((group & 0xff) as u8);
        }

        Self {
            extension_type: 0x000a, // supported_groups
            data,
        }
    }

    /// EC Point Formats
    pub fn ec_point_formats() -> Self {
        Self {
            extension_type: 0x000b, // ec_point_formats
            data: vec![0x01, 0x00], // uncompressed
        }
    }

    /// Signature Algorithms
    pub fn signature_algorithms(algorithms: &[(u8, u8)]) -> Self {
        let mut data = Vec::new();

        // Algorithms length
        let list_len = algorithms.len() * 2;
        data.push(((list_len >> 8) & 0xff) as u8);
        data.push((list_len & 0xff) as u8);

        // Algorithms
        for &(hash, sig) in algorithms {
            data.push(hash);
            data.push(sig);
        }

        Self {
            extension_type: 0x000d, // signature_algorithms
            data,
        }
    }

    /// ALPN (Application Layer Protocol Negotiation)
    pub fn alpn(protocols: &[&str]) -> Self {
        let mut data = Vec::new();

        // Calculate total length
        let list_len: usize = protocols.iter().map(|p| p.len() + 1).sum();

        // List length
        data.push(((list_len >> 8) & 0xff) as u8);
        data.push((list_len & 0xff) as u8);

        // Protocols
        for proto in protocols {
            data.push(proto.len() as u8);
            data.extend_from_slice(proto.as_bytes());
        }

        Self {
            extension_type: 0x0010, // application_layer_protocol_negotiation
            data,
        }
    }

    /// Supported Versions (TLS 1.3+)
    pub fn supported_versions(versions: &[u16]) -> Self {
        let mut data = Vec::new();

        // Versions length
        data.push((versions.len() * 2) as u8);

        // Versions
        for &version in versions {
            data.push(((version >> 8) & 0xff) as u8);
            data.push((version & 0xff) as u8);
        }

        Self {
            extension_type: 0x002b, // supported_versions
            data,
        }
    }

    /// Renegotiation Info (RFC 5746)
    pub fn renegotiation_info() -> Self {
        Self {
            extension_type: 0xff01, // renegotiation_info
            data: vec![0x00],       // Empty renegotiation info
        }
    }

    /// Extended Master Secret (RFC 7627)
    pub fn extended_master_secret() -> Self {
        Self {
            extension_type: 0x0017, // extended_master_secret
            data: vec![],
        }
    }

    /// Session Ticket (RFC 5077)
    pub fn session_ticket() -> Self {
        Self {
            extension_type: 0x0023, // session_ticket
            data: vec![],
        }
    }

    /// Encode extension to bytes
    pub fn encode(&self) -> Vec<u8> {
        // Extension type and length
        let mut bytes = vec![
            ((self.extension_type >> 8) & 0xff) as u8,
            (self.extension_type & 0xff) as u8,
            ((self.data.len() >> 8) & 0xff) as u8,
            (self.data.len() & 0xff) as u8,
        ];

        // Extension data
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

/// Custom ClientHello builder
pub struct ClientHelloBuilder {
    version: u16,
    random: [u8; 32],
    cipher_suites: Vec<u16>,
    extensions: Vec<TlsExtension>,
}

impl ClientHelloBuilder {
    /// Create new ClientHello builder
    pub fn new(version: u16) -> Self {
        // Generate random
        let mut random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut random);

        Self {
            version,
            random,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Add cipher suite
    pub fn cipher_suite(mut self, cipher: u16) -> Self {
        self.cipher_suites.push(cipher);
        self
    }

    /// Add multiple cipher suites
    pub fn cipher_suites(mut self, ciphers: &[u16]) -> Self {
        self.cipher_suites.extend_from_slice(ciphers);
        self
    }

    /// Add extension
    pub fn extension(mut self, extension: TlsExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Build from client profile
    pub fn from_profile(profile: &ClientProfile, hostname: &str) -> Self {
        let version = match profile.highest_protocol.as_deref() {
            Some("tls1_3") => 0x0303, // TLS 1.2 in record, 1.3 in extension
            Some("tls1_2") => 0x0303,
            Some("tls1_1") => 0x0302,
            Some("tls1") | Some("tls1_0") => 0x0301,
            _ => 0x0303, // Default to TLS 1.2
        };

        let mut builder = Self::new(version);

        // Add cipher suites from profile
        // For now, use a default set of modern ciphers
        // In a real implementation, would parse cipher_string
        let default_ciphers = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        ];

        builder = builder.cipher_suites(&default_ciphers);

        // Add common extensions
        builder = builder
            .extension(TlsExtension::server_name(hostname))
            .extension(TlsExtension::supported_groups(&[
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ]))
            .extension(TlsExtension::ec_point_formats())
            .extension(TlsExtension::signature_algorithms(&[
                (0x04, 0x03), // ecdsa_secp256r1_sha256
                (0x05, 0x03), // ecdsa_secp384r1_sha384
                (0x06, 0x03), // ecdsa_secp521r1_sha512
                (0x08, 0x04), // rsa_pss_rsae_sha256
                (0x08, 0x05), // rsa_pss_rsae_sha384
                (0x08, 0x06), // rsa_pss_rsae_sha512
                (0x04, 0x01), // rsa_pkcs1_sha256
                (0x05, 0x01), // rsa_pkcs1_sha384
                (0x06, 0x01), // rsa_pkcs1_sha512
            ]))
            .extension(TlsExtension::renegotiation_info())
            .extension(TlsExtension::extended_master_secret())
            .extension(TlsExtension::session_ticket());

        // Add ALPN with common protocols
        builder = builder.extension(TlsExtension::alpn(&["h2", "http/1.1"]));

        // Add supported_versions for TLS 1.3
        if matches!(profile.highest_protocol.as_deref(), Some("tls1_3")) {
            builder = builder.extension(TlsExtension::supported_versions(&[
                0x0304, // TLS 1.3
                0x0303, // TLS 1.2
            ]));
        }

        builder
    }

    /// Build the ClientHello message
    pub fn build(self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record Layer
        hello.push(0x16); // Handshake
        hello.push(((self.version >> 8) & 0xff) as u8);
        hello.push((self.version & 0xff) as u8);

        // Record length placeholder
        let record_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake header
        hello.push(0x01); // ClientHello

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version
        hello.push(((self.version >> 8) & 0xff) as u8);
        hello.push((self.version & 0xff) as u8);

        // Random
        hello.extend_from_slice(&self.random);

        // Session ID (empty)
        hello.push(0x00);

        // Cipher Suites
        let cipher_len = self.cipher_suites.len() * 2;
        hello.push(((cipher_len >> 8) & 0xff) as u8);
        hello.push((cipher_len & 0xff) as u8);

        for cipher in &self.cipher_suites {
            hello.push(((cipher >> 8) & 0xff) as u8);
            hello.push((cipher & 0xff) as u8);
        }

        // Compression Methods
        hello.push(0x01); // Length
        hello.push(0x00); // null compression

        // Extensions
        if !self.extensions.is_empty() {
            let ext_start = hello.len();
            hello.push(0x00);
            hello.push(0x00); // Extensions length placeholder

            for ext in &self.extensions {
                hello.extend_from_slice(&ext.encode());
            }

            // Update extensions length
            let ext_len = hello.len() - ext_start - 2;
            hello[ext_start] = ((ext_len >> 8) & 0xff) as u8;
            hello[ext_start + 1] = (ext_len & 0xff) as u8;
        }

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Update record length
        let record_len = hello.len() - record_len_pos - 2;
        hello[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        hello[record_len_pos + 1] = (record_len & 0xff) as u8;

        hello
    }
}

/// Perform custom TLS handshake
pub async fn perform_custom_handshake(
    stream: &mut TcpStream,
    client_hello: &[u8],
    timeout_duration: Duration,
) -> Result<(Protocol, String)> {
    use tokio::time::timeout;

    // Send ClientHello
    timeout(timeout_duration, stream.write_all(client_hello)).await??;

    // Read ServerHello and extract info
    let mut buffer = vec![0u8; 16384];
    let n = timeout(timeout_duration, stream.read(&mut buffer)).await??;

    if n == 0 {
        anyhow::bail!("Server closed connection");
    }

    // Parse ServerHello
    let (protocol, cipher) = parse_server_hello(&buffer[..n])?;

    Ok((protocol, cipher))
}

/// Parse ServerHello to extract protocol and cipher
fn parse_server_hello(data: &[u8]) -> Result<(Protocol, String)> {
    // Basic parsing - look for ServerHello (0x02)
    for i in 0..data.len().saturating_sub(10) {
        if data[i] == 0x16 && // Handshake
           i + 5 < data.len() &&
           data[i + 5] == 0x02
        {
            // ServerHello

            // Extract version (bytes 9-10 in ServerHello)
            if i + 11 < data.len() {
                let version = u16::from_be_bytes([data[i + 9], data[i + 10]]);
                let protocol = match version {
                    0x0304 => Protocol::TLS13,
                    0x0303 => Protocol::TLS12,
                    0x0302 => Protocol::TLS11,
                    0x0301 => Protocol::TLS10,
                    0x0300 => Protocol::SSLv3,
                    _ => Protocol::TLS12,
                };

                // Extract cipher suite (after 32-byte random + session ID)
                // Skip to cipher suite field
                if i + 44 < data.len() {
                    let session_id_len = data[i + 43] as usize;
                    let cipher_pos = i + 44 + session_id_len;

                    if cipher_pos + 1 < data.len() {
                        let cipher = u16::from_be_bytes([data[cipher_pos], data[cipher_pos + 1]]);
                        let cipher_name = format!("0x{:04X}", cipher);

                        return Ok((protocol, cipher_name));
                    }
                }

                return Ok((protocol, "Unknown".to_string()));
            }
        }
    }

    anyhow::bail!("Could not parse ServerHello")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_extension() {
        let ext = TlsExtension::server_name("example.com");
        assert_eq!(ext.extension_type, 0x0000);
        let encoded = ext.encode();
        assert!(encoded.len() > 4);
    }

    #[test]
    fn test_client_hello_builder() {
        let hello = ClientHelloBuilder::new(0x0303)
            .cipher_suite(0xc02f)
            .cipher_suite(0xc030)
            .extension(TlsExtension::server_name("test.com"))
            .build();

        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // ClientHello
        assert!(hello.len() > 50);
    }
}
