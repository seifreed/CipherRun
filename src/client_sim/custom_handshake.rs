// Custom TLS Handshake - Build and send real TLS ClientHello messages
// Allows precise control over extensions, cipher suites, and TLS version

use crate::Result;
use crate::data::client_data::ClientProfile;
use crate::protocols::Protocol;
use std::str::FromStr;
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
        use rand::Rng;
        rand::rng().fill_bytes(&mut random);

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
        let highest_protocol = parse_profile_protocol(profile.highest_protocol.as_deref());
        let version = match highest_protocol {
            Some(Protocol::TLS13) => 0x0303, // TLS 1.2 in record, 1.3 in extension
            Some(Protocol::TLS12) => 0x0303,
            Some(Protocol::TLS11) => 0x0302,
            Some(Protocol::TLS10) => 0x0301,
            Some(Protocol::SSLv3) => 0x0300,
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
            .extension(TlsExtension::supported_groups(&profile_supported_groups(
                profile,
            )))
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

        if profile.uses_sni {
            builder = builder.extension(TlsExtension::server_name(hostname));
        }

        // Add ALPN with common protocols
        builder = builder.extension(TlsExtension::alpn(&["h2", "http/1.1"]));

        // Add supported_versions for TLS 1.3
        if matches!(highest_protocol, Some(Protocol::TLS13)) {
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

fn parse_profile_protocol(value: Option<&str>) -> Option<Protocol> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        && let Ok(raw) = u16::from_str_radix(hex, 16)
    {
        return match raw {
            0x0300 => Some(Protocol::SSLv3),
            0x0301 => Some(Protocol::TLS10),
            0x0302 => Some(Protocol::TLS11),
            0x0303 => Some(Protocol::TLS12),
            0x0304 => Some(Protocol::TLS13),
            _ => None,
        };
    }

    Protocol::from_str(value).ok()
}

fn profile_supported_groups(profile: &ClientProfile) -> Vec<u16> {
    let groups: Vec<u16> = profile
        .curves
        .iter()
        .filter_map(|curve| named_group_id(curve))
        .collect();

    if groups.is_empty() {
        vec![0x001d, 0x0017, 0x0018]
    } else {
        groups
    }
}

fn named_group_id(curve: &str) -> Option<u16> {
    match curve.trim().to_ascii_lowercase().as_str() {
        "x25519" => Some(0x001d),
        "x448" => Some(0x001e),
        "secp256r1" | "prime256v1" | "p-256" => Some(0x0017),
        "secp384r1" | "p-384" => Some(0x0018),
        "secp521r1" | "p-521" => Some(0x0019),
        "secp256k1" => Some(0x0016),
        "ffdhe2048" => Some(0x0100),
        "ffdhe3072" => Some(0x0101),
        "ffdhe4096" => Some(0x0102),
        "ffdhe6144" => Some(0x0103),
        "ffdhe8192" => Some(0x0104),
        _ => None,
    }
}

/// Extended handshake information from ServerHello
#[derive(Debug, Clone)]
pub struct ServerHelloInfo {
    pub protocol: Protocol,
    pub cipher: String,
    pub alpn: Option<String>,
    pub key_exchange_group: Option<u16>,
}

/// Perform custom TLS handshake
pub async fn perform_custom_handshake(
    stream: &mut TcpStream,
    client_hello: &[u8],
    timeout_duration: Duration,
) -> Result<ServerHelloInfo> {
    use tokio::time::timeout;

    // Send ClientHello
    timeout(timeout_duration, stream.write_all(client_hello)).await??;

    // Read ServerHello and extract info
    let mut buffer = vec![0u8; 16384];
    let n = timeout(timeout_duration, stream.read(&mut buffer)).await??;

    if n == 0 {
        return Err(crate::error::TlsError::ConnectionClosed {
            details: "Server closed connection".to_string(),
        });
    }

    // Parse ServerHello with extended info
    parse_server_hello_extended(&buffer[..n])
}

/// Parse ServerHello with extended information (ALPN, key exchange)
fn parse_server_hello_extended(data: &[u8]) -> Result<ServerHelloInfo> {
    // Look for ServerHello (0x02)
    for i in 0..data.len().saturating_sub(10) {
        if data[i] == 0x16 && // Handshake
           i + 5 < data.len() &&
           data[i + 5] == 0x02
        {
            // ServerHello found

            // Extract version (bytes 9-10 in ServerHello)
            if i + 10 < data.len() {
                let version = u16::from_be_bytes([data[i + 9], data[i + 10]]);
                let mut protocol = match version {
                    0x0304 => Protocol::TLS13,
                    0x0303 => Protocol::TLS12,
                    0x0302 => Protocol::TLS11,
                    0x0301 => Protocol::TLS10,
                    0x0300 => Protocol::SSLv3,
                    _ => {
                        return Err(crate::error::TlsError::InvalidHandshake {
                            details: format!(
                                "Unknown ServerHello protocol version 0x{version:04x}"
                            ),
                        });
                    }
                };

                // Extract cipher suite (after 32-byte random + session ID)
                let mut cipher_name = "Unknown".to_string();
                let mut alpn = None;
                let mut key_exchange_group = None;

                if i + 44 < data.len() {
                    let session_id_len = data[i + 43] as usize;
                    let cipher_pos = i + 44 + session_id_len;

                    if cipher_pos + 1 < data.len() {
                        let cipher = u16::from_be_bytes([data[cipher_pos], data[cipher_pos + 1]]);
                        cipher_name = format_cipher_name(cipher);

                        // Parse extensions (after cipher suite + compression method)
                        let ext_start = cipher_pos + 2 + 1; // +2 for cipher, +1 for compression
                        if ext_start + 1 < data.len() {
                            let ext_len =
                                u16::from_be_bytes([data[ext_start], data[ext_start + 1]]) as usize;
                            let mut ext_pos = ext_start + 2;
                            let ext_end = ext_pos + ext_len;

                            // Parse each extension
                            while ext_pos + 4 <= ext_end && ext_pos + 4 <= data.len() {
                                let ext_type =
                                    u16::from_be_bytes([data[ext_pos], data[ext_pos + 1]]);
                                let ext_data_len =
                                    u16::from_be_bytes([data[ext_pos + 2], data[ext_pos + 3]])
                                        as usize;
                                ext_pos += 4;

                                if ext_pos + ext_data_len > data.len() {
                                    break;
                                }

                                match ext_type {
                                    0x0010 => {
                                        // ALPN extension
                                        if ext_data_len >= 3 {
                                            let list_len = u16::from_be_bytes([
                                                data[ext_pos],
                                                data[ext_pos + 1],
                                            ])
                                                as usize;
                                            if ext_pos + 2 + list_len <= data.len() {
                                                let proto_len = data[ext_pos + 2] as usize;
                                                if ext_pos + 3 + proto_len <= data.len() {
                                                    alpn = String::from_utf8(
                                                        data[ext_pos + 3..ext_pos + 3 + proto_len]
                                                            .to_vec(),
                                                    )
                                                    .ok();
                                                }
                                            }
                                        }
                                    }
                                    0x002b => {
                                        // Supported versions (TLS 1.3)
                                        if ext_data_len >= 2 {
                                            let selected_version = u16::from_be_bytes([
                                                data[ext_pos],
                                                data[ext_pos + 1],
                                            ]);
                                            protocol = match selected_version {
                                                0x0304 => Protocol::TLS13,
                                                0x0303 => Protocol::TLS12,
                                                _ => {
                                                    return Err(
                                                        crate::error::TlsError::InvalidHandshake {
                                                            details: format!(
                                                                "Unknown ServerHello supported_version 0x{selected_version:04x}"
                                                            ),
                                                        },
                                                    );
                                                }
                                            };
                                        }
                                    }
                                    0x0033 => {
                                        // Key share (TLS 1.3)
                                        if ext_data_len >= 2 {
                                            key_exchange_group = Some(u16::from_be_bytes([
                                                data[ext_pos],
                                                data[ext_pos + 1],
                                            ]));
                                        }
                                    }
                                    _ => {}
                                }

                                ext_pos += ext_data_len;
                            }
                        }
                    }
                }

                return Ok(ServerHelloInfo {
                    protocol,
                    cipher: cipher_name,
                    alpn,
                    key_exchange_group,
                });
            }
        }
    }

    Err(crate::error::TlsError::InvalidHandshake {
        details: "Could not parse ServerHello".to_string(),
    })
}

/// Format cipher suite code to human-readable name
fn format_cipher_name(cipher: u16) -> String {
    match cipher {
        // TLS 1.3 cipher suites
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
        0x1305 => "TLS_AES_128_CCM_8_SHA256".to_string(),

        // TLS 1.2 ECDHE cipher suites
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),

        // Other common cipher suites
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),

        // Default: hex representation
        _ => format!("0x{:04X}", cipher),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(highest_protocol: Option<&str>) -> ClientProfile {
        ClientProfile {
            name: "Test Client".to_string(),
            short_id: "test".to_string(),
            cipher_string: None,
            tls13_ciphers: None,
            uses_sni: true,
            warning: None,
            handshake_bytes: None,
            protocol_flags: vec![],
            tls_version: None,
            lowest_protocol: None,
            highest_protocol: highest_protocol.map(|s| s.to_string()),
            services: vec![],
            min_dh_bits: None,
            max_dh_bits: None,
            min_rsa_bits: None,
            max_rsa_bits: None,
            min_ecdsa_bits: None,
            curves: vec![],
            requires_sha2: false,
            current: true,
        }
    }

    fn build_server_hello(
        cipher: u16,
        alpn: Option<&str>,
        selected_version: Option<u16>,
        key_share_group: Option<u16>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x02); // ServerHello
        body.extend_from_slice(&[0x00, 0x00, 0x00]); // Handshake length placeholder
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 in legacy_version
        body.extend_from_slice(&[0u8; 32]); // Random
        body.push(0x00); // Session ID length
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0x00); // Compression method

        let mut extensions = Vec::new();
        if let Some(proto) = alpn {
            let proto_bytes = proto.as_bytes();
            let list_len = proto_bytes.len() + 1;
            let ext_len = 2 + list_len;
            extensions.extend_from_slice(&0x0010u16.to_be_bytes());
            extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
            extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
            extensions.push(proto_bytes.len() as u8);
            extensions.extend_from_slice(proto_bytes);
        }

        if let Some(version) = selected_version {
            extensions.extend_from_slice(&0x002bu16.to_be_bytes());
            extensions.extend_from_slice(&2u16.to_be_bytes());
            extensions.extend_from_slice(&version.to_be_bytes());
        }

        if let Some(group) = key_share_group {
            extensions.extend_from_slice(&0x0033u16.to_be_bytes());
            extensions.extend_from_slice(&2u16.to_be_bytes());
            extensions.extend_from_slice(&group.to_be_bytes());
        }

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let hs_len = body.len() - 4;
        body[1] = ((hs_len >> 16) & 0xff) as u8;
        body[2] = ((hs_len >> 8) & 0xff) as u8;
        body[3] = (hs_len & 0xff) as u8;

        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        let record_len = body.len();
        record[3] = ((record_len >> 8) & 0xff) as u8;
        record[4] = (record_len & 0xff) as u8;
        record.extend_from_slice(&body);
        record
    }

    fn parse_extension_types(client_hello: &[u8]) -> Vec<u16> {
        let session_len = client_hello[43] as usize;
        let cipher_len_pos = 44 + session_len;
        let cipher_len = u16::from_be_bytes([
            client_hello[cipher_len_pos],
            client_hello[cipher_len_pos + 1],
        ]) as usize;
        let compression_len_pos = cipher_len_pos + 2 + cipher_len;
        let compression_len = client_hello[compression_len_pos] as usize;
        let extensions_len_pos = compression_len_pos + 1 + compression_len;
        let extensions_len = u16::from_be_bytes([
            client_hello[extensions_len_pos],
            client_hello[extensions_len_pos + 1],
        ]) as usize;
        let mut pos = extensions_len_pos + 2;
        let end = pos + extensions_len;
        let mut extension_types = Vec::new();

        while pos + 4 <= end {
            let extension_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
            let extension_len =
                u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
            extension_types.push(extension_type);
            pos += 4 + extension_len;
        }

        extension_types
    }

    fn supported_groups_from_client_hello(client_hello: &[u8]) -> Vec<u16> {
        let session_len = client_hello[43] as usize;
        let cipher_len_pos = 44 + session_len;
        let cipher_len = u16::from_be_bytes([
            client_hello[cipher_len_pos],
            client_hello[cipher_len_pos + 1],
        ]) as usize;
        let compression_len_pos = cipher_len_pos + 2 + cipher_len;
        let compression_len = client_hello[compression_len_pos] as usize;
        let extensions_len_pos = compression_len_pos + 1 + compression_len;
        let extensions_len = u16::from_be_bytes([
            client_hello[extensions_len_pos],
            client_hello[extensions_len_pos + 1],
        ]) as usize;
        let mut pos = extensions_len_pos + 2;
        let end = pos + extensions_len;

        while pos + 4 <= end {
            let extension_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
            let extension_len =
                u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
            let data_start = pos + 4;
            let data_end = data_start + extension_len;
            if extension_type == 0x000a && data_start + 2 <= data_end {
                let list_len =
                    u16::from_be_bytes([client_hello[data_start], client_hello[data_start + 1]])
                        as usize;
                let mut group_pos = data_start + 2;
                let group_end = (group_pos + list_len).min(data_end);
                let mut groups = Vec::new();
                while group_pos + 2 <= group_end {
                    groups.push(u16::from_be_bytes([
                        client_hello[group_pos],
                        client_hello[group_pos + 1],
                    ]));
                    group_pos += 2;
                }
                return groups;
            }
            pos = data_end;
        }

        Vec::new()
    }

    #[test]
    fn test_sni_extension() {
        let ext = TlsExtension::server_name("example.com");
        assert_eq!(ext.extension_type, 0x0000);
        let encoded = ext.encode();
        assert!(encoded.len() > 4);
    }

    #[test]
    fn test_extension_encodings() {
        let groups = TlsExtension::supported_groups(&[0x001d, 0x0017]);
        let groups_encoded = groups.encode();
        assert_eq!(groups.extension_type, 0x000a);
        assert_eq!(groups_encoded[4], 0x00);
        assert_eq!(groups_encoded[5], 0x04);

        let sigs = TlsExtension::signature_algorithms(&[(0x04, 0x03), (0x08, 0x04)]);
        let sigs_encoded = sigs.encode();
        assert_eq!(sigs.extension_type, 0x000d);
        assert_eq!(sigs_encoded[4], 0x00);
        assert_eq!(sigs_encoded[5], 0x04);

        let alpn = TlsExtension::alpn(&["h2", "http/1.1"]);
        let alpn_encoded = alpn.encode();
        assert_eq!(alpn.extension_type, 0x0010);
        assert!(alpn_encoded.len() > 8);

        let versions = TlsExtension::supported_versions(&[0x0304, 0x0303]);
        let versions_encoded = versions.encode();
        assert_eq!(versions.extension_type, 0x002b);
        assert_eq!(versions_encoded[4], 0x04);
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

    #[test]
    fn test_client_hello_from_profile_tls13() {
        let profile = sample_profile(Some("tls1_3"));
        let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();

        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[5], 0x01); // ClientHello
        assert!(hello.windows(2).any(|w| w == [0x00, 0x2b])); // supported_versions
        assert!(hello.windows(2).any(|w| w == [0x00, 0x10])); // ALPN
    }

    #[test]
    fn test_client_hello_from_profile_omits_sni_when_profile_disables_it() {
        let mut profile = sample_profile(Some("tls1_2"));
        profile.uses_sni = false;

        let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();
        let extension_types = parse_extension_types(&hello);

        assert!(!extension_types.contains(&0x0000));
    }

    #[test]
    fn test_client_hello_from_profile_uses_profile_curves() {
        let mut profile = sample_profile(Some("tls1_2"));
        profile.curves = vec!["secp256r1".to_string(), "secp384r1".to_string()];

        let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();

        assert_eq!(supported_groups_from_client_hello(&hello), [0x0017, 0x0018]);
    }

    #[test]
    fn test_parse_server_hello_extended_with_alpn() {
        let data = build_server_hello(0x1301, Some("h2"), Some(0x0304), Some(0x001d));
        let info = parse_server_hello_extended(&data).expect("test assertion should succeed");

        assert_eq!(info.protocol, Protocol::TLS13);
        assert_eq!(info.cipher, "TLS_AES_128_GCM_SHA256");
        assert_eq!(info.alpn.as_deref(), Some("h2"));
        assert_eq!(info.key_exchange_group, Some(0x001d));
    }

    #[test]
    fn test_parse_server_hello_rejects_unknown_legacy_version() {
        let mut data = build_server_hello(0x1301, None, None, None);
        data[9] = 0x7f;
        data[10] = 0x17;

        let err = parse_server_hello_extended(&data).expect_err("unknown version should fail");

        assert!(
            err.to_string()
                .contains("Unknown ServerHello protocol version")
        );
    }

    #[test]
    fn test_parse_server_hello_extended_missing() {
        let err = parse_server_hello_extended(&[0x00, 0x01, 0x02]).unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("ServerHello") || message.contains("handshake"));
    }

    #[test]
    fn test_format_cipher_name_unknown() {
        let name = format_cipher_name(0x1234);
        assert_eq!(name, "0x1234");
    }
}
