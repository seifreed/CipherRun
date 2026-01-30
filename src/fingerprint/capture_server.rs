// ServerHello network capture module
//
// This module captures ServerHello messages from live TLS connections
// for JA3S fingerprinting

use crate::Result;
use crate::error::TlsError;
use crate::fingerprint::server_hello::ServerHelloCapture;
use crate::utils::network::Target;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Capture ServerHello from a TLS connection
pub struct ServerHelloNetworkCapture {
    target: Target,
    timeout: Duration,
}

impl ServerHelloNetworkCapture {
    /// Create a new ServerHello capture
    pub fn new(target: Target) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(10),
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Capture ServerHello by performing a TLS handshake
    pub fn capture(&self) -> Result<ServerHelloCapture> {
        // Connect to target
        // Use the first resolved IP address from the target
        let ip = self
            .target
            .ip_addresses
            .first()
            .ok_or_else(|| TlsError::ParseError {
                message: format!(
                    "No IP addresses resolved for target {}",
                    self.target.hostname
                ),
            })?;

        let socket_addr = std::net::SocketAddr::new(*ip, self.target.port);
        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout)
            .map_err(|e| TlsError::IoError { source: e })?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| TlsError::IoError { source: e })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| TlsError::IoError { source: e })?;

        // Send ClientHello
        let client_hello = self.build_client_hello();
        stream
            .write_all(&client_hello)
            .map_err(|e| TlsError::IoError { source: e })?;

        // Read ServerHello response
        let mut buffer = vec![0u8; 16384]; // 16KB buffer
        let bytes_read = stream
            .read(&mut buffer)
            .map_err(|e| TlsError::IoError { source: e })?;

        buffer.truncate(bytes_read);

        // Parse ServerHello
        ServerHelloCapture::parse(&buffer)
    }

    /// Build a ClientHello supporting TLS 1.2 and TLS 1.3
    fn build_client_hello(&self) -> Vec<u8> {
        let mut client_hello = Vec::new();

        // TLS Record Layer
        client_hello.push(0x16); // ContentType: Handshake
        client_hello.extend_from_slice(&[0x03, 0x01]); // Legacy version: TLS 1.0 for compatibility

        // We'll calculate and update the length later
        let length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]); // Placeholder for length

        // Handshake Protocol
        client_hello.push(0x01); // HandshakeType: ClientHello

        // Placeholder for handshake length (3 bytes)
        let handshake_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello
        client_hello.extend_from_slice(&[0x03, 0x03]); // Legacy version: TLS 1.2

        // Random (32 bytes) - use proper random
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs() as u32;
        let mut random = [0u8; 32];
        random[0..4].copy_from_slice(&now.to_be_bytes());
        // Fill rest with some pseudo-random data
        for (i, byte) in random.iter_mut().enumerate().skip(4) {
            *byte = ((i * 7 + now as usize) % 256) as u8;
        }
        client_hello.extend_from_slice(&random);

        // Session ID (empty for initial handshake)
        client_hello.push(0x00);

        // Cipher Suites - include TLS 1.3 and TLS 1.2 ciphers
        let cipher_suites = vec![
            // TLS 1.3 ciphers
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            // TLS 1.2 ciphers
            0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC0, 0x2B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC0, 0x2C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xCC, 0xA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xCC, 0xA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xC0, 0x2D, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            0xC0, 0x2E, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        ];
        client_hello.extend_from_slice(&((cipher_suites.len() as u16).to_be_bytes()));
        client_hello.extend_from_slice(&cipher_suites);

        // Compression Methods
        client_hello.push(0x01); // Length: 1
        client_hello.push(0x00); // No compression

        // Extensions
        let extensions_start = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]); // Placeholder for extensions length

        // Extension: server_name (SNI)
        let server_name = self.target.hostname.as_bytes();
        let sni_extension = Self::build_sni_extension(server_name);
        client_hello.extend_from_slice(&sni_extension);

        // Extension: supported_groups
        client_hello.extend_from_slice(&[
            0x00, 0x0A, // Extension type: supported_groups
            0x00, 0x0C, // Extension length: 12
            0x00, 0x0A, // Groups length: 10
            0x00, 0x1D, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
            0x00, 0x19, // secp521r1
            0x00, 0x1E, // x448
        ]);

        // Extension: signature_algorithms
        client_hello.extend_from_slice(&[
            0x00, 0x0D, // Extension type: signature_algorithms
            0x00, 0x14, // Extension length: 20
            0x00, 0x12, // Algorithms length: 18
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x06, 0x03, // ecdsa_secp521r1_sha512
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x06, 0x01, // rsa_pkcs1_sha512
        ]);

        // Extension: ec_point_formats
        client_hello.extend_from_slice(&[
            0x00, 0x0B, // Extension type: ec_point_formats
            0x00, 0x02, // Extension length: 2
            0x01, // Formats length: 1
            0x00, // uncompressed
        ]);

        // Extension: supported_versions (TLS 1.3)
        client_hello.extend_from_slice(&[
            0x00, 0x2B, // Extension type: supported_versions
            0x00, 0x05, // Extension length: 5
            0x04, // Versions length: 4
            0x03, 0x04, // TLS 1.3
            0x03, 0x03, // TLS 1.2
        ]);

        // Extension: key_share (TLS 1.3)
        client_hello.extend_from_slice(&[
            0x00, 0x33, // Extension type: key_share
            0x00, 0x26, // Extension length: 38
            0x00, 0x24, // Client shares length: 36
            // Key share entry: x25519
            0x00, 0x1D, // Group: x25519
            0x00,
            0x20, // Key exchange length: 32
                  // Public key (32 bytes of pseudo-random data)
        ]);
        for i in 0..32 {
            client_hello.push(((i * 13 + now as usize) % 256) as u8);
        }

        // Extension: psk_key_exchange_modes (TLS 1.3)
        client_hello.extend_from_slice(&[
            0x00, 0x2D, // Extension type: psk_key_exchange_modes
            0x00, 0x02, // Extension length: 2
            0x01, // Modes length: 1
            0x01, // psk_dhe_ke
        ]);

        // Extension: extended_master_secret
        client_hello.extend_from_slice(&[
            0x00, 0x17, // Extension type: extended_master_secret
            0x00, 0x00, // Extension length: 0
        ]);

        // Update extensions length
        let extensions_len = (client_hello.len() - extensions_start - 2) as u16;
        client_hello[extensions_start..extensions_start + 2]
            .copy_from_slice(&extensions_len.to_be_bytes());

        // Update handshake length (3 bytes, big-endian, excludes handshake header)
        let handshake_body_len = (client_hello.len() - handshake_length_pos - 3) as u32;
        client_hello[handshake_length_pos] = ((handshake_body_len >> 16) & 0xFF) as u8;
        client_hello[handshake_length_pos + 1] = ((handshake_body_len >> 8) & 0xFF) as u8;
        client_hello[handshake_length_pos + 2] = (handshake_body_len & 0xFF) as u8;

        // Update record length
        let record_len = (client_hello.len() - length_pos - 2) as u16;
        client_hello[length_pos..length_pos + 2].copy_from_slice(&record_len.to_be_bytes());

        client_hello
    }

    /// Build SNI extension
    fn build_sni_extension(server_name: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();

        // Extension type: server_name (0x0000)
        extension.extend_from_slice(&[0x00, 0x00]);

        // Extension length (to be calculated)
        let ext_len_pos = extension.len();
        extension.extend_from_slice(&[0x00, 0x00]);

        // Server Name List Length
        let list_len_pos = extension.len();
        extension.extend_from_slice(&[0x00, 0x00]);

        // Server Name Type: host_name (0)
        extension.push(0x00);

        // Server Name Length
        extension.extend_from_slice(&(server_name.len() as u16).to_be_bytes());

        // Server Name
        extension.extend_from_slice(server_name);

        // Update Server Name List Length
        let list_len = (extension.len() - list_len_pos - 2) as u16;
        extension[list_len_pos..list_len_pos + 2].copy_from_slice(&list_len.to_be_bytes());

        // Update Extension Length
        let ext_len = (extension.len() - ext_len_pos - 2) as u16;
        extension[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

        extension
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let capture = ServerHelloNetworkCapture::new(target);
        let client_hello = capture.build_client_hello();

        // Should be a valid TLS record
        assert_eq!(client_hello[0], 0x16); // Handshake
        assert_eq!(client_hello[1], 0x03); // Version major
        assert_eq!(client_hello[2], 0x01); // Legacy record version (TLS 1.0) for compatibility

        // Should have reasonable length
        assert!(client_hello.len() > 50);
        assert!(client_hello.len() < 1024);
    }

    #[test]
    fn test_build_sni_extension() {
        let server_name = b"example.com";
        let extension = ServerHelloNetworkCapture::build_sni_extension(server_name);

        // Extension type should be 0x0000
        assert_eq!(extension[0], 0x00);
        assert_eq!(extension[1], 0x00);

        // Should contain the server name
        assert!(
            extension
                .windows(server_name.len())
                .any(|window| window == server_name)
        );
    }
}
