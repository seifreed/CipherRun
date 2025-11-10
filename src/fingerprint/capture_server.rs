// ServerHello network capture module
//
// This module captures ServerHello messages from live TLS connections
// for JA3S fingerprinting

use crate::fingerprint::server_hello::ServerHelloCapture;
use crate::utils::network::Target;
use crate::Result;
use crate::error::TlsError;
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
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| TlsError::IoError {
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid address: {}", e))
            })?,
            self.timeout
        ).map_err(|e| TlsError::IoError { source: e })?;

        stream.set_read_timeout(Some(self.timeout))
            .map_err(|e| TlsError::IoError { source: e })?;
        stream.set_write_timeout(Some(self.timeout))
            .map_err(|e| TlsError::IoError { source: e })?;

        // Send ClientHello
        let client_hello = self.build_client_hello();
        stream.write_all(&client_hello)
            .map_err(|e| TlsError::IoError { source: e })?;

        // Read ServerHello response
        let mut buffer = vec![0u8; 16384]; // 16KB buffer
        let bytes_read = stream.read(&mut buffer)
            .map_err(|e| TlsError::IoError { source: e })?;

        buffer.truncate(bytes_read);

        // Parse ServerHello
        ServerHelloCapture::parse(&buffer)
    }

    /// Build a minimal ClientHello for TLS 1.2
    fn build_client_hello(&self) -> Vec<u8> {
        let mut client_hello = Vec::new();

        // TLS Record Layer
        client_hello.push(0x16); // ContentType: Handshake
        client_hello.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2

        // We'll calculate and update the length later
        let length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]); // Placeholder for length

        // Handshake Protocol
        client_hello.push(0x01); // HandshakeType: ClientHello

        // Placeholder for handshake length (3 bytes)
        let handshake_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello
        client_hello.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2

        // Random (32 bytes)
        let random: [u8; 32] = [0x00; 32]; // Simple random for now
        client_hello.extend_from_slice(&random);

        // Session ID (empty)
        client_hello.push(0x00);

        // Cipher Suites
        let cipher_suites = vec![
            0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC0, 0x2B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC0, 0x2C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0x00, 0x9E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
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
            0x00, 0x08, // Extension length: 8
            0x00, 0x06, // Groups length: 6
            0x00, 0x1D, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
        ]);

        // Extension: signature_algorithms
        client_hello.extend_from_slice(&[
            0x00, 0x0D, // Extension type: signature_algorithms
            0x00, 0x08, // Extension length: 8
            0x00, 0x06, // Algorithms length: 6
            0x04, 0x03, // rsa_pkcs1_sha256
            0x05, 0x03, // rsa_pkcs1_sha384
            0x06, 0x03, // rsa_pkcs1_sha512
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
        client_hello[length_pos..length_pos + 2]
            .copy_from_slice(&record_len.to_be_bytes());

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
        extension[list_len_pos..list_len_pos + 2]
            .copy_from_slice(&list_len.to_be_bytes());

        // Update Extension Length
        let ext_len = (extension.len() - ext_len_pos - 2) as u16;
        extension[ext_len_pos..ext_len_pos + 2]
            .copy_from_slice(&ext_len.to_be_bytes());

        extension
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let capture = ServerHelloNetworkCapture::new(target);
        let client_hello = capture.build_client_hello();

        // Should be a valid TLS record
        assert_eq!(client_hello[0], 0x16); // Handshake
        assert_eq!(client_hello[1], 0x03); // Version major
        assert_eq!(client_hello[2], 0x03); // Version minor (TLS 1.2)

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
        assert!(extension.windows(server_name.len())
            .any(|window| window == server_name));
    }
}
