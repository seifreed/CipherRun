// Pre-Handshake / Early Termination Module
// Implements fast certificate retrieval by disconnecting after ServerHello
// Benefits: 2-3x faster than full handshake, works with TLS 1.0-1.2

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use crate::error::TlsError;
use crate::utils::network::Target;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Pre-handshake scanner for fast certificate retrieval
pub struct PreHandshakeScanner {
    target: Target,
    timeout_duration: Duration,
}

impl PreHandshakeScanner {
    /// Create new pre-handshake scanner
    pub fn new(target: Target) -> Self {
        Self {
            target,
            timeout_duration: Duration::from_secs(10),
        }
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, timeout_duration: Duration) -> Self {
        self.timeout_duration = timeout_duration;
        self
    }

    /// Perform pre-handshake scan - early termination after ServerHello
    pub async fn scan_pre_handshake(&self) -> Result<PreHandshakeScanResult> {
        let start_time = Instant::now();

        // 1. Connect to target
        let addr = format!("{}:{}", self.target.hostname, self.target.port);
        let mut stream = timeout(self.timeout_duration, TcpStream::connect(&addr))
            .await
            .map_err(|_| TlsError::Timeout {
                duration: self.timeout_duration,
            })?
            .map_err(|e| TlsError::IoError { source: e })?;

        // 2. Build and send ClientHello
        let client_hello = self.build_client_hello()?;
        stream
            .write_all(&client_hello)
            .await
            .map_err(|e| TlsError::IoError { source: e })?;

        // 3. Receive ServerHello + Certificate
        let mut response_buffer = vec![0u8; 16384]; // 16KB buffer for handshake
        let bytes_read = timeout(self.timeout_duration, stream.read(&mut response_buffer))
            .await
            .map_err(|_| TlsError::Timeout {
                duration: self.timeout_duration,
            })?
            .map_err(|e| TlsError::IoError { source: e })?;

        if bytes_read == 0 {
            return Err(TlsError::ConnectionClosed {
                details: "Server closed connection before sending ServerHello".to_string(),
            });
        }

        let response_data = &response_buffer[..bytes_read];

        // 4. Parse handshake messages (ServerHello, Certificate, ServerHelloDone)
        let parse_result = self.parse_handshake_response(response_data)?;

        // 5. Disconnect immediately (no cipher negotiation)
        drop(stream); // TCP RST sent here

        let elapsed = start_time.elapsed();

        Ok(PreHandshakeScanResult {
            success: true,
            certificate_data: parse_result.certificate_data,
            server_hello_data: parse_result.server_hello_data,
            handshake_time_ms: elapsed.as_millis() as u64,
            protocol_version: parse_result.protocol_version,
            cipher_suite: parse_result.cipher_suite,
            compression_method: parse_result.compression_method,
        })
    }

    /// Build TLS ClientHello message
    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut client_hello = Vec::new();

        // TLS Record Layer Header
        client_hello.push(0x16); // Handshake content type
        client_hello.push(0x03); // TLS version major (3)
        client_hello.push(0x01); // TLS version minor (1 = TLS 1.0)

        // Placeholder for record length (will be filled later)
        let record_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]);

        // Handshake Protocol - ClientHello
        client_hello.push(0x01); // ClientHello type

        // Placeholder for handshake length (will be filled later)
        let handshake_length_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello body
        client_hello.push(0x03); // Version major
        client_hello.push(0x03); // Version minor (3 = TLS 1.2)

        // Random (32 bytes)
        let random = self.generate_client_random();
        client_hello.extend_from_slice(&random);

        // Session ID (empty)
        client_hello.push(0x00);

        // Cipher Suites
        let cipher_suites = self.get_cipher_suites();
        let cipher_suites_len = (cipher_suites.len() * 2) as u16;
        client_hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for cipher in cipher_suites {
            client_hello.extend_from_slice(&cipher.to_be_bytes());
        }

        // Compression Methods
        client_hello.push(0x01); // Length
        client_hello.push(0x00); // NULL compression

        // Extensions
        let extensions = self.build_extensions()?;
        let extensions_len = extensions.len() as u16;
        client_hello.extend_from_slice(&extensions_len.to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        // Update lengths
        let handshake_body_len = client_hello.len() - handshake_length_pos - 3;
        client_hello[handshake_length_pos] = ((handshake_body_len >> 16) & 0xFF) as u8;
        client_hello[handshake_length_pos + 1] = ((handshake_body_len >> 8) & 0xFF) as u8;
        client_hello[handshake_length_pos + 2] = (handshake_body_len & 0xFF) as u8;

        let record_body_len = client_hello.len() - record_length_pos - 2;
        client_hello[record_length_pos] = ((record_body_len >> 8) & 0xFF) as u8;
        client_hello[record_length_pos + 1] = (record_body_len & 0xFF) as u8;

        Ok(client_hello)
    }

    /// Generate 32-byte client random
    fn generate_client_random(&self) -> [u8; 32] {
        use rand::RngCore;
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);
        random
    }

    /// Get cipher suites for ClientHello
    fn get_cipher_suites(&self) -> Vec<u16> {
        vec![
            // TLS 1.3 ciphers
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            // TLS 1.2 ciphers (ECDHE)
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            // Older ciphers for compatibility
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        ]
    }

    /// Build TLS extensions
    fn build_extensions(&self) -> Result<Vec<u8>> {
        let mut extensions = Vec::new();

        // Server Name Indication (SNI)
        let sni_ext = self.build_sni_extension();
        extensions.extend_from_slice(&sni_ext);

        // Supported Groups (curves)
        extensions.extend_from_slice(&[
            0x00, 0x0a, // Extension type: supported_groups
            0x00, 0x0c, // Length: 12
            0x00, 0x0a, // List length: 10
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
            0x00, 0x19, // secp521r1
            0x01, 0x00, // ffdhe2048
        ]);

        // Signature Algorithms
        extensions.extend_from_slice(&[
            0x00, 0x0d, // Extension type: signature_algorithms
            0x00, 0x1e, // Length: 30
            0x00, 0x1c, // List length: 28
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x06, 0x03, // ecdsa_secp521r1_sha512
            0x08, 0x07, // ed25519
            0x08, 0x08, // ed448
            0x08, 0x09, // rsa_pss_pss_sha256
            0x08, 0x0a, // rsa_pss_pss_sha384
            0x08, 0x0b, // rsa_pss_pss_sha512
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x06, 0x01, // rsa_pkcs1_sha512
        ]);

        // Extended Master Secret
        extensions.extend_from_slice(&[
            0x00, 0x17, // Extension type: extended_master_secret
            0x00, 0x00, // Length: 0
        ]);

        // Session Ticket
        extensions.extend_from_slice(&[
            0x00, 0x23, // Extension type: session_ticket
            0x00, 0x00, // Length: 0
        ]);

        // Supported Versions (TLS 1.3, 1.2, 1.1, 1.0)
        extensions.extend_from_slice(&[
            0x00, 0x2b, // Extension type: supported_versions
            0x00, 0x09, // Length: 9
            0x08, // List length: 8
            0x03, 0x04, // TLS 1.3
            0x03, 0x03, // TLS 1.2
            0x03, 0x02, // TLS 1.1
            0x03, 0x01, // TLS 1.0
        ]);

        Ok(extensions)
    }

    /// Build SNI extension
    fn build_sni_extension(&self) -> Vec<u8> {
        let hostname = self.target.hostname.as_bytes();
        let hostname_len = hostname.len() as u16;
        let list_len = hostname_len + 3;
        let ext_len = list_len + 2;

        let mut sni = Vec::new();
        sni.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        sni.extend_from_slice(&ext_len.to_be_bytes()); // Extension length
        sni.extend_from_slice(&list_len.to_be_bytes()); // Server name list length
        sni.push(0x00); // Name type: host_name
        sni.extend_from_slice(&hostname_len.to_be_bytes()); // Hostname length
        sni.extend_from_slice(hostname); // Hostname

        sni
    }

    /// Parse handshake response (ServerHello, Certificate, etc.)
    fn parse_handshake_response(&self, data: &[u8]) -> Result<HandshakeParseResult> {
        let mut offset = 0;
        let mut certificate_data = None;
        let mut server_hello_data = None;
        let mut protocol_version = None;
        let mut cipher_suite = None;
        let mut compression_method = None;

        while offset < data.len() {
            // Check if we have enough data for record header
            if offset + 5 > data.len() {
                break;
            }

            // Parse TLS record header
            let content_type = data[offset];
            let _version_major = data[offset + 1];
            let _version_minor = data[offset + 2];
            let record_length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

            offset += 5;

            // Check if we have the full record
            if offset + record_length > data.len() {
                break;
            }

            // Only process Handshake records (0x16)
            if content_type != 0x16 {
                offset += record_length;
                continue;
            }

            // Parse handshake messages within this record
            let record_end = offset + record_length;
            while offset < record_end {
                if offset + 4 > data.len() {
                    break;
                }

                let handshake_type = data[offset];
                let handshake_length =
                    u32::from_be_bytes([0, data[offset + 1], data[offset + 2], data[offset + 3]])
                        as usize;

                offset += 4;

                if offset + handshake_length > data.len() {
                    break;
                }

                match handshake_type {
                    0x02 => {
                        // ServerHello
                        if handshake_length >= 38 {
                            let version_maj = data[offset];
                            let version_min = data[offset + 1];
                            protocol_version = Some(format!("{}.{}", version_maj - 2, version_min));

                            // Skip random (32 bytes)
                            let cipher_offset = offset + 34;
                            if cipher_offset + 2 <= offset + handshake_length {
                                let cipher = u16::from_be_bytes([
                                    data[cipher_offset],
                                    data[cipher_offset + 1],
                                ]);
                                cipher_suite = Some(format!("0x{:04x}", cipher));

                                if cipher_offset + 3 <= offset + handshake_length {
                                    compression_method = Some(data[cipher_offset + 2]);
                                }
                            }

                            server_hello_data =
                                Some(data[offset..offset + handshake_length].to_vec());
                        }
                    }
                    0x0b => {
                        // Certificate
                        if handshake_length >= 3 {
                            let certs_length = u32::from_be_bytes([
                                0,
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                            ]) as usize;

                            let mut cert_offset = offset + 3;
                            let certs_end = offset + 3 + certs_length;

                            // Parse first certificate (leaf)
                            if cert_offset + 3 <= certs_end && cert_offset + 3 <= data.len() {
                                let cert_length = u32::from_be_bytes([
                                    0,
                                    data[cert_offset],
                                    data[cert_offset + 1],
                                    data[cert_offset + 2],
                                ]) as usize;
                                cert_offset += 3;

                                if cert_offset + cert_length <= data.len() {
                                    let cert_der = &data[cert_offset..cert_offset + cert_length];
                                    certificate_data = self.parse_certificate(cert_der).ok();
                                }
                            }
                        }
                    }
                    _ => {
                        // Other handshake messages - skip
                    }
                }

                offset += handshake_length;
            }
        }

        Ok(HandshakeParseResult {
            certificate_data,
            server_hello_data,
            protocol_version,
            cipher_suite,
            compression_method,
        })
    }

    /// Parse X.509 certificate from DER format
    fn parse_certificate(&self, der: &[u8]) -> Result<CertificateInfo> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der).map_err(|e| TlsError::ParseError {
            message: format!("Failed to parse certificate: {:?}", e),
        })?;

        // Extract basic certificate information
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let not_before = cert
            .validity()
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|e| e);
        let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_else(|e| e);
        let serial_number = cert.serial.to_string();

        // Extract SANs
        let mut san = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    san.push(dns.to_string());
                }
            }
        }

        // Get signature algorithm
        let signature_algorithm = format!("{}", cert.signature_algorithm.algorithm);

        // Get public key info
        let public_key_algorithm = format!("{}", cert.public_key().algorithm.algorithm);
        let public_key_size = cert
            .public_key()
            .parsed()
            .map(|pk| match pk {
                x509_parser::public_key::PublicKey::RSA(rsa) => Some(rsa.key_size()),
                _ => None,
            })
            .ok()
            .flatten();

        Ok(CertificateInfo {
            subject,
            issuer,
            not_before,
            not_after,
            serial_number,
            san,
            signature_algorithm,
            public_key_algorithm,
            public_key_size,
            ..Default::default()
        })
    }
}

/// Result of pre-handshake scan
#[derive(Debug, Clone)]
pub struct PreHandshakeScanResult {
    pub success: bool,
    pub certificate_data: Option<CertificateInfo>,
    pub server_hello_data: Option<Vec<u8>>,
    pub handshake_time_ms: u64,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub compression_method: Option<u8>,
}

/// Internal struct for parsing handshake
struct HandshakeParseResult {
    certificate_data: Option<CertificateInfo>,
    server_hello_data: Option<Vec<u8>>,
    protocol_version: Option<String>,
    cipher_suite: Option<String>,
    compression_method: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let scanner = PreHandshakeScanner::new(target);
        let client_hello = scanner.build_client_hello().unwrap();

        // Verify record header
        assert_eq!(client_hello[0], 0x16); // Handshake
        assert_eq!(client_hello[1], 0x03); // TLS major version
        assert_eq!(client_hello[2], 0x01); // TLS 1.0 for compatibility

        // Verify handshake type
        assert_eq!(client_hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_sni_extension() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let scanner = PreHandshakeScanner::new(target);
        let sni = scanner.build_sni_extension();

        // Verify SNI extension structure
        assert_eq!(sni[0], 0x00);
        assert_eq!(sni[1], 0x00); // SNI extension type
        assert!(sni.len() > 4);
    }
}
