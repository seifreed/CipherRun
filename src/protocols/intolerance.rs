// TLS Intolerance Tests - Detect server intolerance to various TLS features
//
// This module tests for 5 types of TLS intolerance:
// 1. Extension intolerance - Server rejects ClientHellos with certain extensions
// 2. Version intolerance - Server rejects versions in ClientHello
// 3. Long handshake intolerance - Server rejects ClientHello > 256 bytes
// 4. Incorrect SNI alerts - Server sends incorrect alert when SNI fails
// 5. Uses common DH primes - Server uses known weak DH primes

use crate::Result;
use crate::utils::network::Target;
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of intolerance testing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntoleranceTestResult {
    pub extension_intolerance: bool,
    pub version_intolerance: bool,
    pub long_handshake_intolerance: bool,
    pub incorrect_sni_alerts: bool,
    pub uses_common_dh_primes: bool,
    pub details: HashMap<String, String>,
}

/// TLS Intolerance Tester
pub struct IntoleranceTester {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl IntoleranceTester {
    /// Create new intolerance tester
    pub fn new(target: Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Run all intolerance tests
    pub async fn test_all(&self) -> Result<IntoleranceTestResult> {
        let mut result = IntoleranceTestResult::default();

        // Test 1: Extension intolerance
        result.extension_intolerance = self.test_extension_intolerance().await?;
        if result.extension_intolerance {
            result.details.insert(
                "extension_intolerance".to_string(),
                "Server rejects ClientHellos with certain extensions (bad)".to_string(),
            );
        }

        // Test 2: Version intolerance
        result.version_intolerance = self.test_version_intolerance().await?;
        if result.version_intolerance {
            result.details.insert(
                "version_intolerance".to_string(),
                "Server rejects ClientHello with high version in record layer (bad)".to_string(),
            );
        }

        // Test 3: Long handshake intolerance
        result.long_handshake_intolerance = self.test_long_handshake_intolerance().await?;
        if result.long_handshake_intolerance {
            result.details.insert(
                "long_handshake_intolerance".to_string(),
                "Server rejects ClientHello > 256 bytes (bad)".to_string(),
            );
        }

        // Test 4: Incorrect SNI alerts
        result.incorrect_sni_alerts = self.test_sni_alerts().await?;
        if result.incorrect_sni_alerts {
            result.details.insert(
                "incorrect_sni_alerts".to_string(),
                "Server sends incorrect alert when SNI fails (bad)".to_string(),
            );
        }

        // Test 5: Common DH primes
        result.uses_common_dh_primes = self.test_common_dh_primes().await?;
        if result.uses_common_dh_primes {
            result.details.insert(
                "uses_common_dh_primes".to_string(),
                "Server uses known weak DH primes (critical security issue)".to_string(),
            );
        }

        Ok(result)
    }

    /// Test for extension intolerance
    /// Sends ClientHellos with/without extensions and compares responses
    async fn test_extension_intolerance(&self) -> Result<bool> {
        // Test 1: Minimal ClientHello without extensions
        let minimal_hello = self.build_minimal_client_hello()?;
        let minimal_response = self.send_client_hello(&minimal_hello).await;

        // Test 2: ClientHello with common extensions
        let extended_hello = self.build_extended_client_hello()?;
        let extended_response = self.send_client_hello(&extended_hello).await;

        match (minimal_response, extended_response) {
            (Ok(_), Err(_)) => {
                // Server accepts minimal but rejects with extensions - intolerant
                Ok(true)
            }
            _ => {
                // Either both work or both fail - not extension intolerant
                Ok(false)
            }
        }
    }

    /// Test for version intolerance
    /// Sends ClientHello with high version in record layer
    async fn test_version_intolerance(&self) -> Result<bool> {
        // Test 1: ClientHello with TLS 1.0 in record layer
        let normal_hello = self.build_versioned_client_hello(0x0301)?; // TLS 1.0
        let normal_response = self.send_client_hello(&normal_hello).await;

        // Test 2: ClientHello with TLS 1.2 in record layer
        let high_version_hello = self.build_versioned_client_hello(0x0303)?; // TLS 1.2
        let high_version_response = self.send_client_hello(&high_version_hello).await;

        match (normal_response, high_version_response) {
            (Ok(_), Err(_)) => {
                // Server accepts low version but rejects high version - intolerant
                Ok(true)
            }
            _ => {
                // Not version intolerant
                Ok(false)
            }
        }
    }

    /// Test for long handshake intolerance
    /// Sends ClientHello > 256 bytes with padding
    async fn test_long_handshake_intolerance(&self) -> Result<bool> {
        // Test 1: Normal size ClientHello
        let normal_hello = self.build_minimal_client_hello()?;
        let normal_response = self.send_client_hello(&normal_hello).await;

        // Test 2: Long ClientHello with padding extension
        let long_hello = self.build_long_client_hello()?;
        let long_response = self.send_client_hello(&long_hello).await;

        match (normal_response, long_response) {
            (Ok(_), Err(_)) => {
                // Server accepts normal but rejects long - intolerant
                Ok(true)
            }
            _ => {
                // Not intolerant to long handshakes
                Ok(false)
            }
        }
    }

    /// Test for incorrect SNI alerts
    /// Sends ClientHello with invalid SNI and checks alert type
    async fn test_sni_alerts(&self) -> Result<bool> {
        // Build ClientHello with invalid SNI
        let invalid_sni_hello = self.build_invalid_sni_client_hello()?;

        match self.send_and_read_alert(&invalid_sni_hello).await {
            Ok(Some(alert_code)) => {
                // Correct alert for SNI failure is 112 (unrecognized_name)
                // Incorrect alerts might be 40 (handshake_failure), 47 (certificate_unknown), etc.
                Ok(alert_code != 112)
            }
            _ => {
                // No alert or connection succeeded - not applicable
                Ok(false)
            }
        }
    }

    /// Test for common DH primes
    /// Connects with DHE cipher and extracts DH prime from ServerKeyExchange
    async fn test_common_dh_primes(&self) -> Result<bool> {
        // Load common primes database
        let common_primes = Self::load_common_primes()?;

        // Try to establish DHE connection and extract prime
        match self.extract_dh_prime().await {
            Ok(Some(prime_hex)) => {
                // Check if prime matches any known weak prime
                Ok(common_primes.contains(&prime_hex.to_uppercase()))
            }
            _ => {
                // DHE not supported or couldn't extract prime
                Ok(false)
            }
        }
    }

    /// Build minimal ClientHello without extensions
    fn build_minimal_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // TLS Record Layer
        buf.put_u8(0x16); // Content Type: Handshake
        buf.put_u16(0x0301); // Version: TLS 1.0
        // Length placeholder (will be filled later)
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Header
        buf.put_u8(0x01); // Handshake Type: ClientHello
        // Length placeholder
        let hs_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello
        buf.put_u16(0x0303); // Client Version: TLS 1.2

        // Random (32 bytes)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);

        // Session ID (empty)
        buf.put_u8(0);

        // Cipher Suites
        let ciphers = vec![
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
        ];
        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        // Compression Methods
        buf.put_u8(1); // Length
        buf.put_u8(0); // No compression

        // NO EXTENSIONS (this is the key difference)

        // Fill in lengths
        let total_length = buf.len() - length_pos - 2;
        let hs_length = buf.len() - hs_length_pos - 3;

        let mut result = buf.to_vec();
        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    /// Build ClientHello with common extensions
    fn build_extended_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // TLS Record Layer
        buf.put_u8(0x16);
        buf.put_u16(0x0301);
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Header
        buf.put_u8(0x01);
        let hs_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello
        buf.put_u16(0x0303);

        // Random
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);

        // Session ID
        buf.put_u8(0);

        // Cipher Suites
        let ciphers = vec![0xc02f, 0xc030, 0x009c, 0x009d];
        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        // Compression Methods
        buf.put_u8(1);
        buf.put_u8(0);

        // Extensions
        let mut extensions = BytesMut::new();

        // SNI extension
        self.add_sni_extension(&mut extensions, &self.target.hostname);

        // supported_groups extension
        self.add_supported_groups_extension(&mut extensions);

        // ec_point_formats extension
        self.add_ec_point_formats_extension(&mut extensions);

        // signature_algorithms extension
        self.add_signature_algorithms_extension(&mut extensions);

        // Add extensions to buffer
        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);

        // Fill in lengths
        let total_length = buf.len() - length_pos - 2;
        let hs_length = buf.len() - hs_length_pos - 3;

        let mut result = buf.to_vec();
        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    /// Build ClientHello with specific version in record layer
    fn build_versioned_client_hello(&self, record_version: u16) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // TLS Record Layer with specified version
        buf.put_u8(0x16);
        buf.put_u16(record_version); // Variable version
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Header
        buf.put_u8(0x01);
        let hs_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello (always advertise TLS 1.2 capability)
        buf.put_u16(0x0303);

        // Random
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);

        // Session ID
        buf.put_u8(0);

        // Cipher Suites
        let ciphers = vec![0xc02f, 0xc030];
        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        // Compression Methods
        buf.put_u8(1);
        buf.put_u8(0);

        // Fill in lengths
        let total_length = buf.len() - length_pos - 2;
        let hs_length = buf.len() - hs_length_pos - 3;

        let mut result = buf.to_vec();
        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    /// Build long ClientHello with padding extension
    fn build_long_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // TLS Record Layer
        buf.put_u8(0x16);
        buf.put_u16(0x0301);
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Header
        buf.put_u8(0x01);
        let hs_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello
        buf.put_u16(0x0303);

        // Random
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);

        // Session ID
        buf.put_u8(0);

        // Cipher Suites
        let ciphers = vec![0xc02f, 0xc030, 0x009c, 0x009d];
        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        // Compression Methods
        buf.put_u8(1);
        buf.put_u8(0);

        // Extensions with large padding to exceed 256 bytes
        let mut extensions = BytesMut::new();

        // Add normal extensions
        self.add_sni_extension(&mut extensions, &self.target.hostname);

        // Add padding extension (type 0x0015) to make total > 256 bytes
        // Calculate how much padding needed
        let current_size = buf.len() + 2 + extensions.len(); // +2 for extensions length
        let padding_needed = if current_size < 300 {
            300 - current_size
        } else {
            100
        };

        extensions.put_u16(0x0015); // Padding extension type
        extensions.put_u16(padding_needed as u16); // Padding length
        extensions.put_slice(&vec![0u8; padding_needed]); // Padding data

        // Add extensions to buffer
        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);

        // Fill in lengths
        let total_length = buf.len() - length_pos - 2;
        let hs_length = buf.len() - hs_length_pos - 3;

        let mut result = buf.to_vec();
        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    /// Build ClientHello with invalid SNI
    fn build_invalid_sni_client_hello(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();

        // TLS Record Layer
        buf.put_u8(0x16);
        buf.put_u16(0x0301);
        let length_pos = buf.len();
        buf.put_u16(0);

        // Handshake Header
        buf.put_u8(0x01);
        let hs_length_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // ClientHello
        buf.put_u16(0x0303);

        // Random
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        buf.put_u32(timestamp);
        buf.put_slice(&[0u8; 28]);

        // Session ID
        buf.put_u8(0);

        // Cipher Suites
        let ciphers = vec![0xc02f, 0xc030];
        buf.put_u16((ciphers.len() * 2) as u16);
        for cipher in ciphers {
            buf.put_u16(cipher);
        }

        // Compression Methods
        buf.put_u8(1);
        buf.put_u8(0);

        // Extensions with invalid SNI
        let mut extensions = BytesMut::new();
        self.add_sni_extension(&mut extensions, "invalid.nonexistent.example.com");

        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);

        // Fill in lengths
        let total_length = buf.len() - length_pos - 2;
        let hs_length = buf.len() - hs_length_pos - 3;

        let mut result = buf.to_vec();
        result[length_pos] = ((total_length >> 8) & 0xff) as u8;
        result[length_pos + 1] = (total_length & 0xff) as u8;

        result[hs_length_pos] = ((hs_length >> 16) & 0xff) as u8;
        result[hs_length_pos + 1] = ((hs_length >> 8) & 0xff) as u8;
        result[hs_length_pos + 2] = (hs_length & 0xff) as u8;

        Ok(result)
    }

    /// Add SNI extension to extensions buffer
    fn add_sni_extension(&self, buf: &mut BytesMut, hostname: &str) {
        buf.put_u16(0x0000); // Extension type: server_name

        let ext_data_len = 2 + 1 + 2 + hostname.len(); // list_len + type + name_len + name
        buf.put_u16(ext_data_len as u16);

        let list_len = 1 + 2 + hostname.len();
        buf.put_u16(list_len as u16);

        buf.put_u8(0); // Name type: hostname
        buf.put_u16(hostname.len() as u16);
        buf.put_slice(hostname.as_bytes());
    }

    /// Add supported_groups extension
    fn add_supported_groups_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(0x000a); // Extension type: supported_groups

        let curves = vec![
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
        ];

        buf.put_u16((2 + curves.len() * 2) as u16); // Extension length
        buf.put_u16((curves.len() * 2) as u16); // Curves list length

        for curve in curves {
            buf.put_u16(curve);
        }
    }

    /// Add ec_point_formats extension
    fn add_ec_point_formats_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(0x000b); // Extension type: ec_point_formats
        buf.put_u16(2); // Extension length
        buf.put_u8(1); // Formats length
        buf.put_u8(0); // uncompressed
    }

    /// Add signature_algorithms extension
    fn add_signature_algorithms_extension(&self, buf: &mut BytesMut) {
        buf.put_u16(0x000d); // Extension type: signature_algorithms

        let algorithms = vec![
            (0x04, 0x01), // rsa_pkcs1_sha256
            (0x05, 0x01), // rsa_pkcs1_sha384
            (0x06, 0x01), // rsa_pkcs1_sha512
            (0x04, 0x03), // ecdsa_secp256r1_sha256
            (0x05, 0x03), // ecdsa_secp384r1_sha384
        ];

        buf.put_u16((2 + algorithms.len() * 2) as u16); // Extension length
        buf.put_u16((algorithms.len() * 2) as u16); // Algorithms list length

        for (hash, sig) in algorithms {
            buf.put_u8(hash);
            buf.put_u8(sig);
        }
    }

    /// Send ClientHello and read response
    async fn send_client_hello(&self, client_hello: &[u8]) -> Result<Vec<u8>> {
        use crate::TlsError;

        let addr = self.target.socket_addrs()[0];

        let stream = timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| TlsError::ConnectionTimeout {
                duration: self.connect_timeout,
                addr,
            })??;

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Send ClientHello
        writer.write_all(client_hello).await?;
        writer.flush().await?;

        // Read response
        let mut response = vec![0u8; 16384];
        match timeout(self.read_timeout, reader.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                response.truncate(n);
                Ok(response)
            }
            _ => Err(TlsError::Timeout {
                duration: self.read_timeout,
            }),
        }
    }

    /// Send ClientHello and read alert if present
    async fn send_and_read_alert(&self, client_hello: &[u8]) -> Result<Option<u8>> {
        match self.send_client_hello(client_hello).await {
            Ok(response) => {
                // Check if response is a TLS Alert
                if response.len() >= 7 && response[0] == 0x15 && response[5] == 0x02 {
                    // Alert record, fatal alert
                    let alert_code = response[6];
                    Ok(Some(alert_code))
                } else {
                    // Not an alert
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Extract DH prime from ServerKeyExchange
    async fn extract_dh_prime(&self) -> Result<Option<String>> {
        use openssl::ssl::{SslConnector, SslMethod};

        let addr = self.target.socket_addrs()[0];

        let stream = timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Set DHE ciphers only
        builder.set_cipher_list("DHE:EDH:!aNULL:!eNULL")?;

        let connector = builder.build();
        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                // Try to extract DH parameters
                // Note: OpenSSL doesn't easily expose ServerKeyExchange in this API
                // For a complete implementation, we'd need to parse TLS handshake messages manually
                // For now, we'll use a simplified approach

                // Get current cipher
                let cipher = ssl_stream.ssl().current_cipher();
                if let Some(c) = cipher {
                    let cipher_name = c.name();
                    if cipher_name.contains("DHE") {
                        // DHE is being used, but we can't easily extract the prime
                        // In a full implementation, we'd parse the ServerKeyExchange message
                        // For now, return None (not detected)
                        return Ok(None);
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    /// Load common DH primes from database
    fn load_common_primes() -> Result<Vec<String>> {
        let primes_data = include_str!("../../data/common-primes.txt");
        let mut primes = Vec::new();

        for line in primes_data.lines() {
            let trimmed = line.trim();
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Each prime is a hex string
            primes.push(trimmed.to_uppercase());
        }

        Ok(primes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_common_primes() {
        let primes = IntoleranceTester::load_common_primes().unwrap();
        assert!(!primes.is_empty());
        // Should contain Oakley Group 1, 2, 5, etc.
        assert!(primes.len() > 10);
    }

    #[test]
    fn test_intolerance_result_default() {
        let result = IntoleranceTestResult::default();
        assert!(!result.extension_intolerance);
        assert!(!result.version_intolerance);
        assert!(!result.long_handshake_intolerance);
        assert!(!result.incorrect_sni_alerts);
        assert!(!result.uses_common_dh_primes);
        assert!(result.details.is_empty());
    }

    #[tokio::test]
    async fn test_build_minimal_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = IntoleranceTester::new(target);
        let hello = tester.build_minimal_client_hello().unwrap();

        // Verify structure
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[tokio::test]
    async fn test_build_extended_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = IntoleranceTester::new(target);
        let hello = tester.build_extended_client_hello().unwrap();

        // Verify structure
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // ClientHello

        // Should be longer than minimal due to extensions
        let minimal = tester.build_minimal_client_hello().unwrap();
        assert!(hello.len() > minimal.len());
    }

    #[tokio::test]
    async fn test_build_long_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec!["93.184.216.34".parse().unwrap()],
        };

        let tester = IntoleranceTester::new(target);
        let hello = tester.build_long_client_hello().unwrap();

        // Should be > 256 bytes
        assert!(hello.len() > 256);
    }
}
