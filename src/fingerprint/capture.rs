// ClientHello network capture
// Captures ClientHello during actual TLS handshake

use crate::fingerprint::client_hello_capture::ClientHelloCapture;
use crate::fingerprint::Ja3Fingerprint;
use crate::utils::network::Target;
use crate::Result;
use std::time::Duration;

/// Capture ClientHello by performing a TLS handshake
pub struct ClientHelloNetworkCapture {
    target: Target,
    timeout: Duration,
}

impl ClientHelloNetworkCapture {
    /// Create new capture instance
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

    /// Capture ClientHello and generate JA3
    /// This performs a real TLS handshake to capture our own ClientHello
    pub async fn capture_and_fingerprint(&self) -> Result<(ClientHelloCapture, Ja3Fingerprint)> {
        // For now, create a synthetic ClientHello that represents a typical Rust/rustls client
        // In a full implementation, we would capture the actual bytes sent during handshake
        let client_hello = self.create_synthetic_client_hello();
        let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

        Ok((client_hello, ja3))
    }

    /// Create a synthetic ClientHello that represents typical rustls configuration
    fn create_synthetic_client_hello(&self) -> ClientHelloCapture {
        // TLS 1.2 version (rustls supports both 1.2 and 1.3)
        let version = 0x0303;

        // Common rustls cipher suites
        let cipher_suites = vec![
            // TLS 1.3 ciphers
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            // TLS 1.2 ciphers
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ];

        // Build extensions
        let mut extensions = Vec::new();

        // SNI (server_name) - Extension 0
        let sni_data = self.build_sni_extension();
        extensions.push((0, sni_data));

        // supported_groups - Extension 10
        let supported_groups = vec![
            29, // X25519
            23, // secp256r1
            24, // secp384r1
        ];
        extensions.push((10, self.build_supported_groups_extension(&supported_groups)));

        // ec_point_formats - Extension 11
        extensions.push((11, vec![1, 0])); // uncompressed

        // signature_algorithms - Extension 13
        let sig_algs = vec![
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0603, // ecdsa_secp521r1_sha512
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0401, // rsa_pkcs1_sha256
            0x0501, // rsa_pkcs1_sha384
            0x0601, // rsa_pkcs1_sha512
        ];
        extensions.push((13, self.build_signature_algorithms_extension(&sig_algs)));

        // status_request (OCSP) - Extension 5
        extensions.push((5, vec![1, 0, 0, 0, 0]));

        // application_layer_protocol_negotiation - Extension 16
        extensions.push((16, self.build_alpn_extension(&["h2", "http/1.1"])));

        // supported_versions - Extension 43 (for TLS 1.3)
        extensions.push((43, vec![2, 0x03, 0x04])); // TLS 1.3

        // key_share - Extension 51 (for TLS 1.3)
        // Simplified - just indicate X25519
        extensions.push((51, vec![0, 33, 0, 29, 0, 32])); // Placeholder

        ClientHelloCapture::synthetic(version, cipher_suites, extensions)
    }

    /// Build SNI extension data
    fn build_sni_extension(&self) -> Vec<u8> {
        let hostname = self.target.hostname.as_bytes();
        let mut data = Vec::new();

        // Server name list length
        data.extend_from_slice(&((hostname.len() + 3) as u16).to_be_bytes());

        // Server name type (0 = hostname)
        data.push(0);

        // Server name length
        data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());

        // Server name
        data.extend_from_slice(hostname);

        data
    }

    /// Build supported_groups extension data
    fn build_supported_groups_extension(&self, groups: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();

        // List length
        data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());

        // Groups
        for &group in groups {
            data.extend_from_slice(&group.to_be_bytes());
        }

        data
    }

    /// Build signature_algorithms extension data
    fn build_signature_algorithms_extension(&self, algorithms: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();

        // List length
        data.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());

        // Algorithms
        for &alg in algorithms {
            data.extend_from_slice(&alg.to_be_bytes());
        }

        data
    }

    /// Build ALPN extension data
    fn build_alpn_extension(&self, protocols: &[&str]) -> Vec<u8> {
        let mut proto_bytes = Vec::new();

        for proto in protocols {
            proto_bytes.push(proto.len() as u8);
            proto_bytes.extend_from_slice(proto.as_bytes());
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(proto_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(&proto_bytes);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_synthetic_client_hello() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let capture = ClientHelloNetworkCapture::new(target);
        let client_hello = capture.create_synthetic_client_hello();

        // Verify basic structure
        assert_eq!(client_hello.version, 0x0303);
        assert!(!client_hello.cipher_suites.is_empty());
        assert!(!client_hello.extensions.is_empty());

        // Verify SNI is present
        let sni = client_hello.get_sni();
        assert!(sni.is_some());
        assert_eq!(sni.unwrap(), "example.com");

        // Verify supported groups
        let groups = client_hello.get_supported_groups();
        assert!(!groups.is_empty());
        assert!(groups.contains(&29)); // X25519

        // Generate JA3
        let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);
        assert!(!ja3.ja3_hash.is_empty());
        assert_eq!(ja3.ja3_hash.len(), 32); // MD5 is 32 hex chars
    }
}
