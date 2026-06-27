// ClientHello network capture
// Captures ClientHello during actual TLS handshake

use crate::fingerprint::Ja3Fingerprint;
use crate::fingerprint::client_hello_capture::ClientHelloCapture;
use crate::utils::network::Target;
use crate::{Result, TlsError};

/// Build the canonical CipherRun ClientHello and derive its JA3 fingerprint.
pub struct ClientHelloNetworkCapture {
    target: Target,
}

impl ClientHelloNetworkCapture {
    /// Create new capture instance
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Build CipherRun's canonical ClientHello and compute its JA3 fingerprint.
    ///
    /// JA3 is a property of the *client*: it is the MD5 of the ClientHello's
    /// version, offered ciphers, extension list, supported groups, and EC point
    /// formats. It does not depend on the server's response, so it is derived
    /// deterministically from the ClientHello CipherRun presents rather than
    /// requiring a network round-trip. The SNI is filled from the target so the
    /// extension layout matches what would be sent to this host.
    pub async fn capture_and_fingerprint(&self) -> Result<(ClientHelloCapture, Ja3Fingerprint)> {
        let client_hello = self.build_client_hello()?;
        let ja3 = Ja3Fingerprint::from_client_hello(&client_hello)?;

        Ok((client_hello, ja3))
    }

    /// Build CipherRun's canonical ClientHello (a representative modern rustls
    /// client profile) used as the basis for the JA3 fingerprint.
    fn build_client_hello(&self) -> Result<ClientHelloCapture> {
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
        let sni_data = self.build_sni_extension()?;
        extensions.push((0, sni_data));

        // supported_groups - Extension 10
        let supported_groups = vec![
            29, // X25519
            23, // secp256r1
            24, // secp384r1
        ];
        extensions.push((
            10,
            Self::build_supported_groups_extension(&supported_groups)?,
        ));

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
        extensions.push((13, Self::build_signature_algorithms_extension(&sig_algs)?));

        // status_request (OCSP) - Extension 5
        extensions.push((5, vec![1, 0, 0, 0, 0]));

        // application_layer_protocol_negotiation - Extension 16
        extensions.push((16, Self::build_alpn_extension(&["h2", "http/1.1"])?));

        // supported_versions - Extension 43 (for TLS 1.3)
        extensions.push((43, vec![2, 0x03, 0x04])); // TLS 1.3

        // key_share - Extension 51 (for TLS 1.3)
        // Only the extension type contributes to JA3, so the key_share carries
        // an x25519 group header without the 32-byte key material; this hello is
        // never transmitted, it exists solely to derive the fingerprint.
        extensions.push((51, vec![0, 33, 0, 29, 0, 32]));

        Ok(ClientHelloCapture::synthetic(
            version,
            cipher_suites,
            extensions,
        ))
    }

    /// Build SNI extension data
    fn build_sni_extension(&self) -> Result<Vec<u8>> {
        let hostname = self.target.hostname.as_bytes();
        let mut data = Vec::new();
        let hostname_len = u16::try_from(hostname.len()).map_err(|_| TlsError::ParseError {
            message: "SNI hostname is too long".to_string(),
        })?;
        let list_len = hostname_len
            .checked_add(3)
            .ok_or_else(|| TlsError::ParseError {
                message: "SNI hostname is too long".to_string(),
            })?;

        // Server name list length
        data.extend_from_slice(&list_len.to_be_bytes());

        // Server name type (0 = hostname)
        data.push(0);

        // Server name length
        data.extend_from_slice(&hostname_len.to_be_bytes());

        // Server name
        data.extend_from_slice(hostname);

        Ok(data)
    }

    /// Build supported_groups extension data
    fn build_supported_groups_extension(groups: &[u16]) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let byte_len = groups
            .len()
            .checked_mul(2)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: "supported_groups list is too long".to_string(),
            })?;

        // List length
        data.extend_from_slice(&byte_len.to_be_bytes());

        // Groups
        for &group in groups {
            data.extend_from_slice(&group.to_be_bytes());
        }

        Ok(data)
    }

    /// Build signature_algorithms extension data
    fn build_signature_algorithms_extension(algorithms: &[u16]) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let byte_len = algorithms
            .len()
            .checked_mul(2)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or_else(|| TlsError::ParseError {
                message: "signature_algorithms list is too long".to_string(),
            })?;

        // List length
        data.extend_from_slice(&byte_len.to_be_bytes());

        // Algorithms
        for &alg in algorithms {
            data.extend_from_slice(&alg.to_be_bytes());
        }

        Ok(data)
    }

    /// Build ALPN extension data
    fn build_alpn_extension(protocols: &[&str]) -> Result<Vec<u8>> {
        let mut proto_bytes = Vec::new();

        for proto in protocols {
            let proto_len = u8::try_from(proto.len()).map_err(|_| TlsError::ParseError {
                message: "ALPN protocol name is too long".to_string(),
            })?;
            proto_bytes.push(proto_len);
            proto_bytes.extend_from_slice(proto.as_bytes());
        }

        let mut data = Vec::new();
        let protocols_len = u16::try_from(proto_bytes.len()).map_err(|_| TlsError::ParseError {
            message: "ALPN protocol list is too long".to_string(),
        })?;
        data.extend_from_slice(&protocols_len.to_be_bytes());
        data.extend_from_slice(&proto_bytes);

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_synthetic_client_hello() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let capture = ClientHelloNetworkCapture::new(target);
        let client_hello = capture
            .build_client_hello()
            .expect("ClientHello should build");

        // Verify basic structure
        assert_eq!(client_hello.version, 0x0303);
        assert!(!client_hello.cipher_suites.is_empty());
        assert!(!client_hello.extensions.is_empty());

        // Verify SNI is present
        let sni = client_hello.get_sni().expect("SNI should parse");
        assert!(sni.is_some());
        assert_eq!(sni.unwrap(), "example.com");

        // Verify supported groups
        let groups = client_hello
            .get_supported_groups()
            .expect("supported groups should parse");
        assert!(!groups.is_empty());
        assert!(groups.contains(&29)); // X25519

        // Generate JA3
        let ja3 =
            Ja3Fingerprint::from_client_hello(&client_hello).expect("ClientHello JA3 should parse");
        assert!(!ja3.ja3_hash.is_empty());
        assert_eq!(ja3.ja3_hash.len(), 32); // MD5 is 32 hex chars
    }
}
