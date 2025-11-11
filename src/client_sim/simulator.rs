// Client Simulator - Simulates TLS connections from various clients

use crate::Result;
use crate::data::client_data::{CLIENT_DB, ClientProfile};
use crate::protocols::Protocol;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Extended handshake information
#[derive(Debug, Clone)]
struct HandshakeInfo {
    protocol: Protocol,
    cipher: Option<String>,
    alpn: Option<String>,
    key_exchange: Option<String>,
    certificate_type: Option<String>,
}

/// Client simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSimulationResult {
    pub client_name: String,
    pub client_id: String,
    pub success: bool,
    pub protocol: Option<Protocol>,
    pub cipher: Option<String>,
    pub error: Option<String>,
    pub handshake_time_ms: Option<u64>,
    /// ALPN protocol negotiated (e.g., "h2", "http/1.1", "h3")
    pub alpn: Option<String>,
    /// Key exchange algorithm (e.g., "ECDH x25519", "DH 2048", "RSA")
    pub key_exchange: Option<String>,
    /// Whether the cipher suite provides forward secrecy
    pub forward_secrecy: bool,
    /// Certificate type and key information (e.g., "RSA 2048 (SHA256)", "ECDSA P-256")
    pub certificate_type: Option<String>,
}

/// Client simulator
pub struct ClientSimulator {
    target: Target,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl ClientSimulator {
    /// Create new client simulator
    pub fn new(target: Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Simulate all current clients
    pub async fn simulate_all_clients(&self) -> Result<Vec<ClientSimulationResult>> {
        let clients = CLIENT_DB.current_clients();
        let mut results = Vec::new();

        for client in clients {
            let result = self.simulate_client(client).await;
            results.push(result);
        }

        Ok(results)
    }

    /// Simulate a specific client by ID
    pub async fn simulate_client_by_id(&self, client_id: &str) -> Result<ClientSimulationResult> {
        let client = CLIENT_DB
            .get_by_id(client_id)
            .ok_or_else(|| anyhow::anyhow!("Client not found: {}", client_id))?;

        Ok(self.simulate_client(client).await)
    }

    /// Simulate a specific client profile
    async fn simulate_client(&self, client: &ClientProfile) -> ClientSimulationResult {
        let start = std::time::Instant::now();

        match self.try_connect_as_client(client).await {
            Ok(handshake_info) => {
                // Determine forward secrecy from cipher name
                let has_fs = handshake_info
                    .cipher
                    .as_ref()
                    .map(|c| {
                        c.contains("ECDHE")
                            || c.contains("DHE")
                            || c.starts_with("TLS_AES")
                            || c.starts_with("TLS_CHACHA20")
                    })
                    .unwrap_or(false);

                ClientSimulationResult {
                    client_name: client.name.clone(),
                    client_id: client.short_id.clone(),
                    success: true,
                    protocol: Some(handshake_info.protocol),
                    cipher: handshake_info.cipher,
                    error: None,
                    handshake_time_ms: Some(start.elapsed().as_millis() as u64),
                    alpn: handshake_info.alpn,
                    key_exchange: handshake_info.key_exchange,
                    forward_secrecy: has_fs,
                    certificate_type: handshake_info.certificate_type,
                }
            }
            Err(e) => ClientSimulationResult {
                client_name: client.name.clone(),
                client_id: client.short_id.clone(),
                success: false,
                protocol: None,
                cipher: None,
                error: Some(e.to_string()),
                handshake_time_ms: None,
                alpn: None,
                key_exchange: None,
                forward_secrecy: false,
                certificate_type: None,
            },
        }
    }

    /// Try to connect as a specific client
    async fn try_connect_as_client(&self, client: &ClientProfile) -> Result<HandshakeInfo> {
        // Use rustls with client-specific configuration
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let stream = timeout(self.connect_timeout, TcpStream::connect(addr)).await??;

        // Build TLS config based on client profile
        let config = self.build_client_config(client)?;
        let connector = TlsConnector::from(Arc::new(config));

        // Connect with TLS
        let hostname = self.target.hostname.clone();
        let domain = rustls_pki_types::ServerName::try_from(hostname.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        let tls_stream = timeout(self.read_timeout, connector.connect(domain, stream)).await??;

        // Get connection info
        let (_io, connection) = tls_stream.into_inner();

        // Extract protocol version
        let protocol = match connection.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => Protocol::TLS13,
            Some(rustls::ProtocolVersion::TLSv1_2) => Protocol::TLS12,
            Some(rustls::ProtocolVersion::TLSv1_1) => Protocol::TLS11,
            Some(rustls::ProtocolVersion::TLSv1_0) => Protocol::TLS10,
            _ => Protocol::TLS12, // Default
        };

        // Extract negotiated cipher suite
        let cipher_suite = connection.negotiated_cipher_suite().map(|cs| {
            // Convert rustls cipher suite to human-readable name
            Self::format_cipher_suite(cs.suite())
        });

        // Extract ALPN protocol
        let alpn = connection
            .alpn_protocol()
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok());

        // Extract key exchange from negotiated cipher suite
        let key_exchange = connection
            .negotiated_cipher_suite()
            .and_then(|cs| Self::extract_key_exchange(&cs, &client.curves));

        // Extract certificate information
        let certificate_type = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| Self::extract_certificate_info(cert));

        Ok(HandshakeInfo {
            protocol,
            cipher: cipher_suite,
            alpn,
            key_exchange,
            certificate_type,
        })
    }

    /// Format cipher suite to human-readable name
    fn format_cipher_suite(suite: rustls::CipherSuite) -> String {
        // Map rustls cipher suite IDs to standard names
        match suite {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256".to_string(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384".to_string(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
                "TLS_CHACHA20_POLY1305_SHA256".to_string()
            }
            _ => format!("{:?}", suite),
        }
    }

    /// Extract key exchange algorithm from cipher suite and client curves
    fn extract_key_exchange(
        cipher_suite: &rustls::SupportedCipherSuite,
        curves: &[String],
    ) -> Option<String> {
        // For TLS 1.3, key exchange is always ECDHE with the first supported curve
        if matches!(
            cipher_suite.suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        ) {
            // Use first curve from client profile, or default to x25519
            let curve = curves.first().map(|c| c.as_str()).unwrap_or("x25519");
            return Some(format!("ECDH {}", curve));
        }

        // For TLS 1.2 and earlier, extract from cipher suite name
        let suite_name = format!("{:?}", cipher_suite.suite());
        if suite_name.contains("ECDHE") {
            let curve = curves.first().map(|c| c.as_str()).unwrap_or("secp256r1");
            Some(format!("ECDH {}", curve))
        } else if suite_name.contains("DHE") {
            Some("DH 2048".to_string())
        } else if suite_name.contains("RSA") {
            Some("RSA".to_string())
        } else {
            None
        }
    }

    /// Extract certificate type and key information
    fn extract_certificate_info(cert: &rustls_pki_types::CertificateDer) -> Option<String> {
        use x509_parser::prelude::*;

        // Parse X.509 certificate
        let parsed = X509Certificate::from_der(cert.as_ref());
        if let Ok((_, cert)) = parsed {
            // Get public key algorithm
            let key_algo = cert.public_key().algorithm.algorithm.to_id_string();

            // Get signature algorithm
            let sig_algo = cert.signature_algorithm.algorithm.to_id_string();

            // Determine key type and size
            let key_info = if key_algo.contains("rsaEncryption") {
                // RSA key
                let key_size = cert.public_key().subject_public_key.data.len() * 8;
                format!("RSA {}", key_size)
            } else if key_algo.contains("ecPublicKey") {
                // ECDSA key
                "ECDSA P-256".to_string()
            } else {
                "Unknown".to_string()
            };

            // Determine signature hash
            let hash = if sig_algo.contains("sha256") {
                "SHA256"
            } else if sig_algo.contains("sha384") {
                "SHA384"
            } else if sig_algo.contains("sha512") {
                "SHA512"
            } else {
                "SHA1"
            };

            Some(format!("{} ({})", key_info, hash))
        } else {
            None
        }
    }

    /// Build rustls ClientConfig based on client profile
    fn build_client_config(&self, client: &ClientProfile) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Parse TLS version preference
        let versions = match client.highest_protocol.as_deref() {
            Some("tls1_3") => vec![&rustls::version::TLS13],
            Some("tls1_2") => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            Some("tls1_1") => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            Some("tls1") | Some("tls1_0") => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            _ => vec![&rustls::version::TLS13, &rustls::version::TLS12], // Default
        };

        let config = ClientConfig::builder_with_protocol_versions(&versions)
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(config)
    }

    /// Simulate popular clients (subset)
    pub async fn simulate_popular_clients(&self) -> Result<Vec<ClientSimulationResult>> {
        let popular_ids = vec![
            "chrome_120",
            "firefox_120",
            "safari_17_0",
            "edge_120",
            "android_14",
            "ios_17_0",
        ];

        let mut results = Vec::new();
        for id in popular_ids {
            if let Ok(result) = self.simulate_client_by_id(id).await {
                results.push(result);
            }
        }

        Ok(results)
    }
}

impl ClientSimulationResult {
    /// Check if connection was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        if self.success {
            format!(
                "{} -  {} / {}",
                self.client_name,
                self.protocol
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                self.cipher.as_ref().unwrap_or(&"Unknown".to_string())
            )
        } else {
            format!(
                "{} -  {}",
                self.client_name,
                self.error
                    .as_ref()
                    .unwrap_or(&"Connection failed".to_string())
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_simulation_result_summary() {
        let result = ClientSimulationResult {
            client_name: "Chrome 120".to_string(),
            client_id: "chrome_120".to_string(),
            success: true,
            protocol: Some(Protocol::TLS13),
            cipher: Some("TLS_AES_128_GCM_SHA256".to_string()),
            error: None,
            handshake_time_ms: Some(150),
            alpn: Some("h2".to_string()),
            key_exchange: Some("ECDH x25519".to_string()),
            forward_secrecy: true,
            certificate_type: Some("RSA 2048 (SHA256)".to_string()),
        };

        let summary = result.summary();
        assert!(summary.contains("Chrome 120"));
        assert!(summary.contains(""));
    }

    #[test]
    fn test_failed_simulation_result() {
        let result = ClientSimulationResult {
            client_name: "Old Client".to_string(),
            client_id: "old_client".to_string(),
            success: false,
            protocol: None,
            cipher: None,
            error: Some("TLS version not supported".to_string()),
            handshake_time_ms: None,
            alpn: None,
            key_exchange: None,
            forward_secrecy: false,
            certificate_type: None,
        };

        let summary = result.summary();
        assert!(summary.contains(""));
        assert!(summary.contains("TLS version not supported"));
    }
}
