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
            Ok((protocol, cipher)) => ClientSimulationResult {
                client_name: client.name.clone(),
                client_id: client.short_id.clone(),
                success: true,
                protocol: Some(protocol),
                cipher: Some(cipher),
                error: None,
                handshake_time_ms: Some(start.elapsed().as_millis() as u64),
            },
            Err(e) => ClientSimulationResult {
                client_name: client.name.clone(),
                client_id: client.short_id.clone(),
                success: false,
                protocol: None,
                cipher: None,
                error: Some(e.to_string()),
                handshake_time_ms: None,
            },
        }
    }

    /// Try to connect as a specific client
    async fn try_connect_as_client(&self, client: &ClientProfile) -> Result<(Protocol, String)> {
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
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "Unknown".to_string());

        Ok((protocol, cipher_suite))
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
        };

        let summary = result.summary();
        assert!(summary.contains(""));
        assert!(summary.contains("TLS version not supported"));
    }
}
