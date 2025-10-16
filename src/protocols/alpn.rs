// ALPN (Application-Layer Protocol Negotiation) Detection
// RFC 7301 - TLS Application-Layer Protocol Negotiation Extension

use crate::Result;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// ALPN detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlpnResult {
    pub supported_protocols: Vec<String>,
    pub http2_supported: bool,
    pub http3_supported: bool,
    pub negotiated_protocol: Option<String>,
    pub details: Vec<String>,
}

/// ALPN protocol tester
pub struct AlpnTester {
    target: Target,
}

impl AlpnTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test ALPN support with various protocols
    pub async fn test_alpn(&self) -> Result<AlpnResult> {
        let mut result = AlpnResult {
            supported_protocols: Vec::new(),
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: Vec::new(),
        };

        // List of common ALPN protocols to test
        let _protocols_to_test = [
            vec![b"h2".to_vec()],                       // HTTP/2
            vec![b"http/1.1".to_vec()],                 // HTTP/1.1
            vec![b"h3".to_vec()],                       // HTTP/3
            vec![b"h2".to_vec(), b"http/1.1".to_vec()], // HTTP/2 with fallback
        ];

        // Test HTTP/2 first
        if let Ok(Some(proto)) = self.test_protocol(vec![b"h2".to_vec()]).await
            && proto == "h2"
        {
            result.http2_supported = true;
            result.supported_protocols.push("h2".to_string());
            result
                .details
                .push("✓ HTTP/2 (h2) is supported".to_string());
        }

        // Test HTTP/1.1
        if let Ok(Some(proto)) = self.test_protocol(vec![b"http/1.1".to_vec()]).await
            && proto == "http/1.1"
        {
            result.supported_protocols.push("http/1.1".to_string());
            result.details.push("✓ HTTP/1.1 is supported".to_string());
        }

        // Test HTTP/3 (QUIC)
        // Note: HTTP/3 uses QUIC which is UDP-based, so we can't test it the same way
        // This is a simplified check
        result
            .details
            .push("HTTP/3 detection requires QUIC support (UDP-based)".to_string());

        // Test with both protocols to see preference
        if let Ok(Some(proto)) = self
            .test_protocol(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .await
        {
            result.negotiated_protocol = Some(proto.clone());
            result.details.push(format!("Server prefers: {}", proto));
        }

        if result.supported_protocols.is_empty() {
            result
                .details
                .push("No ALPN protocols supported or ALPN not enabled".to_string());
        }

        Ok(result)
    }

    /// Test a specific ALPN protocol
    async fn test_protocol(&self, protocols: Vec<Vec<u8>>) -> Result<Option<String>> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        // Connect to server
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        // Create rustls config with ALPN
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut config = config;
        config.alpn_protocols = protocols;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let hostname = self.target.hostname.clone();
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        // Attempt TLS handshake with ALPN
        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(tls_stream)) => {
                // Check which protocol was negotiated
                let (_, connection) = tls_stream.get_ref();
                if let Some(protocol) = connection.alpn_protocol() {
                    let proto_str = String::from_utf8_lossy(protocol).to_string();
                    return Ok(Some(proto_str));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Test for SPDY support (legacy HTTP/2 predecessor)
    pub async fn test_spdy(&self) -> Result<bool> {
        let spdy_protocols = vec![b"spdy/3.1".to_vec(), b"spdy/3".to_vec(), b"spdy/2".to_vec()];

        for proto in spdy_protocols {
            if let Ok(Some(negotiated)) = self.test_protocol(vec![proto.clone()]).await
                && negotiated.starts_with("spdy/")
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get comprehensive ALPN report
    pub async fn get_comprehensive_report(&self) -> Result<AlpnReport> {
        let alpn_result = self.test_alpn().await?;
        let spdy_supported = self.test_spdy().await.unwrap_or(false);
        let recommendations = self.generate_recommendations(&alpn_result, spdy_supported);

        Ok(AlpnReport {
            alpn_enabled: !alpn_result.supported_protocols.is_empty(),
            alpn_result,
            spdy_supported,
            recommendations,
        })
    }

    /// Generate recommendations based on ALPN support
    fn generate_recommendations(&self, result: &AlpnResult, spdy: bool) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !result.http2_supported {
            recommendations
                .push("Consider enabling HTTP/2 (h2) for better performance".to_string());
        } else {
            recommendations.push("✓ HTTP/2 is enabled - good for performance".to_string());
        }

        if spdy {
            recommendations.push("SPDY is deprecated - migrate to HTTP/2".to_string());
        }

        if result.supported_protocols.is_empty() {
            recommendations.push(
                "ALPN is not enabled - consider enabling for protocol negotiation".to_string(),
            );
        }

        recommendations
    }
}

/// Comprehensive ALPN report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlpnReport {
    pub alpn_enabled: bool,
    pub alpn_result: AlpnResult,
    pub spdy_supported: bool,
    pub recommendations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_tester_creation() {
        let target = Target {
            hostname: "example.com".to_string(),
            port: 443,
            ip_addresses: vec![],
        };

        let tester = AlpnTester::new(target);
        assert_eq!(tester.target.hostname, "example.com");
    }

    #[test]
    fn test_alpn_result() {
        let result = AlpnResult {
            supported_protocols: vec!["h2".to_string()],
            http2_supported: true,
            http3_supported: false,
            negotiated_protocol: Some("h2".to_string()),
            details: vec![],
        };

        assert!(result.http2_supported);
        assert_eq!(result.supported_protocols.len(), 1);
    }
}
