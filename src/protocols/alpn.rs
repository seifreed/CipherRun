// ALPN (Application-Layer Protocol Negotiation) Detection
// RFC 7301 - TLS Application-Layer Protocol Negotiation Extension

use crate::Result;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No socket addresses available for target"))?;

        // Connect to server
        let stream =
            match crate::utils::network::connect_with_timeout(addr, Duration::from_secs(5), None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(None),
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
            .map_err(|_| crate::error::TlsError::ParseError {
                message: "Invalid DNS name".into(),
            })?
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
    use std::net::IpAddr;

    #[test]
    fn test_alpn_tester_creation() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

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

    #[test]
    fn test_generate_recommendations() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = AlpnTester::new(target);

        let mut result = AlpnResult {
            supported_protocols: Vec::new(),
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: Vec::new(),
        };

        let recs = tester.generate_recommendations(&result, true);
        assert!(recs.iter().any(|r| r.contains("HTTP/2")));
        assert!(recs.iter().any(|r| r.contains("SPDY is deprecated")));
        assert!(recs.iter().any(|r| r.contains("ALPN is not enabled")));

        result.supported_protocols = vec!["h2".to_string()];
        result.http2_supported = true;
        let recs = tester.generate_recommendations(&result, false);
        assert!(recs.iter().any(|r| r.contains("HTTP/2 is enabled")));
        assert!(!recs.iter().any(|r| r.contains("ALPN is not enabled")));
    }

    #[test]
    fn test_alpn_result_serde_roundtrip() {
        let result = AlpnResult {
            supported_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            http2_supported: true,
            http3_supported: false,
            negotiated_protocol: Some("h2".to_string()),
            details: vec!["detail".to_string()],
        };

        let json = serde_json::to_string(&result).expect("serialize");
        let decoded: AlpnResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.supported_protocols, result.supported_protocols);
        assert_eq!(decoded.http2_supported, result.http2_supported);
        assert_eq!(decoded.http3_supported, result.http3_supported);
        assert_eq!(decoded.negotiated_protocol, result.negotiated_protocol);
        assert_eq!(decoded.details, result.details);
    }

    #[test]
    fn test_generate_recommendations_alpn_enabled_without_http2() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = AlpnTester::new(target);

        let result = AlpnResult {
            supported_protocols: vec!["http/1.1".to_string()],
            http2_supported: false,
            http3_supported: false,
            negotiated_protocol: None,
            details: Vec::new(),
        };

        let recs = tester.generate_recommendations(&result, false);
        assert!(recs.iter().any(|r| r.contains("Consider enabling HTTP/2")));
        assert!(!recs.iter().any(|r| r.contains("ALPN is not enabled")));
    }

    #[test]
    fn test_alpn_report_serde_roundtrip() {
        let report = AlpnReport {
            alpn_enabled: true,
            alpn_result: AlpnResult {
                supported_protocols: vec!["h2".to_string()],
                http2_supported: true,
                http3_supported: false,
                negotiated_protocol: Some("h2".to_string()),
                details: vec!["detail".to_string()],
            },
            spdy_supported: false,
            recommendations: vec!["ok".to_string()],
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let decoded: AlpnReport = serde_json::from_str(&json).expect("deserialize");
        assert!(decoded.alpn_enabled);
        assert_eq!(decoded.alpn_result.supported_protocols.len(), 1);
        assert_eq!(decoded.recommendations.len(), 1);
    }

    #[test]
    fn test_alpn_report_disabled_has_no_protocols() {
        let report = AlpnReport {
            alpn_enabled: false,
            alpn_result: AlpnResult {
                supported_protocols: Vec::new(),
                http2_supported: false,
                http3_supported: false,
                negotiated_protocol: None,
                details: vec!["none".to_string()],
            },
            spdy_supported: false,
            recommendations: vec![],
        };
        assert!(!report.alpn_enabled);
        assert!(report.alpn_result.supported_protocols.is_empty());
    }
}
