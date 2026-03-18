// GREASE (Generate Random Extensions And Sustain Extensibility) Testing
// RFC 8701 - GREASE: Greasing the QUIC Bit

use crate::Result;
use crate::utils::network::Target;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// GREASE test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseResult {
    pub tolerates_grease: bool,
    pub inconclusive: bool,
    pub direct_grease_test_performed: bool,
    pub issues: Vec<String>,
    pub details: Vec<String>,
}

/// GREASE tester
///
/// Tests if a server properly handles unknown/reserved TLS extensions and values.
/// Servers should ignore unknown extensions gracefully as per RFC 8701.
///
/// GREASE values are reserved values that should be ignored:
/// - Cipher suites: 0x0A0A, 0x1A1A, 0x2A2A, etc.
/// - Extensions: 0x0A0A, 0x1A1A, 0x2A2A, etc.
/// - Supported groups: 0x0A0A, 0x1A1A, 0x2A2A, etc.
pub struct GreaseTester {
    target: Target,
}

impl GreaseTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test server GREASE tolerance
    pub async fn test(&self) -> Result<GreaseResult> {
        let mut result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: false,
            issues: Vec::new(),
            details: Vec::new(),
        };

        // Test 1: Normal connection (baseline)
        match self.test_normal_connection().await {
            Ok(true) => {
                result
                    .details
                    .push("✓ Baseline connection successful".to_string());
            }
            Ok(false) => {
                result
                    .issues
                    .push("Baseline connection failed - cannot test GREASE".to_string());
                return Ok(result);
            }
            Err(e) => {
                result
                    .issues
                    .push(format!("Baseline connection error: {}", e));
                return Ok(result);
            }
        }

        // Test 2: Connection with GREASE extensions
        // Note: rustls doesn't directly support injecting GREASE values,
        // so this is a simplified test that checks server behavior
        result.inconclusive = true;
        result.issues.push(
            "Direct GREASE injection is not implemented; this result is heuristic and inconclusive"
                .to_string(),
        );
        match self.test_with_unknown_extensions().await {
            Ok(true) => {
                result
                    .details
                    .push("✓ Server accepts a heuristic extension/ALPN variation, but this is not a direct GREASE proof".to_string());
            }
            Ok(false) => {
                result
                    .issues
                    .push("Server rejected a heuristic extension-variation probe".to_string());
                result
                    .details
                    .push("Server rejected connection with heuristic extension variation".to_string());
            }
            Err(e) => {
                result.issues.push(format!("GREASE test error: {}", e));
            }
        }

        // Test 3: Check for size limitations
        match self.test_size_limitations().await {
            Ok(true) => {
                result
                    .details
                    .push("✓ Server handles large ClientHello messages".to_string());
            }
            Ok(false) => {
                result
                    .issues
                    .push("Server may have ClientHello size limitations".to_string());
            }
            Err(_) => {
                // Non-critical issue
                result
                    .details
                    .push("Could not test ClientHello size limitations".to_string());
            }
        }

        Ok(result)
    }

    /// Test normal TLS connection
    async fn test_normal_connection(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let hostname = self.target.hostname.clone();
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Test with unknown extensions (simulated GREASE)
    async fn test_with_unknown_extensions(&self) -> Result<bool> {
        // Since rustls doesn't support arbitrary extension injection,
        // we test by attempting connections with various configurations
        // that would include different extension sets

        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Create config with various ALPN protocols (adds extensions)
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Add ALPN protocols to increase extension variety
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let hostname = self.target.hostname.clone();
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Test for ClientHello size limitations
    async fn test_size_limitations(&self) -> Result<bool> {
        // Test by connecting with maximum extension data
        // If server accepts, it doesn't have strict size limits

        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Add many ALPN protocols to increase ClientHello size
        config.alpn_protocols = (0..10)
            .map(|i| format!("protocol{}", i).into_bytes())
            .collect();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let hostname = self.target.hostname.clone();
        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?
            .to_owned();

        match timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Generate comprehensive GREASE report
    pub async fn get_comprehensive_report(&self) -> Result<GreaseReport> {
        let grease_result = self.test().await?;
        let recommendations = self.generate_recommendations(&grease_result);

        Ok(GreaseReport {
            grease_result,
            recommendations,
        })
    }

    /// Generate recommendations
    fn generate_recommendations(&self, result: &GreaseResult) -> Vec<String> {
        let mut recommendations = Vec::new();

        if result.direct_grease_test_performed && result.tolerates_grease {
            recommendations.push(
                "✓ Server properly implements TLS extensibility (RFC 8701 compliant)".to_string(),
            );
        } else if result.inconclusive {
            recommendations.push(
                "Direct GREASE injection is not implemented here; treat this result as inconclusive".to_string(),
            );
        } else {
            recommendations.push(
                "Server should properly handle unknown TLS extensions per RFC 8701".to_string(),
            );
            recommendations.push("Consider updating TLS library to support GREASE".to_string());
        }

        if !result.issues.is_empty() {
            recommendations.push(
                "Address the identified issues to improve TLS implementation robustness"
                    .to_string(),
            );
        }

        recommendations
    }
}

/// Comprehensive GREASE report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreaseReport {
    pub grease_result: GreaseResult,
    pub recommendations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Once;
    use tokio::net::TcpListener;

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_grease_tester_creation() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let tester = GreaseTester::new(target);
        assert_eq!(tester.target.hostname, "example.com");
    }

    #[test]
    fn test_generate_recommendations_variants() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let ok_result = GreaseResult {
            tolerates_grease: true,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec![],
            details: vec![],
        };
        let ok_recs = tester.generate_recommendations(&ok_result);
        assert!(ok_recs.iter().any(|r| r.contains("RFC 8701")));

        let bad_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec!["issue".to_string()],
            details: vec![],
        };
        let bad_recs = tester.generate_recommendations(&bad_result);
        assert!(
            bad_recs
                .iter()
                .any(|r| r.contains("handle unknown TLS extensions"))
        );
        assert!(
            bad_recs
                .iter()
                .any(|r| r.contains("Address the identified issues"))
        );
    }

    #[test]
    fn test_grease_result() {
        let result = GreaseResult {
            tolerates_grease: true,
            inconclusive: false,
            direct_grease_test_performed: true,
            issues: vec![],
            details: vec!["Test".to_string()],
        };

        assert!(result.tolerates_grease);
        assert_eq!(result.details.len(), 1);
    }

    #[test]
    fn test_grease_report_fields() {
        let report = GreaseReport {
            grease_result: GreaseResult {
                tolerates_grease: false,
                inconclusive: true,
                direct_grease_test_performed: false,
                issues: vec!["issue".to_string()],
                details: vec!["detail".to_string()],
            },
            recommendations: vec!["rec".to_string()],
        };

        assert!(!report.grease_result.tolerates_grease);
        assert_eq!(report.grease_result.issues.len(), 1);
        assert_eq!(report.recommendations.len(), 1);
    }

    async fn spawn_dummy_server(max_accepts: usize) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut remaining = max_accepts;
            while remaining > 0 {
                if let Ok((socket, _)) = listener.accept().await {
                    drop(socket);
                }
                remaining -= 1;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_grease_tester_baseline_failure_path() {
        install_crypto_provider();
        let addr = spawn_dummy_server(5).await;
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = GreaseTester::new(target);
        let result = tester.test().await.unwrap();
        assert!(!result.tolerates_grease);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("Baseline connection failed"))
        );
    }

    #[test]
    fn test_grease_result_details_includes_issues() {
        let result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: vec!["Baseline connection failed".to_string()],
            details: vec!["Not tolerant".to_string()],
        };
        assert!(!result.tolerates_grease);
        assert!(result.details.iter().any(|d| d.contains("Not tolerant")));
        assert_eq!(result.issues.len(), 1);
    }

    #[test]
    fn test_recommendations_count_increases_with_issues() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = GreaseTester::new(target);

        let base_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: Vec::new(),
            details: Vec::new(),
        };
        let base_recs = tester.generate_recommendations(&base_result);

        let issue_result = GreaseResult {
            tolerates_grease: false,
            inconclusive: true,
            direct_grease_test_performed: false,
            issues: vec!["issue".to_string()],
            details: Vec::new(),
        };
        let issue_recs = tester.generate_recommendations(&issue_result);

        assert!(issue_recs.len() > base_recs.len());
    }
}
