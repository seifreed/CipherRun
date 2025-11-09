// Advanced Certificate Tests
// Multiple certificates, certificate compression, cipher order enforcement

use crate::Result;
use crate::utils::network::Target;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Multiple certificates analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipleCertificatesAnalysis {
    pub certificates_count: usize,
    pub certificates: Vec<CertificateInfo>,
    pub virtual_hosts_detected: bool,
    pub sni_required: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub san_entries: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub fingerprint: String,
}

/// Certificate compression analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateCompressionAnalysis {
    pub compression_supported: bool,
    pub compression_algorithms: Vec<String>,
    pub original_size: Option<usize>,
    pub compressed_size: Option<usize>,
    pub compression_ratio: Option<f64>,
    pub details: String,
}

/// Cipher order enforcement analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderEnforcementAnalysis {
    pub server_enforces_order: bool,
    pub test_results: Vec<CipherOrderEnforcementTest>,
    pub consistency_score: f64,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderEnforcementTest {
    pub test_name: String,
    pub client_order: Vec<String>,
    pub server_selected: String,
    pub expected_if_server_preference: String,
    pub expected_if_client_preference: String,
    pub matches_server_preference: bool,
}

/// Advanced certificate tester
pub struct CertificateAdvancedTester {
    target: Target,
}

impl CertificateAdvancedTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for multiple certificates on same IP:port
    pub async fn test_multiple_certificates(&self) -> Result<MultipleCertificatesAnalysis> {
        let mut certificates = Vec::new();

        // Test 1: Connect without SNI
        let cert_no_sni = self.get_certificate(None).await;

        // Test 2: Connect with SNI (target hostname)
        let cert_with_sni = self.get_certificate(Some(&self.target.hostname)).await;

        // Test 3: Try common alternative hostnames
        let alt_hostnames = vec![
            format!("www.{}", self.target.hostname),
            format!("mail.{}", self.target.hostname),
            format!("api.{}", self.target.hostname),
        ];

        // Check SNI requirement before moving values
        let no_sni_failed = cert_no_sni.is_err();
        let with_sni_ok = cert_with_sni.is_ok();

        // Add no-SNI certificate
        if let Ok(cert) = cert_no_sni {
            certificates.push(cert);
        }

        // Add SNI certificate
        if let Ok(cert) = cert_with_sni {
            // Only add if different from no-SNI cert
            if certificates.is_empty() || cert.fingerprint != certificates[0].fingerprint {
                certificates.push(cert);
            }
        }

        // Try alternative hostnames
        for alt_hostname in alt_hostnames {
            if let Ok(cert) = self.get_certificate(Some(&alt_hostname)).await {
                // Only add if different from existing certificates
                if !certificates
                    .iter()
                    .any(|c| c.fingerprint == cert.fingerprint)
                {
                    certificates.push(cert);
                }
            }
        }

        let certificates_count = certificates.len();
        let virtual_hosts_detected = certificates_count > 1;
        let sni_required = certificates_count > 0 && no_sni_failed && with_sni_ok;

        let details = format!(
            "{} certificate(s) detected. Virtual hosts: {}. SNI required: {}",
            certificates_count, virtual_hosts_detected, sni_required
        );

        Ok(MultipleCertificatesAnalysis {
            certificates_count,
            certificates,
            virtual_hosts_detected,
            sni_required,
            details,
        })
    }

    async fn get_certificate(&self, sni_hostname: Option<&str>) -> Result<CertificateInfo> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let builder = SslConnector::builder(SslMethod::tls())?;

        let connector = builder.build();

        let hostname_to_use = sni_hostname.unwrap_or(&self.target.hostname);

        let ssl_stream = connector.connect(hostname_to_use, std_stream)?;

        let cert = ssl_stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| anyhow::anyhow!("No certificate presented"))?;

        Ok(extract_certificate_info(&cert))
    }

    /// Test certificate compression
    pub async fn test_certificate_compression(&self) -> Result<CertificateCompressionAnalysis> {
        // Certificate compression is defined in RFC 8879
        // It's a TLS 1.3 extension (compress_certificate, type 27)

        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Try to enable TLS 1.3 for certificate compression
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                let cert = ssl_stream.ssl().peer_certificate();

                if let Some(cert) = cert {
                    // Get certificate size
                    let cert_der = cert.to_der()?;
                    let original_size = cert_der.len();

                    // Note: OpenSSL doesn't expose certificate compression details directly
                    // We can only estimate based on certificate chain size

                    let details = format!(
                        "Certificate size: {} bytes. Certificate compression is a TLS 1.3 feature (RFC 8879), \
                        but OpenSSL doesn't expose compression details directly.",
                        original_size
                    );

                    Ok(CertificateCompressionAnalysis {
                        compression_supported: false,
                        compression_algorithms: Vec::new(),
                        original_size: Some(original_size),
                        compressed_size: None,
                        compression_ratio: None,
                        details,
                    })
                } else {
                    Ok(CertificateCompressionAnalysis {
                        compression_supported: false,
                        compression_algorithms: Vec::new(),
                        original_size: None,
                        compressed_size: None,
                        compression_ratio: None,
                        details: "No certificate presented".to_string(),
                    })
                }
            }
            Err(e) => Ok(CertificateCompressionAnalysis {
                compression_supported: false,
                compression_algorithms: Vec::new(),
                original_size: None,
                compressed_size: None,
                compression_ratio: None,
                details: format!("TLS 1.3 connection failed: {}", e),
            }),
        }
    }

    /// Test cipher order enforcement (detailed)
    pub async fn test_cipher_order_enforcement(&self) -> Result<CipherOrderEnforcementAnalysis> {
        let mut test_results = Vec::new();

        // Define test cases with different cipher orders
        let tests = vec![
            // Test 1: Strong to weak order
            (
                "Strong to weak",
                vec![
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_AES_128_GCM_SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "AES256-SHA",
                    "AES128-SHA",
                    "DES-CBC3-SHA",
                ],
                "TLS_AES_256_GCM_SHA384", // Expected if client preference
                "TLS_AES_256_GCM_SHA384", // Expected if server preference (assuming server prefers strong)
            ),
            // Test 2: Weak to strong order
            (
                "Weak to strong",
                vec![
                    "DES-CBC3-SHA",
                    "AES128-SHA",
                    "AES256-SHA",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                ],
                "DES-CBC3-SHA",           // Expected if client preference
                "TLS_AES_256_GCM_SHA384", // Expected if server preference (assuming server prefers strong)
            ),
            // Test 3: Random order
            (
                "Random order",
                vec![
                    "AES128-SHA",
                    "TLS_AES_256_GCM_SHA384",
                    "DES-CBC3-SHA",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "AES256-SHA",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                ],
                "AES128-SHA",             // Expected if client preference
                "TLS_AES_256_GCM_SHA384", // Expected if server preference
            ),
            // Test 4: Only modern ciphers
            (
                "Modern ciphers only",
                vec![
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "TLS_AES_128_GCM_SHA256",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "TLS_AES_256_GCM_SHA384",
                ],
                "ECDHE-RSA-AES128-GCM-SHA256", // Expected if client preference
                "TLS_AES_256_GCM_SHA384",      // Expected if server preference
            ),
        ];

        for (test_name, client_order, expected_client, expected_server) in tests {
            if let Ok(selected) = self.test_cipher_selection(&client_order).await {
                let matches_server = selected == expected_server;

                test_results.push(CipherOrderEnforcementTest {
                    test_name: test_name.to_string(),
                    client_order: client_order.iter().map(|s| s.to_string()).collect(),
                    server_selected: selected,
                    expected_if_server_preference: expected_server.to_string(),
                    expected_if_client_preference: expected_client.to_string(),
                    matches_server_preference: matches_server,
                });
            }
        }

        // Calculate consistency score (how many tests matched server preference)
        let server_preference_matches = test_results
            .iter()
            .filter(|t| t.matches_server_preference)
            .count();

        let consistency_score = if test_results.is_empty() {
            0.0
        } else {
            (server_preference_matches as f64) / (test_results.len() as f64) * 100.0
        };

        let server_enforces_order = consistency_score > 75.0;

        let details = format!(
            "Cipher order enforcement: {}. Consistency score: {:.1}%. {}/{} tests matched server preference.",
            if server_enforces_order { "YES" } else { "NO" },
            consistency_score,
            server_preference_matches,
            test_results.len()
        );

        Ok(CipherOrderEnforcementAnalysis {
            server_enforces_order,
            test_results,
            consistency_score,
            details,
        })
    }

    async fn test_cipher_selection(&self, cipher_list: &[&str]) -> Result<String> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);

        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let std_stream = stream.into_std()?;

        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // Set cipher list
        let cipher_string = cipher_list.join(":");
        builder.set_cipher_list(&cipher_string)?;

        let connector = builder.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(ssl_stream) => {
                let cipher = ssl_stream
                    .ssl()
                    .current_cipher()
                    .ok_or_else(|| anyhow::anyhow!("No cipher negotiated"))?;

                Ok(cipher.name().to_string())
            }
            Err(e) => Err(anyhow::anyhow!("Connection failed: {}", e).into()),
        }
    }
}

fn extract_certificate_info(cert: &X509) -> CertificateInfo {
    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                String::from_utf8_lossy(e.data().as_slice())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                String::from_utf8_lossy(e.data().as_slice())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let san_entries = if let Some(san) = cert.subject_alt_names() {
        san.iter()
            .filter_map(|name| {
                if let Some(dns) = name.dnsname() {
                    Some(format!("DNS:{}", dns))
                } else {
                    name.ipaddress()
                        .map(|ip| format!("IP:{}", String::from_utf8_lossy(ip)))
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let valid_from = cert.not_before().to_string();
    let valid_until = cert.not_after().to_string();

    let fingerprint = if let Ok(digest) = cert.digest(openssl::hash::MessageDigest::sha256()) {
        digest
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        "unknown".to_string()
    };

    CertificateInfo {
        subject,
        issuer,
        san_entries,
        valid_from,
        valid_until,
        fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_certificate_info() {
        // This test would require a valid X509 certificate
        // Skipping for now as it requires integration testing
    }

    #[test]
    fn test_consistency_score_calculation() {
        // Test consistency score calculation
        let test_results = vec![
            CipherOrderEnforcementTest {
                test_name: "Test 1".to_string(),
                client_order: vec!["A".to_string()],
                server_selected: "A".to_string(),
                expected_if_server_preference: "A".to_string(),
                expected_if_client_preference: "A".to_string(),
                matches_server_preference: true,
            },
            CipherOrderEnforcementTest {
                test_name: "Test 2".to_string(),
                client_order: vec!["B".to_string()],
                server_selected: "B".to_string(),
                expected_if_server_preference: "A".to_string(),
                expected_if_client_preference: "B".to_string(),
                matches_server_preference: false,
            },
        ];

        let matches = test_results
            .iter()
            .filter(|t| t.matches_server_preference)
            .count();
        let score = (matches as f64) / (test_results.len() as f64) * 100.0;

        assert_eq!(score, 50.0);
    }
}
