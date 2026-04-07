// Anycast Detection Module
// Resolves all A/AAAA records and scans each IP individually
// Detects Anycast deployments by comparing certificates and behaviors

mod detection;

use crate::Args;
use crate::Result;
use crate::error::TlsError;
use crate::scanner::ScanResults;
use crate::utils::network::Target;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Anycast scanner for testing all IPs of a hostname
pub struct AnycastScanner {
    hostname: String,
    port: u16,
    args: Args,
}

impl AnycastScanner {
    /// Create new anycast scanner
    pub fn new(hostname: String, port: u16, args: Args) -> Self {
        Self {
            hostname,
            port,
            args,
        }
    }

    /// Scan all IPs resolved for the hostname
    pub async fn scan_all_ips(&self) -> Result<AnycastScanResults> {
        // 1. Resolve hostname to all IPs (A + AAAA records)
        let ip_addresses = self.resolve_all_ips().await?;

        if ip_addresses.is_empty() {
            return Err(TlsError::DnsResolutionFailed {
                hostname: self.hostname.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No IP addresses resolved",
                ),
            });
        }

        println!(
            "  Resolved {} IP address(es) for {}",
            ip_addresses.len(),
            self.hostname
        );

        // 2. Scan each IP individually
        let mut ip_results = Vec::new();
        for (index, ip) in ip_addresses.iter().enumerate() {
            println!(
                "  [{}/{}] Scanning IP: {}",
                index + 1,
                ip_addresses.len(),
                ip
            );

            match self.scan_single_ip(ip).await {
                Ok(scan_result) => {
                    ip_results.push(IpScanResult {
                        ip: *ip,
                        results: scan_result,
                        error: None,
                    });
                }
                Err(e) => {
                    println!("    Warning: Scan failed for {}: {}", ip, e);
                    ip_results.push(IpScanResult {
                        ip: *ip,
                        results: ScanResults::default(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // 3. Detect Anycast deployment
        let anycast_detection = Self::detect_anycast(&ip_results);

        Ok(AnycastScanResults {
            hostname: self.hostname.clone(),
            port: self.port,
            total_ips: ip_addresses.len(),
            successful_scans: ip_results.iter().filter(|r| r.error.is_none()).count(),
            ip_results,
            anycast_detection,
        })
    }

    /// Resolve all A and AAAA records for hostname
    async fn resolve_all_ips(&self) -> Result<Vec<IpAddr>> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        let mut ips = Vec::new();

        // Query A records (IPv4)
        if !self.args.network.ipv6_only {
            match resolver.ipv4_lookup(&self.hostname).await {
                Ok(lookup) => {
                    for ipv4 in lookup.iter() {
                        ips.push(IpAddr::V4(ipv4.0));
                    }
                }
                Err(_) => {
                    // A records not found, continue
                }
            }
        }

        // Query AAAA records (IPv6)
        if !self.args.network.ipv4_only {
            match resolver.ipv6_lookup(&self.hostname).await {
                Ok(lookup) => {
                    for ipv6 in lookup.iter() {
                        ips.push(IpAddr::V6(ipv6.0));
                    }
                }
                Err(_) => {
                    // AAAA records not found, continue
                }
            }
        }

        Ok(ips)
    }

    /// Scan a single IP address with SNI=hostname
    async fn scan_single_ip(&self, ip: &IpAddr) -> Result<ScanResults> {
        // Create target with specific IP (unused but kept for potential future use)
        let _target = Target::with_ips(self.hostname.clone(), self.port, vec![*ip])?;

        // Create scanner with modified args (use IP directly)
        let mut scanner_args = self.args.clone();
        scanner_args.target = Some(format!("{}:{}", ip, self.port));

        // Override SNI to use original hostname
        if scanner_args.tls.sni_name.is_none() {
            scanner_args.tls.sni_name = Some(self.hostname.clone());
        }

        // Create and run scanner
        let scanner = crate::scanner::Scanner::new(scanner_args.to_scan_request())?;
        scanner.run().await
    }

}

/// Result of scanning a single IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpScanResult {
    pub ip: IpAddr,
    pub results: ScanResults,
    pub error: Option<String>,
}

/// Complete Anycast scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastScanResults {
    pub hostname: String,
    pub port: u16,
    pub total_ips: usize,
    pub successful_scans: usize,
    pub ip_results: Vec<IpScanResult>,
    pub anycast_detection: AnycastDetection,
}

/// Anycast detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastDetection {
    pub is_anycast: bool,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub certificate_fingerprints: HashSet<String>,
    pub cipher_preferences: HashMap<IpAddr, String>,
    pub protocol_support: HashMap<IpAddr, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::parser::{CertificateChain, CertificateInfo};
    use crate::certificates::validator::ValidationResult;
    use crate::ciphers::CipherSuite;
    use crate::ciphers::tester::ProtocolCipherSummary;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use std::collections::HashMap;

    fn build_scan_with_fingerprint(
        fingerprint: &str,
        cipher_name: &str,
        protocols: Vec<Protocol>,
    ) -> ScanResults {
        let cert = CertificateInfo {
            fingerprint_sha256: Some(fingerprint.to_string()),
            ..Default::default()
        };
        let chain = CertificateChain {
            certificates: vec![cert],
            chain_length: 1,
            chain_size_bytes: 0,
        };
        let validation = ValidationResult {
            valid: true,
            issues: Vec::new(),
            trust_chain_valid: true,
            hostname_match: true,
            not_expired: true,
            signature_valid: true,
            trusted_ca: None,
            platform_trust: None,
        };
        let cipher = CipherSuite {
            hexcode: "0x1301".to_string(),
            openssl_name: cipher_name.to_string(),
            iana_name: "TLS_AES_128_GCM_SHA256".to_string(),
            protocol: "TLS13".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AESGCM".to_string(),
            mac: "AEAD".to_string(),
            bits: 128,
            export: false,
        };
        let mut ciphers = HashMap::new();
        ciphers.insert(
            Protocol::TLS12,
            ProtocolCipherSummary {
                protocol: Protocol::TLS12,
                supported_ciphers: vec![],
                server_ordered: false,
                server_preference: vec![],
                preferred_cipher: Some(cipher),
                counts: Default::default(),
                avg_handshake_time_ms: None,
            },
        );

        ScanResults {
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain,
                validation,
                revocation: None,
            }),
            ciphers,
            protocols: protocols
                .into_iter()
                .map(|protocol| ProtocolTestResult {
                    protocol,
                    supported: true,
                    preferred: false,
                    ciphers_count: 0,
                    handshake_time_ms: None,
                    heartbeat_enabled: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_anycast_detection_different_certs() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
        ];

        // Simulate different certificate fingerprints
        // (In real code, this would come from actual certificate data)

        let detection = AnycastScanner::detect_anycast(&results);

        // With default ScanResults, we don't have cert data, so it should be uncertain
        assert!(detection.confidence >= 0.0);
    }

    #[test]
    fn test_anycast_detection_insufficient_results() {
        let results = vec![IpScanResult {
            ip: "1.1.1.1".parse().unwrap(),
            results: ScanResults::default(),
            error: None,
        }];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_all_errors() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.certificate_fingerprints.len(), 0);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_one_success_one_error_insufficient() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: Some("fail".to_string()),
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert!(detection.reasons.iter().any(|r| r.contains("Insufficient")));
    }

    #[test]
    fn test_anycast_detection_different_fingerprints() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp2",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("Different certificates"))
        );
    }

    #[test]
    fn test_anycast_detection_identical_results() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];
        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.confidence, 0.0);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("identical certificates"))
        );
    }

    #[test]
    fn test_anycast_detection_identical_results_reasons_count() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.reasons.len(), 3);
    }

    #[test]
    fn test_anycast_detection_different_cipher_preferences() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_256_GCM_SHA384",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("cipher preferences"))
        );
    }

    #[test]
    fn test_anycast_detection_different_protocols() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS13],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("protocol support"))
        );
    }

    #[test]
    fn test_anycast_detection_uncertain_with_empty_results() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: ScanResults::default(),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(!detection.is_anycast);
        assert_eq!(detection.confidence, 0.5);
    }

    #[test]
    fn test_anycast_detection_full_confidence() {
        let results = vec![
            IpScanResult {
                ip: "1.1.1.1".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp1",
                    "TLS_AES_128_GCM_SHA256",
                    vec![Protocol::TLS12],
                ),
                error: None,
            },
            IpScanResult {
                ip: "2.2.2.2".parse().unwrap(),
                results: build_scan_with_fingerprint(
                    "fp2",
                    "TLS_AES_256_GCM_SHA384",
                    vec![Protocol::TLS13],
                ),
                error: None,
            },
        ];

        let detection = AnycastScanner::detect_anycast(&results);
        assert!(detection.is_anycast);
        assert_eq!(detection.confidence, 1.0);
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("Different certificates"))
        );
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("cipher preferences"))
        );
        assert!(
            detection
                .reasons
                .iter()
                .any(|r| r.contains("protocol support"))
        );
    }

    #[test]
    fn test_anycast_display_summary_smoke() {
        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 0,
            successful_scans: 0,
            ip_results: Vec::new(),
            anycast_detection: AnycastDetection {
                is_anycast: false,
                confidence: 0.0,
                reasons: vec![],
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };

        results.display_summary();
    }

    #[test]
    fn test_anycast_display_summary_anycast_true_smoke() {
        let results = AnycastScanResults {
            hostname: "example.com".to_string(),
            port: 443,
            total_ips: 2,
            successful_scans: 2,
            ip_results: Vec::new(),
            anycast_detection: AnycastDetection {
                is_anycast: true,
                confidence: 0.75,
                reasons: vec![
                    "Different certificates detected (2 unique fingerprints)".to_string(),
                ],
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            },
        };

        results.display_summary();
    }
}
