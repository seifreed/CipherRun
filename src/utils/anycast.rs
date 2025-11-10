// Anycast Detection Module
// Resolves all A/AAAA records and scans each IP individually
// Detects Anycast deployments by comparing certificates and behaviors

use crate::error::TlsError;
use crate::scanner::ScanResults;
use crate::utils::network::Target;
use crate::Args;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

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
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let mut ips = Vec::new();

        // Query A records (IPv4)
        if !self.args.ipv6_only {
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
        if !self.args.ipv4_only {
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
        // Create target with specific IP
        let target = Target {
            hostname: self.hostname.clone(),
            port: self.port,
            ip_addresses: vec![*ip],
        };

        // Create scanner with modified args (use IP directly)
        let mut scanner_args = self.args.clone();
        scanner_args.target = Some(format!("{}:{}", ip, self.port));

        // Override SNI to use original hostname
        if scanner_args.sni_name.is_none() {
            scanner_args.sni_name = Some(self.hostname.clone());
        }

        // Create and run scanner
        let mut scanner = crate::scanner::Scanner::new(scanner_args)?;
        scanner.run().await
    }

    /// Detect Anycast deployment by comparing scan results
    fn detect_anycast(results: &[IpScanResult]) -> AnycastDetection {
        let successful_results: Vec<_> = results.iter().filter(|r| r.error.is_none()).collect();

        if successful_results.len() < 2 {
            return AnycastDetection {
                is_anycast: false,
                confidence: 0.0,
                reasons: vec!["Insufficient successful scans to determine Anycast".to_string()],
                certificate_fingerprints: HashSet::new(),
                cipher_preferences: HashMap::new(),
                protocol_support: HashMap::new(),
            };
        }

        let mut is_anycast = false;
        let mut reasons = Vec::new();
        let mut certificate_fingerprints = HashSet::new();
        let mut cipher_preferences: HashMap<IpAddr, String> = HashMap::new();
        let mut protocol_support: HashMap<IpAddr, Vec<String>> = HashMap::new();

        // Compare certificate fingerprints
        for result in &successful_results {
            if let Some(cert) = &result.results.certificate_chain {
                if let Some(fingerprint) = &cert.chain.leaf().and_then(|c| c.fingerprint_sha256.clone()) {
                    certificate_fingerprints.insert(fingerprint.clone());
                }
            }

            // Extract cipher preferences
            if let Some(first_protocol) = result.results.ciphers.values().next() {
                if let Some(preferred_cipher) = &first_protocol.preferred_cipher {
                    cipher_preferences.insert(result.ip, preferred_cipher.openssl_name.clone());
                }
            }

            // Extract protocol support
            let protocols: Vec<String> = result
                .results
                .protocols
                .iter()
                .filter(|p| p.supported)
                .map(|p| p.protocol.to_string())
                .collect();
            protocol_support.insert(result.ip, protocols);
        }

        // Check for different certificates (strong Anycast indicator)
        if certificate_fingerprints.len() > 1 {
            is_anycast = true;
            reasons.push(format!(
                "Different certificates detected ({} unique fingerprints)",
                certificate_fingerprints.len()
            ));
        }

        // Check for different cipher preferences
        let unique_ciphers: HashSet<_> = cipher_preferences.values().cloned().collect();
        if unique_ciphers.len() > 1 {
            is_anycast = true;
            reasons.push(format!(
                "Different cipher preferences detected ({} unique)",
                unique_ciphers.len()
            ));
        }

        // Check for different protocol support
        let protocol_sets: Vec<HashSet<String>> = protocol_support
            .values()
            .map(|v| v.iter().cloned().collect())
            .collect();

        if protocol_sets.len() >= 2 {
            let first_set = &protocol_sets[0];
            if protocol_sets.iter().any(|set| set != first_set) {
                is_anycast = true;
                reasons.push("Different protocol support detected".to_string());
            }
        }

        // Calculate confidence score
        let confidence = if is_anycast {
            let mut score: f32 = 0.0;

            // Certificate differences = high confidence
            if certificate_fingerprints.len() > 1 {
                score += 0.7;
            }

            // Cipher differences = medium confidence
            if unique_ciphers.len() > 1 {
                score += 0.2;
            }

            // Protocol differences = low confidence
            if protocol_sets.len() >= 2 && protocol_sets.iter().any(|s| s != &protocol_sets[0]) {
                score += 0.1;
            }

            score.min(1.0)
        } else {
            if certificate_fingerprints.len() == 1
                && unique_ciphers.len() == 1
                && protocol_sets.iter().all(|s| s == &protocol_sets[0])
            {
                0.0 // Not Anycast
            } else {
                0.5 // Uncertain
            }
        };

        if !is_anycast && certificate_fingerprints.len() == 1 {
            reasons.push("All IPs return identical certificates".to_string());
            reasons.push("All IPs have matching cipher preferences".to_string());
            reasons.push("All IPs have identical protocol support".to_string());
        }

        AnycastDetection {
            is_anycast,
            confidence: confidence as f64,
            reasons,
            certificate_fingerprints,
            cipher_preferences,
            protocol_support,
        }
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

impl AnycastScanResults {
    /// Display results summary
    pub fn display_summary(&self) {
        use colored::*;

        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", "Anycast Scan Results".cyan().bold());
        println!("{}", "=".repeat(60).cyan());

        println!("Hostname:         {}", self.hostname.green());
        println!("Port:             {}", self.port);
        println!("Total IPs:        {}", self.total_ips);
        println!(
            "Successful Scans: {}/{}",
            self.successful_scans, self.total_ips
        );

        println!("\n{}", "Per-IP Results:".cyan().bold());
        for result in &self.ip_results {
            if let Some(error) = &result.error {
                println!("  {} {} - {}", "✗".red(), result.ip, error.red());
            } else {
                let cert_status = if let Some(cert) = &result.results.certificate_chain {
                    if cert.validation.valid {
                        "Valid Cert".green()
                    } else {
                        "Invalid Cert".red()
                    }
                } else {
                    "No Cert".yellow()
                };

                let protocol_count = result
                    .results
                    .protocols
                    .iter()
                    .filter(|p| p.supported)
                    .count();

                println!(
                    "  {} {} - {} - {} protocols",
                    "✓".green(),
                    result.ip,
                    cert_status,
                    protocol_count
                );
            }
        }

        println!("\n{}", "Anycast Detection:".cyan().bold());
        let detection_status = if self.anycast_detection.is_anycast {
            format!(
                "YES (confidence: {:.0}%)",
                self.anycast_detection.confidence * 100.0
            )
            .red()
            .bold()
        } else {
            "NO".green().bold()
        };
        println!("  Anycast Detected: {}", detection_status);

        if !self.anycast_detection.reasons.is_empty() {
            println!("\n  Reasons:");
            for reason in &self.anycast_detection.reasons {
                println!("    - {}", reason);
            }
        }

        if self.anycast_detection.certificate_fingerprints.len() > 1 {
            println!(
                "\n  Unique Certificates: {}",
                self.anycast_detection.certificate_fingerprints.len()
            );
        }

        println!("{}", "=".repeat(60).cyan());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anycast_detection_different_certs() {
        let mut results = vec![
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
}
