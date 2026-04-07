use super::{AnycastDetection, AnycastScanResults, IpScanResult};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

impl super::AnycastScanner {
    /// Detect Anycast deployment by comparing scan results
    pub(super) fn detect_anycast(results: &[IpScanResult]) -> AnycastDetection {
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
            if let Some(cert) = &result.results.certificate_chain
                && let Some(fingerprint) =
                    &cert.chain.leaf().and_then(|c| c.fingerprint_sha256.clone())
            {
                certificate_fingerprints.insert(fingerprint.clone());
            }

            // Extract cipher preferences
            if let Some(first_protocol) = result.results.ciphers.values().next()
                && let Some(preferred_cipher) = &first_protocol.preferred_cipher
            {
                cipher_preferences.insert(result.ip, preferred_cipher.openssl_name.clone());
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
        } else if certificate_fingerprints.len() == 1
            && unique_ciphers.len() == 1
            && protocol_sets.iter().all(|s| s == &protocol_sets[0])
        {
            0.0 // Not Anycast
        } else {
            0.5 // Uncertain
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
