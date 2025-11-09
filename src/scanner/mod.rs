// Scanner module - Main scanning engine

pub mod mass;

use crate::certificates::{
    parser::{CertificateChain, CertificateParser},
    revocation::{RevocationChecker, RevocationResult},
    validator::{CertificateValidator, ValidationResult},
};
use crate::ciphers::tester::{CipherTester, ProtocolCipherSummary};
use crate::client_sim::simulator::{ClientSimulationResult, ClientSimulator};
use crate::http::tester::{HeaderAnalysisResult, HeaderAnalyzer};
use crate::protocols::{Protocol, ProtocolTestResult, tester::ProtocolTester};
use crate::rating::{RatingCalculator, RatingResult};
use crate::utils::mtls::MtlsConfig;
use crate::utils::network::Target;
use crate::vulnerabilities::{VulnerabilityResult, tester::VulnerabilityScanner};
use crate::{Args, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Main scanner struct
pub struct Scanner {
    pub args: Args,
    target: Target,
    mtls_config: Option<MtlsConfig>,
}

impl Scanner {
    pub fn new(args: Args) -> Result<Self> {
        // Parse target from args
        let target_str = args
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        // For now, use a placeholder - in full implementation this would be async
        // We'll need to refactor this to handle async initialization
        let target = Target {
            hostname: target_str.clone(),
            port: args.port.unwrap_or(443),
            ip_addresses: vec![],
        };

        // Load mTLS configuration if specified
        let mtls_config =
            if let (Some(key_path), Some(cert_path)) = (&args.client_key, &args.client_certs) {
                // Use separate key and certificate files
                Some(MtlsConfig::from_separate_files(
                    cert_path,
                    key_path,
                    args.client_key_password.as_deref(),
                )?)
            } else if let Some(mtls_path) = &args.mtls_cert {
                // Use combined PEM file
                Some(MtlsConfig::from_pem_file(mtls_path)?)
            } else {
                None
            };

        Ok(Self {
            args,
            target,
            mtls_config,
        })
    }

    /// Initialize target with DNS resolution
    pub async fn initialize(&mut self) -> Result<()> {
        let target_str = self
            .args
            .target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No target specified"))?;

        self.target = Target::parse(target_str).await?;
        Ok(())
    }

    /// Run complete scan
    pub async fn run(&mut self) -> Result<ScanResults> {
        let start_time = Instant::now();

        // Initialize target
        self.initialize().await?;

        // Check for STARTTLS mode
        if let Some(starttls_proto) = self.args.starttls_protocol() {
            println!(
                "\n{} {}:{} ({})\n",
                "Starting scan of".cyan().bold(),
                self.target.hostname.green().bold(),
                self.target.port.to_string().green().bold(),
                format!("STARTTLS {}", starttls_proto).yellow()
            );
            println!(
                "  {} STARTTLS negotiation will be performed before TLS handshake",
                "ℹ".cyan()
            );
        } else {
            println!(
                "\n{} {}:{}\n",
                "Starting scan of".cyan().bold(),
                self.target.hostname.green().bold(),
                self.target.port.to_string().green().bold()
            );
        }

        let mut results = ScanResults {
            target: format!("{}:{}", self.target.hostname, self.target.port),
            scan_time_ms: 0,
            ..Default::default()
        };

        // Phase 1: Protocol Testing
        if self.args.protocols || self.args.all || self.args.target.is_some() {
            println!("{}", "Testing SSL/TLS Protocols...".yellow().bold());
            results.protocols = self.test_protocols().await?;
            self.display_protocol_results(&results.protocols);
        }

        // Phase 2: Cipher Testing
        if !self.args.no_ciphersuites
            && (self.args.each_cipher || self.args.all || self.args.target.is_some())
        {
            println!("\n{}", "Testing Cipher Suites...".yellow().bold());
            results.ciphers = self.test_ciphers(&results.protocols).await?;
            self.display_cipher_results(&results.ciphers);
        }

        // Phase 3: Certificate Analysis
        if self.args.all || self.args.target.is_some() {
            println!("\n{}", "Analyzing Certificate...".yellow().bold());
            results.certificate_chain = self.analyze_certificate().await.ok();
            if let Some(cert_data) = &results.certificate_chain {
                self.display_certificate_results(cert_data);
            }
        }

        // Phase 4: HTTP Security Headers
        if self.args.headers || self.args.all {
            println!("\n{}", "Analyzing HTTP Security Headers...".yellow().bold());
            results.http_headers = self.analyze_http_headers().await.ok();
            if let Some(headers_result) = &results.http_headers {
                self.display_http_headers_results(headers_result);
            }
        }

        // Phase 5: Vulnerability Testing
        if self.args.vulnerabilities || self.args.all || self.args.target.is_some() {
            println!("\n{}", "Testing Vulnerabilities...".yellow().bold());
            results.vulnerabilities = self.test_vulnerabilities().await?;
            self.display_vulnerability_results(&results.vulnerabilities);
        }

        // Phase 6: Client Simulation
        if self.args.all {
            println!("\n{}", "Simulating Client Connections...".yellow().bold());
            results.client_simulations = self.simulate_clients().await.ok();
            if let Some(sim_results) = &results.client_simulations {
                self.display_client_simulation_results(sim_results);
            }
        }

        // Phase 7: Signature Algorithm Enumeration
        if self.args.show_sigs {
            println!(
                "\n{}",
                "Enumerating Signature Algorithms...".yellow().bold()
            );
            results.signature_algorithms = self.enumerate_signatures().await.ok();
            if let Some(sigs) = &results.signature_algorithms {
                self.display_signature_results(sigs);
            }
        }

        // Phase 8: Key Exchange Groups Enumeration
        if self.args.show_groups && !self.args.no_groups {
            println!("\n{}", "Enumerating Key Exchange Groups...".yellow().bold());
            results.key_exchange_groups = self.enumerate_groups().await.ok();
            if let Some(groups) = &results.key_exchange_groups {
                self.display_group_results(groups);
            }
        }

        // Phase 9: Client CAs List
        if self.args.show_client_cas {
            println!("\n{}", "Extracting Client CAs List...".yellow().bold());
            results.client_cas = self.enumerate_client_cas().await.ok();
            if let Some(cas) = &results.client_cas {
                self.display_client_cas_results(cas);
            }
        }

        // Phase 10: TLS Intolerance Tests
        if self.args.all {
            println!("\n{}", "Testing TLS Intolerance...".yellow().bold());
            results.intolerance = self.test_intolerance().await.ok();
            if let Some(intolerance) = &results.intolerance {
                self.display_intolerance_results(intolerance);
            }
        }

        // Calculate overall SSL Labs rating
        if self.args.all || self.args.target.is_some() {
            results.rating = Some(self.calculate_rating(&results));
            if let Some(rating) = &results.rating {
                self.display_rating_results(rating);
            }
        }

        results.scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(results)
    }

    /// Test all protocols
    async fn test_protocols(&self) -> Result<Vec<ProtocolTestResult>> {
        let mut tester = if let Some(ref mtls_config) = self.mtls_config {
            ProtocolTester::with_mtls(self.target.clone(), mtls_config.clone())
        } else {
            ProtocolTester::new(self.target.clone())
        };

        // Enable RDP mode if specified
        if self.args.rdp {
            tester = tester.with_rdp(true);
        }

        // Enable bug workarounds if specified
        if self.args.bugs {
            tester = tester.with_bugs_mode(true);
        }

        // Enable STARTTLS if specified
        if let Some(starttls_proto) = self.args.starttls_protocol() {
            tester = tester.with_starttls(Some(starttls_proto));
        }

        // Set custom SNI if specified
        if let Some(ref sni) = self.args.sni_name {
            tester = tester.with_sni(Some(sni.clone()));
        }

        // Set protocol filter if specified
        if let Some(protocols) = self.args.protocols_to_test() {
            tester = tester.with_protocol_filter(Some(protocols));
        }

        // Enable testing all IPs if specified
        if self.args.test_all_ips {
            tester = tester.with_test_all_ips(true);
        }

        tester.test_all_protocols().await
    }

    /// Test ciphers for supported protocols only
    async fn test_ciphers(
        &self,
        protocol_results: &[ProtocolTestResult],
    ) -> Result<HashMap<Protocol, ProtocolCipherSummary>> {
        let mut tester = CipherTester::new(self.target.clone());

        // Apply connect timeout if specified
        if let Some(timeout_secs) = self.args.connect_timeout {
            tester = tester.with_connect_timeout(std::time::Duration::from_secs(timeout_secs));
        }

        // Apply sleep duration if specified
        if let Some(sleep_ms) = self.args.sleep {
            tester = tester.with_sleep(std::time::Duration::from_millis(sleep_ms));
        }

        // Enable RDP mode if specified
        if self.args.rdp {
            tester = tester.with_rdp(true);
        }

        // Enable STARTTLS if specified
        if let Some(starttls_proto) = self.args.starttls_protocol() {
            tester = tester.with_starttls(Some(starttls_proto));
        }

        // Enable testing all IPs if specified
        if self.args.test_all_ips {
            tester = tester.with_test_all_ips(true);
        }

        // Only test ciphers for supported protocols
        let mut results = HashMap::new();
        for protocol_result in protocol_results {
            if protocol_result.supported && !matches!(protocol_result.protocol, Protocol::QUIC) {
                let summary = tester
                    .test_protocol_ciphers(protocol_result.protocol)
                    .await?;
                if !summary.supported_ciphers.is_empty() {
                    results.insert(protocol_result.protocol, summary);
                }
            }
        }

        Ok(results)
    }

    /// Test vulnerabilities
    async fn test_vulnerabilities(&self) -> Result<Vec<VulnerabilityResult>> {
        let scanner = VulnerabilityScanner::with_args(self.target.clone(), &self.args);
        scanner.test_all().await
    }

    /// Analyze certificate
    async fn analyze_certificate(&self) -> Result<CertificateAnalysisResult> {
        // Parse certificate chain
        let parser = if let Some(ref mtls_config) = self.mtls_config {
            CertificateParser::with_mtls(self.target.clone(), mtls_config.clone())
        } else {
            CertificateParser::new(self.target.clone())
        };
        let chain = parser.get_certificate_chain().await?;

        // Validate certificate with platform trust validation enabled
        let validator = if self.args.no_check_certificate {
            CertificateValidator::with_config(self.target.hostname.clone(), true, true)?
        } else {
            CertificateValidator::with_platform_trust(self.target.hostname.clone())?
        };
        let validation = validator.validate_chain(&chain)?;

        // Check revocation status (if phone-out enabled)
        let revocation_checker = RevocationChecker::new(self.args.phone_out);
        let revocation = if chain.certificates.len() >= 2 {
            revocation_checker
                .check_revocation_status(
                    chain.certificates.first().unwrap(),
                    chain.certificates.get(1),
                )
                .await
                .ok()
        } else {
            revocation_checker
                .check_revocation_status(chain.certificates.first().unwrap(), None)
                .await
                .ok()
        };

        Ok(CertificateAnalysisResult {
            chain,
            validation,
            revocation,
        })
    }

    /// Analyze HTTP security headers
    async fn analyze_http_headers(&self) -> Result<HeaderAnalysisResult> {
        use crate::utils::sneaky::SneakyConfig;

        let sneaky_config = SneakyConfig::new(self.args.sneaky);

        let mut analyzer = if !self.args.custom_headers.is_empty() {
            // Parse custom headers from CLI format "Header: Value"
            let custom_headers: Vec<(String, String)> = self
                .args
                .custom_headers
                .iter()
                .filter_map(|h| {
                    let parts: Vec<&str> = h.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                    } else {
                        eprintln!(
                            "Warning: Invalid header format '{}', expected 'Name: Value'",
                            h
                        );
                        None
                    }
                })
                .collect();
            HeaderAnalyzer::with_custom_headers(self.target.clone(), custom_headers)
        } else {
            HeaderAnalyzer::new(self.target.clone())
        };

        // Apply sneaky mode user agent if enabled
        if sneaky_config.is_enabled() {
            analyzer = analyzer.with_user_agent(sneaky_config.user_agent().to_string());
        }

        analyzer.analyze().await
    }

    /// Simulate client connections
    async fn simulate_clients(&self) -> Result<Vec<ClientSimulationResult>> {
        let simulator = ClientSimulator::new(self.target.clone());
        // Simulate popular clients for faster scanning
        simulator.simulate_popular_clients().await
    }

    /// Enumerate signature algorithms
    async fn enumerate_signatures(
        &self,
    ) -> Result<crate::protocols::signatures::SignatureEnumerationResult> {
        use crate::protocols::signatures::SignatureTester;
        let tester = SignatureTester::new(self.target.clone());
        tester.enumerate_signatures().await
    }

    /// Enumerate key exchange groups
    async fn enumerate_groups(&self) -> Result<crate::protocols::groups::GroupEnumerationResult> {
        use crate::protocols::groups::GroupTester;
        let tester = GroupTester::new(self.target.clone());
        tester.enumerate_groups().await
    }

    /// Enumerate client CAs
    async fn enumerate_client_cas(&self) -> Result<crate::protocols::client_cas::ClientCAsResult> {
        use crate::protocols::client_cas::ClientCAsTester;
        let tester = ClientCAsTester::new(self.target.clone());
        tester.enumerate_client_cas().await
    }

    /// Test TLS intolerance
    async fn test_intolerance(
        &self,
    ) -> Result<crate::protocols::intolerance::IntoleranceTestResult> {
        use crate::protocols::intolerance::IntoleranceTester;
        let tester = IntoleranceTester::new(self.target.clone());
        tester.test_all().await
    }

    /// Calculate SSL Labs rating
    fn calculate_rating(&self, results: &ScanResults) -> RatingResult {
        let cert_validation = results.certificate_chain.as_ref().map(|c| &c.validation);

        RatingCalculator::calculate(
            &results.protocols,
            &results.ciphers,
            cert_validation,
            &results.vulnerabilities,
        )
    }

    /// Display protocol test results
    fn display_protocol_results(&self, results: &[ProtocolTestResult]) {
        println!("\n{}", "Protocol Support:".cyan().bold());
        println!("{}", "-".repeat(50));

        for result in results {
            let status = if result.supported {
                "✓ Supported".green()
            } else {
                "✗ Not supported".red()
            };

            let deprecated = if result.protocol.is_deprecated() {
                " (DEPRECATED)".red()
            } else {
                "".normal()
            };

            let timing = if self.args.show_times {
                if let Some(time_ms) = result.handshake_time_ms {
                    format!(" ({}ms)", time_ms).dimmed().to_string()
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };

            println!(
                "  {:<15} {}{}{}",
                result.protocol, status, deprecated, timing
            );
        }

        // Display protocol features (heartbeat extension)
        let heartbeat_detected = results
            .iter()
            .filter(|r| r.supported && r.heartbeat_enabled.is_some())
            .count();

        if heartbeat_detected > 0 {
            println!("\n{}", "Protocol Features:".cyan().bold());
            println!("{}", "-".repeat(50));

            for result in results {
                if result.supported {
                    if let Some(heartbeat_enabled) = result.heartbeat_enabled {
                        let heartbeat_status = if heartbeat_enabled {
                            "Yes".yellow()
                        } else {
                            "No".normal()
                        };

                        println!(
                            "  {:<15} Heartbeat Extension: {}",
                            result.protocol, heartbeat_status
                        );
                    }
                }
            }
        }
    }

    /// Display cipher test results
    fn display_cipher_results(&self, results: &HashMap<Protocol, ProtocolCipherSummary>) {
        for (protocol, summary) in results {
            let timing_info = if self.args.show_times {
                if let Some(avg_ms) = summary.avg_handshake_time_ms {
                    format!(" (avg {}ms)", avg_ms).dimmed().to_string()
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };

            println!(
                "\n{} - {} ciphers{}",
                protocol.to_string().cyan().bold(),
                summary.counts.total,
                timing_info
            );
            println!("{}", "-".repeat(50));

            if summary.counts.total == 0 {
                println!("  {}", "No ciphers supported".red());
                continue;
            }

            println!("  Strength Distribution:");
            if summary.counts.null_ciphers > 0 {
                println!(
                    "    NULL:    {} {}",
                    summary.counts.null_ciphers,
                    "⚠ CRITICAL".red().bold()
                );
            }
            if summary.counts.export_ciphers > 0 {
                println!(
                    "    EXPORT:  {} {}",
                    summary.counts.export_ciphers,
                    "⚠ WEAK".red()
                );
            }
            if summary.counts.low_strength > 0 {
                println!(
                    "    LOW:     {} {}",
                    summary.counts.low_strength,
                    "⚠".yellow()
                );
            }
            if summary.counts.medium_strength > 0 {
                println!("    MEDIUM:  {}", summary.counts.medium_strength);
            }
            if summary.counts.high_strength > 0 {
                println!(
                    "    HIGH:    {} {}",
                    summary.counts.high_strength,
                    "✓".green()
                );
            }

            println!("\n  Security Features:");
            println!(
                "    Forward Secrecy: {}/{} ({}%)",
                summary.counts.forward_secrecy,
                summary.counts.total,
                (summary.counts.forward_secrecy * 100) / summary.counts.total.max(1)
            );
            println!(
                "    AEAD:            {}/{} ({}%)",
                summary.counts.aead,
                summary.counts.total,
                (summary.counts.aead * 100) / summary.counts.total.max(1)
            );

            if summary.server_ordered {
                println!("\n  {}", "✓ Server enforces cipher order".green());
                if let Some(cipher) = &summary.preferred_cipher {
                    let cipher_name = if self.args.iana_names {
                        &cipher.iana_name
                    } else {
                        &cipher.openssl_name
                    };

                    let cipher_id = if self.args.show_cipher_ids {
                        format!(" (0x{})", cipher.hexcode)
                    } else {
                        String::new()
                    };

                    println!(
                        "    Preferred: {}{}",
                        cipher_name.green(),
                        cipher_id.dimmed()
                    );
                }
            } else {
                println!("\n  {}", "⚠ Client chooses cipher order".yellow());
            }
        }
    }

    /// Display certificate analysis results
    fn display_certificate_results(&self, result: &CertificateAnalysisResult) {
        use crate::certificates::validator::IssueSeverity;

        println!("\n{}", "Certificate Analysis:".cyan().bold());
        println!("{}", "=".repeat(50));

        let leaf = result.chain.leaf();
        if let Some(cert) = leaf {
            println!("\n{}", "Certificate Information:".cyan());
            println!("  Subject:    {}", cert.subject);
            println!("  Issuer:     {}", cert.issuer);
            println!("  Valid From: {}", cert.not_before);
            println!("  Valid To:   {}", cert.not_after);

            // Show expiry countdown if available
            if let Some(ref countdown) = cert.expiry_countdown {
                println!("  Expires:    {}", countdown.yellow());
            }

            println!("  Serial:     {}", cert.serial_number);

            if let Some(key_size) = cert.public_key_size {
                let key_color = if key_size >= 2048 {
                    key_size.to_string().green()
                } else {
                    key_size.to_string().red()
                };
                print!("  Key Size:   {} bits ({})", key_color, cert.public_key_algorithm);

                // Show RSA exponent if available
                if let Some(ref exponent) = cert.rsa_exponent {
                    print!(", {}", exponent);
                }
                println!();
            }

            println!("  Signature:  {}", cert.signature_algorithm);

            // Show certificate fingerprint SHA256
            if let Some(ref fingerprint) = cert.fingerprint_sha256 {
                println!("  Fingerprint SHA256: {}", fingerprint);
            }

            // Show pin SHA256 (HPKP)
            if let Some(ref pin) = cert.pin_sha256 {
                println!("  Pin SHA256 (HPKP):  {}", pin);
            }

            // Show AIA URL (Authority Information Access - CA Issuers)
            if let Some(ref aia_url) = cert.aia_url {
                println!("  AIA URL:            {}", aia_url);
            }

            // Show Debian weak key warning if detected
            if let Some(true) = cert.debian_weak_key {
                println!("  {}",  "⚠ WARNING: Debian Weak Key Detected (CVE-2008-0166)".red().bold());
            }

            if !cert.san.is_empty() {
                println!("\n  Subject Alternative Names:");
                for san in &cert.san {
                    println!("    - {}", san);
                }
            }
        }

        println!("\n{}", "Certificate Chain:".cyan());
        println!("  Chain Length: {} certificates", result.chain.chain_length);
        println!("  Chain Size:   {} bytes", result.chain.chain_size_bytes);
        println!(
            "  Complete:     {}",
            if result.chain.is_complete() {
                "✓ Yes".green()
            } else {
                "⚠ No root CA".yellow()
            }
        );

        // Display full chain if --show-certificates is set
        if self.args.show_certificates && result.chain.certificates.len() > 1 {
            println!("\n  {}", "Full Certificate Chain:".cyan());
            for (i, cert) in result.chain.certificates.iter().enumerate() {
                let cert_type = match i {
                    0 => "Leaf Certificate",
                    n if n == result.chain.certificates.len() - 1 => "Root CA",
                    _ => "Intermediate CA",
                };
                println!(
                    "\n  {}. {} ({})",
                    i + 1,
                    cert_type.yellow(),
                    cert.subject.green()
                );
                println!("     Issuer:     {}", cert.issuer);
                println!("     Valid From: {}", cert.not_before);
                println!("     Valid To:   {}", cert.not_after);
                if let Some(key_size) = cert.public_key_size {
                    println!(
                        "     Key:        {} {} bits",
                        cert.public_key_algorithm, key_size
                    );
                }
                println!("     Signature:  {}", cert.signature_algorithm);
            }
        }

        println!("\n{}", "Validation:".cyan());
        let validation_status = if result.validation.valid {
            "✓ Valid".green().bold()
        } else {
            "✗ Invalid".red().bold()
        };
        println!("  Status:           {}", validation_status);
        println!(
            "  Hostname Match:   {}",
            if result.validation.hostname_match {
                "✓ Yes".green()
            } else {
                "✗ No".red()
            }
        );
        println!(
            "  Not Expired:      {}",
            if result.validation.not_expired {
                "✓ Yes".green()
            } else {
                "✗ Expired".red()
            }
        );
        println!(
            "  Trust Chain:      {}",
            if result.validation.trust_chain_valid {
                "✓ Valid".green()
            } else {
                "✗ Invalid".red()
            }
        );

        if let Some(trusted_ca) = &result.validation.trusted_ca {
            println!("  Trusted CA:       {} {}", "✓".green(), trusted_ca);
        }

        // Display per-trust-store breakdown (Gap 2)
        if let Some(ref platform_trust) = result.validation.platform_trust {
            self.display_platform_trust_breakdown(platform_trust);
        }

        if !result.validation.issues.is_empty() {
            println!("\n{}", "  Issues:".yellow());
            for issue in &result.validation.issues {
                let severity_str = match issue.severity {
                    IssueSeverity::Critical => "CRITICAL".red().bold(),
                    IssueSeverity::High => "HIGH".red(),
                    IssueSeverity::Medium => "MEDIUM".yellow(),
                    IssueSeverity::Low => "LOW".normal(),
                    IssueSeverity::Info => "INFO".cyan(),
                };
                println!("    [{}] {}", severity_str, issue.description);
            }
        }

        if let Some(revocation) = &result.revocation {
            println!("\n{}", "Revocation Status:".cyan());
            let status_str = match revocation.status {
                crate::certificates::revocation::RevocationStatus::Good => "✓ Not Revoked".green(),
                crate::certificates::revocation::RevocationStatus::Revoked => {
                    "✗ REVOKED".red().bold()
                }
                crate::certificates::revocation::RevocationStatus::Unknown => "? Unknown".yellow(),
                crate::certificates::revocation::RevocationStatus::Error => "✗ Check Failed".red(),
                crate::certificates::revocation::RevocationStatus::NotChecked => {
                    "- Not Checked".normal()
                }
            };
            println!("  Status:        {}", status_str);
            println!("  Method:        {:?}", revocation.method);
            println!(
                "  Must-Staple:   {}",
                if revocation.must_staple {
                    "Yes".green()
                } else {
                    "No".normal()
                }
            );

            // Extended OCSP info if --ocsp flag is set
            if self.args.ocsp {
                println!("\n  {}", "OCSP Details:".cyan());

                if matches!(
                    revocation.method,
                    crate::certificates::revocation::RevocationMethod::OCSP
                ) {
                    println!(
                        "    Stapling:     {}",
                        if revocation.must_staple {
                            "✓ Required by certificate".green()
                        } else {
                            "Optional".yellow()
                        }
                    );

                    match revocation.status {
                        crate::certificates::revocation::RevocationStatus::Good => {
                            println!(
                                "    Response:     {} Valid certificate, not revoked",
                                "✓".green()
                            );
                        }
                        crate::certificates::revocation::RevocationStatus::Revoked => {
                            println!(
                                "    Response:     {} Certificate has been REVOKED",
                                "✗".red().bold()
                            );
                        }
                        crate::certificates::revocation::RevocationStatus::Unknown => {
                            println!(
                                "    Response:     {} Responder doesn't know about certificate",
                                "?".yellow()
                            );
                        }
                        _ => {}
                    }
                } else if matches!(
                    revocation.method,
                    crate::certificates::revocation::RevocationMethod::CRL
                ) {
                    println!("    Method:       Certificate Revocation List (CRL)");
                    println!("    OCSP:         Not used");
                } else {
                    println!("    Method:       None");
                    println!("    OCSP:         Not configured");
                }
            }
        }
    }

    /// Display HTTP security headers results
    fn display_http_headers_results(&self, result: &HeaderAnalysisResult) {
        use crate::http::headers::IssueSeverity;

        println!("\n{}", "HTTP Security Headers:".cyan().bold());
        println!("{}", "=".repeat(50));

        // Display HTTP response metadata (Gap 5)
        if let Some(status_code) = result.http_status_code {
            let status_color = if (200..300).contains(&status_code) {
                status_code.to_string().green()
            } else if (300..400).contains(&status_code) {
                status_code.to_string().yellow()
            } else if status_code >= 400 {
                status_code.to_string().red()
            } else {
                status_code.to_string().normal()
            };
            println!("  HTTP Status: {}", status_color);
        }

        if let Some(ref redirect_location) = result.redirect_location {
            println!("  Redirect To: {}", redirect_location.yellow());
        }

        if let Some(ref server) = result.server_hostname {
            println!("  Server:      {}", server.cyan());
        }

        if result.http_status_code.is_some()
            || result.redirect_location.is_some()
            || result.server_hostname.is_some() {
            println!();
        }

        // Display grade
        let grade_str = format!("Grade: {:?}", result.grade);
        let grade_colored = match result.grade {
            crate::http::tester::SecurityGrade::A => grade_str.green().bold(),
            crate::http::tester::SecurityGrade::B => grade_str.blue().bold(),
            crate::http::tester::SecurityGrade::C => grade_str.yellow().bold(),
            crate::http::tester::SecurityGrade::D => grade_str.yellow(),
            crate::http::tester::SecurityGrade::F => grade_str.red().bold(),
        };
        println!("  {}", grade_colored);
        println!("  Score: {}/100", result.score);
        println!("  Total Issues: {}", result.issues.len());

        if !result.issues.is_empty() {
            println!("\n{}", "  Issues:".yellow());

            // Group by severity
            let mut by_severity: HashMap<IssueSeverity, Vec<_>> = HashMap::new();
            for issue in &result.issues {
                by_severity.entry(issue.severity).or_default().push(issue);
            }

            // Display Critical and High first
            for severity in [
                IssueSeverity::Critical,
                IssueSeverity::High,
                IssueSeverity::Medium,
                IssueSeverity::Low,
                IssueSeverity::Info,
            ] {
                if let Some(issues) = by_severity.get(&severity) {
                    for issue in issues {
                        let severity_str = match issue.severity {
                            IssueSeverity::Critical => "CRITICAL".red().bold(),
                            IssueSeverity::High => "HIGH".red(),
                            IssueSeverity::Medium => "MEDIUM".yellow(),
                            IssueSeverity::Low => "LOW".normal(),
                            IssueSeverity::Info => "INFO".cyan(),
                        };

                        let issue_icon = match issue.issue_type {
                            crate::http::headers::IssueType::Missing => "✗",
                            crate::http::headers::IssueType::Insecure => "⚠",
                            crate::http::headers::IssueType::Weak => "⚠",
                            crate::http::headers::IssueType::Deprecated => "ℹ",
                            crate::http::headers::IssueType::Invalid => "✗",
                        };

                        println!(
                            "\n    {} {} - {}",
                            issue_icon,
                            issue.header_name.cyan().bold(),
                            severity_str
                        );
                        println!("      {}", issue.description);
                        println!("      Recommendation: {}", issue.recommendation.green());
                    }
                }
            }
        } else {
            println!(
                "\n{}",
                "  ✓ All security headers properly configured!"
                    .green()
                    .bold()
            );
        }

        // Display advanced analysis
        self.display_advanced_header_analysis(result);
    }

    /// Display per-platform trust store breakdown (Gap 2 - SSL Labs style)
    fn display_platform_trust_breakdown(&self, platform_trust: &crate::certificates::trust_stores::TrustValidationResult) {
        use crate::certificates::trust_stores::TrustStore;

        println!("\n{}", "Platform Trust Status:".cyan());

        // Overall trust status
        let overall_status = if platform_trust.overall_trusted {
            if platform_trust.trusted_count == platform_trust.total_platforms {
                "✓ Yes (All platforms)".green().bold()
            } else {
                "⚠ Partial".yellow().bold()
            }
        } else {
            "✗ No".red().bold()
        };
        println!("  Overall Trusted:  {}", overall_status);

        // Get trusted and untrusted platforms
        let trusted = platform_trust.trusted_platforms();
        let untrusted = platform_trust.untrusted_platforms();

        // Display SSL Labs style breakdown: "Trusted: Yes - Mozilla, Apple, Android, Java, Windows"
        if !trusted.is_empty() {
            let trusted_names: Vec<String> = trusted
                .iter()
                .map(|store| {
                    // Use shorter names for SSL Labs style
                    match store {
                        TrustStore::Mozilla => "Mozilla".to_string(),
                        TrustStore::Apple => "Apple".to_string(),
                        TrustStore::Android => "Android".to_string(),
                        TrustStore::Java => "Java".to_string(),
                        TrustStore::Windows => "Windows".to_string(),
                    }
                })
                .collect();

            println!("  Trusted By:       {}", trusted_names.join(", ").green());
        }

        // Display untrusted platforms if any
        if !untrusted.is_empty() {
            let untrusted_names: Vec<String> = untrusted
                .iter()
                .map(|store| {
                    match store {
                        TrustStore::Mozilla => "Mozilla".to_string(),
                        TrustStore::Apple => "Apple".to_string(),
                        TrustStore::Android => "Android".to_string(),
                        TrustStore::Java => "Java".to_string(),
                        TrustStore::Windows => "Windows".to_string(),
                    }
                })
                .collect();

            println!("  Not Trusted By:   {}", untrusted_names.join(", ").red());
        }

        // Display detailed per-platform status
        println!("\n  {}", "Per-Platform Details:".cyan());
        for store in TrustStore::all() {
            if let Some(status) = platform_trust.platform_status.get(&store) {
                let status_symbol = if status.trusted {
                    "✓".green()
                } else {
                    "✗".red()
                };

                let platform_name = format!("{:<18}", store.name());

                if status.trusted {
                    if let Some(ref root) = status.trusted_root {
                        // Truncate long root names for display
                        let root_display = if root.len() > 50 {
                            format!("{}...", &root[..47])
                        } else {
                            root.clone()
                        };
                        println!("    {} {} - {}", status_symbol, platform_name.cyan(), root_display.dimmed());
                    } else {
                        println!("    {} {}", status_symbol, platform_name.cyan());
                    }
                } else {
                    let message_display = if status.message.len() > 50 {
                        format!("{}...", &status.message[..47])
                    } else {
                        status.message.clone()
                    };
                    println!("    {} {} - {}", status_symbol, platform_name.cyan(), message_display.dimmed());
                }
            }
        }
    }

    /// Display advanced header analysis results
    fn display_advanced_header_analysis(&self, result: &HeaderAnalysisResult) {
        use crate::http::headers_advanced::Grade;

        // HSTS Analysis
        if let Some(hsts) = &result.hsts_analysis {
            println!("\n{}", "HSTS Analysis:".cyan());
            let status = if hsts.enabled {
                format!("✓ Enabled - {}", hsts.details).green()
            } else {
                format!("✗ Disabled - {}", hsts.details).red()
            };
            println!("  Status: {}", status);
            println!("  Grade:  {:?}", hsts.grade);
            if hsts.enabled {
                if let Some(max_age) = hsts.max_age {
                    println!("    max-age:          {} ({} days)", max_age, max_age / 86400);
                }
                println!("    includeSubDomains: {}", hsts.include_subdomains);
                println!("    preload:           {}", hsts.preload);
            }
        }

        // HPKP Analysis (informational)
        if let Some(hpkp) = &result.hpkp_analysis {
            if hpkp.enabled {
                println!("\n{}", "HPKP Analysis:".cyan());
                println!("  {} {}", "⚠".yellow(), hpkp.details.yellow());
                println!("  Pins: {}", hpkp.pins.len());
            }
        }

        // Cookie Analysis
        if let Some(cookies) = &result.cookie_analysis {
            println!("\n{}", "Cookie Security:".cyan());
            println!("  {}", cookies.details);
            println!("  Grade: {:?}", cookies.grade);

            if !cookies.cookies.is_empty() {
                println!("\n  Cookies:");
                for cookie in &cookies.cookies {
                    let security_flags = format!(
                        "{}{}{}",
                        if cookie.secure { "Secure " } else { "" },
                        if cookie.httponly { "HttpOnly " } else { "" },
                        if cookie.samesite.is_some() {
                            format!("SameSite={}", cookie.samesite.as_ref().unwrap())
                        } else {
                            String::new()
                        }
                    );

                    let status = if cookie.secure && cookie.httponly && cookie.samesite.is_some() {
                        "✓".green()
                    } else {
                        "⚠".yellow()
                    };

                    println!(
                        "    {} {} [{}]",
                        status,
                        cookie.name.cyan(),
                        if security_flags.is_empty() {
                            "no security flags".red().to_string()
                        } else {
                            security_flags
                        }
                    );
                }
            }
        }

        // Date/Time Check
        if let Some(datetime) = &result.datetime_check {
            if let Some(server_date) = &datetime.server_date {
                println!("\n{}", "Server Time:".cyan());
                let sync_status = if datetime.synchronized {
                    "✓ Synchronized".green()
                } else {
                    "⚠ Out of sync".yellow()
                };
                println!("  {}", sync_status);
                println!("  Server Date: {}", server_date);
                if let Some(skew) = datetime.skew_seconds {
                    println!("  Time Skew:   {} seconds", skew);
                }
            }
        }

        // Banner Detection
        if let Some(banners) = &result.banner_detection {
            println!("\n{}", "Server Banners:".cyan());
            let grade_color = match banners.grade {
                Grade::A => "Grade A".green().bold(),
                Grade::B => "Grade B".blue(),
                Grade::C => "Grade C".yellow(),
                Grade::D => "Grade D".yellow(),
                Grade::F => "Grade F".red().bold(),
            };
            println!("  {}", grade_color);

            if let Some(server) = &banners.server {
                println!("  Server:      {}", server);
            }
            if let Some(powered_by) = &banners.powered_by {
                println!("  X-Powered-By: {}", powered_by);
            }
            if let Some(app) = &banners.application {
                println!("  Application:  {}", app);
            }

            if banners.version_exposed {
                println!("  {} Version information exposed", "⚠".red());
            } else {
                println!("  {} Version information hidden", "✓".green());
            }
        }

        // Reverse Proxy Detection
        if let Some(proxy) = &result.reverse_proxy_detection {
            if proxy.detected {
                println!("\n{}", "Reverse Proxy:".cyan());
                println!("  {}", proxy.details);
                if let Some(proxy_type) = &proxy.proxy_type {
                    println!("  Type: {}", proxy_type.cyan());
                }
                if let Some(via) = &proxy.via_header {
                    println!("  Via: {}", via);
                }
                let mut headers_found = Vec::new();
                if proxy.x_forwarded_for {
                    headers_found.push("X-Forwarded-For");
                }
                if proxy.x_real_ip {
                    headers_found.push("X-Real-IP");
                }
                if proxy.x_forwarded_proto {
                    headers_found.push("X-Forwarded-Proto");
                }
                if !headers_found.is_empty() {
                    println!("  Headers: {}", headers_found.join(", "));
                }
            }
        }
    }

    /// Display client simulation results
    fn display_client_simulation_results(&self, results: &[ClientSimulationResult]) {
        println!("\n{}", "Client Simulation:".cyan().bold());
        println!("{}", "=".repeat(50));

        let mut successful = 0;
        let mut failed = 0;

        for result in results {
            if result.is_success() {
                successful += 1;
                let handshake_time = result
                    .handshake_time_ms
                    .map(|ms| format!(" ({}ms)", ms))
                    .unwrap_or_default();

                println!(
                    "  {} {} - {} / {}{}",
                    "✓".green(),
                    result.client_name.cyan(),
                    result
                        .protocol
                        .as_ref()
                        .map(|p| p.to_string())
                        .unwrap_or_default(),
                    result.cipher.as_ref().unwrap_or(&"Unknown".to_string()),
                    handshake_time.dimmed()
                );
            } else {
                failed += 1;
                println!(
                    "  {} {} - {}",
                    "✗".red(),
                    result.client_name.cyan(),
                    result
                        .error
                        .as_ref()
                        .unwrap_or(&"Connection failed".to_string())
                        .red()
                );
            }
        }

        println!("\n{}", "=".repeat(50));
        println!(
            "  Total: {} | {} Successful | {} Failed",
            results.len(),
            successful.to_string().green(),
            failed.to_string().red()
        );

        if successful == results.len() {
            println!(
                "\n{}",
                "  ✓ All clients can connect successfully!".green().bold()
            );
        } else if failed == results.len() {
            println!("\n{}", "  ✗ No clients can connect!".red().bold());
        }
    }

    /// Display SSL Labs rating results
    fn display_rating_results(&self, rating: &RatingResult) {
        use crate::rating::Grade;

        println!("\n{}", "SSL Labs Rating:".cyan().bold());
        println!("{}", "=".repeat(50));

        // Display overall grade with color
        let grade_str = format!("Overall Grade: {}", rating.grade);
        let grade_colored = match rating.grade {
            Grade::APlus | Grade::A => grade_str.green().bold(),
            Grade::AMinus | Grade::B => grade_str.blue().bold(),
            Grade::C => grade_str.yellow(),
            Grade::D | Grade::E => grade_str.yellow(),
            Grade::F | Grade::T | Grade::M => grade_str.red().bold(),
        };

        println!("\n  {}", grade_colored);
        println!("  {}", rating.grade.description().dimmed());
        println!("\n  Overall Score: {}/100", rating.score);

        // Component scores
        println!("\n{}", "  Component Scores:".cyan());
        println!("    Certificate:    {}/100", rating.certificate_score);
        println!("    Protocols:      {}/100", rating.protocol_score);
        println!("    Key Exchange:   {}/100", rating.key_exchange_score);
        println!("    Cipher Strength: {}/100", rating.cipher_strength_score);

        // Display warnings if any
        if !rating.warnings.is_empty() {
            println!("\n{}", "  Warnings:".yellow());
            for warning in &rating.warnings {
                println!("    ⚠ {}", warning.red());
            }
        }

        println!();
    }

    /// Display vulnerability results
    fn display_vulnerability_results(&self, results: &[VulnerabilityResult]) {
        use crate::vulnerabilities::Severity;

        println!("\n{}", "Vulnerability Assessment:".cyan().bold());
        println!("{}", "=".repeat(50));

        let mut vulnerable_count = 0;
        let mut by_severity = HashMap::new();

        for result in results {
            if result.vulnerable {
                vulnerable_count += 1;
                *by_severity.entry(result.severity).or_insert(0) += 1;

                let severity_str = match result.severity {
                    Severity::Critical => "CRITICAL".red().bold(),
                    Severity::High => "HIGH".red(),
                    Severity::Medium => "MEDIUM".yellow(),
                    Severity::Low => "LOW".normal(),
                    Severity::Info => "INFO".cyan(),
                };

                println!("\n{} {:?}", "✗".red().bold(), result.vuln_type);
                println!("  Severity: {}", severity_str);
                if let Some(cve) = &result.cve {
                    println!("  CVE:      {}", cve);
                }
                println!("  Details:  {}", result.details);
            }
        }

        println!("\n{}", "=".repeat(50));
        if vulnerable_count == 0 {
            println!("{}", "✓ No vulnerabilities found!".green().bold());
        } else {
            println!(
                "{} {} vulnerability(ies) found",
                "⚠".red().bold(),
                vulnerable_count.to_string().red().bold()
            );

            if let Some(count) = by_severity.get(&Severity::Critical) {
                println!("  Critical: {}", count.to_string().red().bold());
            }
            if let Some(count) = by_severity.get(&Severity::High) {
                println!("  High:     {}", count.to_string().red());
            }
            if let Some(count) = by_severity.get(&Severity::Medium) {
                println!("  Medium:   {}", count.to_string().yellow());
            }
            if let Some(count) = by_severity.get(&Severity::Low) {
                println!("  Low:      {}", count);
            }
        }
    }

    /// Display signature algorithm results
    fn display_signature_results(
        &self,
        results: &crate::protocols::signatures::SignatureEnumerationResult,
    ) {
        println!("\n{}", "Signature Algorithms:".cyan().bold());
        println!("{}", "=".repeat(50));

        let supported: Vec<_> = results.algorithms.iter().filter(|a| a.supported).collect();
        let total = results.algorithms.len();

        println!("  Supported: {}/{}", supported.len(), total);
        println!();

        for algo in &results.algorithms {
            let status = if algo.supported {
                "✓".green()
            } else {
                "✗".red()
            };
            println!("  {} {:<30} (0x{:04x})", status, algo.name, algo.iana_value);
        }
    }

    /// Display key exchange group results
    fn display_group_results(&self, results: &crate::protocols::groups::GroupEnumerationResult) {
        use crate::protocols::groups::GroupType;

        println!("\n{}", "Key Exchange Groups:".cyan().bold());
        println!("{}", "=".repeat(50));

        let supported: Vec<_> = results.groups.iter().filter(|g| g.supported).collect();
        let total = results.groups.len();

        println!("  Supported: {}/{}", supported.len(), total);

        // Group by type
        let ec_groups: Vec<_> = results
            .groups
            .iter()
            .filter(|g| matches!(g.group_type, GroupType::EllipticCurve))
            .collect();
        let ff_groups: Vec<_> = results
            .groups
            .iter()
            .filter(|g| matches!(g.group_type, GroupType::FiniteField))
            .collect();
        let pq_groups: Vec<_> = results
            .groups
            .iter()
            .filter(|g| matches!(g.group_type, GroupType::PostQuantum))
            .collect();

        if !ec_groups.is_empty() {
            println!("\n  {}", "Elliptic Curve Groups:".cyan());
            for group in ec_groups {
                let status = if group.supported {
                    "✓".green()
                } else {
                    "✗".red()
                };
                println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
            }
        }

        if !ff_groups.is_empty() {
            println!("\n  {}", "Finite Field (DHE) Groups:".cyan());
            for group in ff_groups {
                let status = if group.supported {
                    "✓".green()
                } else {
                    "✗".red()
                };
                println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
            }
        }

        if !pq_groups.is_empty() {
            println!("\n  {}", "Post-Quantum Groups:".cyan());
            for group in pq_groups {
                let status = if group.supported {
                    "✓".green()
                } else {
                    "✗".red()
                };
                println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
            }
        }
    }

    /// Display client CAs results
    fn display_client_cas_results(&self, results: &crate::protocols::client_cas::ClientCAsResult) {
        println!("\n{}", "Client Certificate CAs:".cyan().bold());
        println!("{}", "=".repeat(50));

        if !results.requires_client_auth {
            println!(
                "  {}",
                "Server does not require client authentication".yellow()
            );
            return;
        }

        println!(
            "  {} Server requires client certificate authentication",
            "✓".green()
        );
        println!("  Acceptable CAs: {}", results.cas.len());

        if results.cas.is_empty() {
            println!("\n  {}", "No CA restrictions (any CA accepted)".cyan());
            return;
        }

        println!();
        for (i, ca) in results.cas.iter().enumerate() {
            println!("  {}. Client CA:", i + 1);

            if let Some(cn) = &ca.common_name {
                println!("     CN:  {}", cn.green());
            }

            if let Some(org) = &ca.organization {
                println!("     Org: {}", org.cyan());
            }

            // Show abbreviated DN hex
            let dn_preview = if ca.distinguished_name.len() > 60 {
                format!("{}...", &ca.distinguished_name[..60])
            } else {
                ca.distinguished_name.clone()
            };
            println!("     DN:  {}", dn_preview.dimmed());
        }
    }

    /// Display TLS intolerance test results
    fn display_intolerance_results(
        &self,
        results: &crate::protocols::intolerance::IntoleranceTestResult,
    ) {
        println!("\n{}", "TLS Intolerance Tests:".cyan().bold());
        println!("{}", "=".repeat(50));

        let mut issues_found = 0;

        // Extension intolerance
        if results.extension_intolerance {
            issues_found += 1;
            println!("\n{} {}", "✗".red().bold(), "Extension Intolerance".red());
            println!(
                "  {}",
                "Server rejects ClientHellos with certain extensions".yellow()
            );
            if let Some(detail) = results.details.get("extension_intolerance") {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!(
                "\n{} {}",
                "✓".green(),
                "Extension Intolerance".green()
            );
            println!("  Server properly handles TLS extensions");
        }

        // Version intolerance
        if results.version_intolerance {
            issues_found += 1;
            println!("\n{} {}", "✗".red().bold(), "Version Intolerance".red());
            println!(
                "  {}",
                "Server rejects high version numbers in record layer".yellow()
            );
            if let Some(detail) = results.details.get("version_intolerance") {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!("\n{} {}", "✓".green(), "Version Intolerance".green());
            println!("  Server properly handles version negotiation");
        }

        // Long handshake intolerance
        if results.long_handshake_intolerance {
            issues_found += 1;
            println!(
                "\n{} {}",
                "✗".red().bold(),
                "Long Handshake Intolerance".red()
            );
            println!(
                "  {}",
                "Server rejects ClientHello messages > 256 bytes".yellow()
            );
            if let Some(detail) = results.details.get("long_handshake_intolerance") {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!(
                "\n{} {}",
                "✓".green(),
                "Long Handshake Intolerance".green()
            );
            println!("  Server accepts long ClientHello messages");
        }

        // Incorrect SNI alerts
        if results.incorrect_sni_alerts {
            issues_found += 1;
            println!(
                "\n{} {}",
                "✗".red().bold(),
                "Incorrect SNI Alerts".red()
            );
            println!(
                "  {}",
                "Server sends wrong alert type for SNI failures".yellow()
            );
            if let Some(detail) = results.details.get("incorrect_sni_alerts") {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!("\n{} {}", "✓".green(), "Incorrect SNI Alerts".green());
            println!("  Server sends correct alerts for SNI issues");
        }

        // Common DH primes
        if results.uses_common_dh_primes {
            issues_found += 1;
            println!(
                "\n{} {}",
                "✗".red().bold(),
                "Common DH Primes".red().bold()
            );
            println!(
                "  {}",
                "Server uses known weak DH primes (CRITICAL SECURITY ISSUE)"
                    .red()
                    .bold()
            );
            println!("  This makes the server vulnerable to pre-computation attacks");
            if let Some(detail) = results.details.get("uses_common_dh_primes") {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!("\n{} {}", "✓".green(), "Common DH Primes".green());
            println!("  Server does not use known weak DH primes");
        }

        // Summary
        println!("\n{}", "=".repeat(50));
        if issues_found == 0 {
            println!(
                "{}",
                "✓ No TLS intolerance issues detected!".green().bold()
            );
        } else {
            println!(
                "{} {} intolerance issue(s) detected",
                "⚠".yellow().bold(),
                issues_found.to_string().yellow().bold()
            );
            println!("  These issues may cause connectivity problems with some clients");
        }
    }
}

/// Certificate analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAnalysisResult {
    pub chain: CertificateChain,
    pub validation: ValidationResult,
    pub revocation: Option<RevocationResult>,
}

/// Scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub protocols: Vec<ProtocolTestResult>,
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,
    pub certificate_chain: Option<CertificateAnalysisResult>,
    pub http_headers: Option<HeaderAnalysisResult>,
    pub vulnerabilities: Vec<VulnerabilityResult>,
    pub client_simulations: Option<Vec<ClientSimulationResult>>,
    pub rating: Option<RatingResult>,
    pub scan_time_ms: u64,
    pub signature_algorithms: Option<crate::protocols::signatures::SignatureEnumerationResult>,
    pub key_exchange_groups: Option<crate::protocols::groups::GroupEnumerationResult>,
    pub client_cas: Option<crate::protocols::client_cas::ClientCAsResult>,
    pub intolerance: Option<crate::protocols::intolerance::IntoleranceTestResult>,
}

impl ScanResults {
    /// Display results summary
    pub fn display(&self) -> Result<()> {
        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", "Scan Complete".cyan().bold());
        println!("{}", "=".repeat(60).cyan());
        println!("Target:          {}", self.target.green());
        println!("Scan Time:       {} ms", self.scan_time_ms);
        println!("Protocols:       {} tested", self.protocols.len());
        println!("Ciphers:         {} protocols analyzed", self.ciphers.len());

        if let Some(cert) = &self.certificate_chain {
            let cert_status = if cert.validation.valid {
                "✓ Valid".green()
            } else {
                "✗ Invalid".red()
            };
            println!(
                "Certificate:     {} ({} certs, {} bytes)",
                cert_status, cert.chain.chain_length, cert.chain.chain_size_bytes
            );
        }

        if let Some(headers) = &self.http_headers {
            let grade_str = format!("Grade {:?}", headers.grade);
            let grade_colored = match headers.grade {
                crate::http::tester::SecurityGrade::A => grade_str.green(),
                crate::http::tester::SecurityGrade::B => grade_str.blue(),
                crate::http::tester::SecurityGrade::C => grade_str.yellow(),
                crate::http::tester::SecurityGrade::D | crate::http::tester::SecurityGrade::F => {
                    grade_str.red()
                }
            };
            println!(
                "HTTP Headers:    {} ({} issues)",
                grade_colored,
                headers.issues.len()
            );
        }

        println!(
            "Vulnerabilities: {} checks performed",
            self.vulnerabilities.len()
        );

        if let Some(clients) = &self.client_simulations {
            let successful = clients.iter().filter(|c| c.success).count();
            let total = clients.len();
            let status_str = if successful == total {
                format!("{}/{} clients", successful, total).green()
            } else if successful == 0 {
                format!("{}/{} clients", successful, total).red()
            } else {
                format!("{}/{} clients", successful, total).yellow()
            };
            println!("Client Sims:     {}", status_str);
        }

        if let Some(rating) = &self.rating {
            use crate::rating::Grade;
            let grade_str = format!("Grade {}", rating.grade);
            let grade_colored = match rating.grade {
                Grade::APlus | Grade::A => grade_str.green().bold(),
                Grade::AMinus | Grade::B => grade_str.blue().bold(),
                Grade::C => grade_str.yellow(),
                Grade::D | Grade::E | Grade::F => grade_str.red(),
                Grade::T | Grade::M => grade_str.red().bold(),
            };
            println!("SSL Labs Rating: {} ({}/100)", grade_colored, rating.score);
        }

        println!("{}", "=".repeat(60).cyan());

        Ok(())
    }

    /// Export to JSON
    pub fn to_json(&self, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(self)?)
        } else {
            Ok(serde_json::to_string(self)?)
        }
    }

    /// Export to CSV (simplified)
    pub fn to_csv(&self) -> Result<String> {
        let mut csv = String::new();

        // Vulnerabilities CSV
        csv.push_str("Type,Severity,Vulnerable,CVE,Details\n");
        for vuln in &self.vulnerabilities {
            csv.push_str(&format!(
                "{:?},{:?},{},{},{}\n",
                vuln.vuln_type,
                vuln.severity,
                vuln.vulnerable,
                vuln.cve.as_deref().unwrap_or("N/A"),
                vuln.details.replace(',', ";")
            ));
        }

        Ok(csv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_results_json() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1234,
            ..Default::default()
        };

        let json = results.to_json(false).unwrap();
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_scan_results_csv() {
        let results = ScanResults::default();
        let csv = results.to_csv().unwrap();
        assert!(csv.contains("Type,Severity"));
    }
}
