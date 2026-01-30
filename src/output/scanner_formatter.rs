// Output module - Scanner result formatting (presentation layer)
//
// This module contains all display methods extracted from Scanner to follow
// the Single Responsibility Principle. Scanner handles scanning logic,
// ScannerFormatter handles presentation logic.
//
// Organization:
// 1. Common formatting helpers (top-level functions)
// 2. Domain-specific formatting helpers (structs with focused responsibilities)
// 3. ScannerFormatter (orchestrator that delegates to helpers)

use crate::Args;
use crate::certificates::parser::{CertificateChain, CertificateInfo};
use crate::certificates::revocation::RevocationResult;
use crate::certificates::trust_stores::TrustValidationResult;
use crate::certificates::validator::ValidationResult;
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::client_sim::simulator::ClientSimulationResult;
use crate::fingerprint::{
    Ja3Fingerprint, Ja3Signature, Ja3sFingerprint, Ja3sSignature, JarmFingerprint,
};
use crate::http::tester::HeaderAnalysisResult;
use crate::protocols::alpn::AlpnReport;
use crate::protocols::client_cas::ClientCAsResult;
use crate::protocols::groups::GroupEnumerationResult;
use crate::protocols::intolerance::IntoleranceTestResult;
use crate::protocols::signatures::SignatureEnumerationResult;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::RatingResult;
use crate::scanner::CertificateAnalysisResult;
use crate::vulnerabilities::VulnerabilityResult;
use colored::*;
use std::collections::HashMap;

// ============================================================================
// SECTION 1: Common Formatting Helpers
// ============================================================================

/// Format a boolean value as a colored Y/X indicator with descriptive text
fn format_bool_indicator(value: bool, yes_text: &str, no_text: &str) -> ColoredString {
    if value {
        format!("Y {}", yes_text).green()
    } else {
        format!("X {}", no_text).red()
    }
}

/// Format a status indicator (Y/X) with color based on boolean value
fn format_status_indicator(value: bool) -> ColoredString {
    if value { "Y".green() } else { "X".red() }
}

/// Truncate a string with ellipsis if it exceeds max length
fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

/// Print a section header with consistent formatting
fn print_section_header(title: &str) {
    println!("\n{}", title.cyan().bold());
    println!("{}", "=".repeat(50));
}

/// Format optional timing information for display
fn format_timing(show_times: bool, time_ms: Option<u64>) -> String {
    if show_times {
        time_ms
            .map(|ms| format!(" ({}ms)", ms).dimmed().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    }
}

/// Format average timing information for display
fn format_avg_timing(show_times: bool, avg_ms: Option<u64>) -> String {
    if show_times {
        avg_ms
            .map(|ms| format!(" (avg {}ms)", ms).dimmed().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    }
}

// ============================================================================
// SECTION 2: Grade Formatting Helpers
// ============================================================================

/// Format SSL Labs grade with appropriate color
fn format_ssl_grade(grade: &crate::rating::Grade) -> ColoredString {
    use crate::rating::Grade;
    let grade_str = format!("Grade {}", grade);
    match grade {
        Grade::APlus | Grade::A => grade_str.green().bold(),
        Grade::AMinus | Grade::B => grade_str.blue().bold(),
        Grade::C => grade_str.yellow(),
        Grade::D | Grade::E => grade_str.yellow(),
        Grade::F | Grade::T | Grade::M => grade_str.red().bold(),
    }
}

/// Format HTTP security grade with appropriate color
fn format_http_grade(grade: &crate::http::tester::SecurityGrade) -> ColoredString {
    use crate::http::tester::SecurityGrade;
    let grade_str = format!("Grade {:?}", grade);
    match grade {
        SecurityGrade::A => grade_str.green().bold(),
        SecurityGrade::B => grade_str.blue().bold(),
        SecurityGrade::C => grade_str.yellow().bold(),
        SecurityGrade::D => grade_str.yellow(),
        SecurityGrade::F => grade_str.red().bold(),
    }
}

/// Format advanced header analysis grade
fn format_advanced_grade(grade: &crate::http::headers_advanced::Grade) -> ColoredString {
    use crate::http::headers_advanced::Grade;
    match grade {
        Grade::A => "Grade A".green().bold(),
        Grade::B => "Grade B".blue(),
        Grade::C => "Grade C".yellow(),
        Grade::D => "Grade D".yellow(),
        Grade::F => "Grade F".red().bold(),
    }
}

// ============================================================================
// SECTION 3: Threat Level Formatting Helper
// ============================================================================

/// Format threat level with appropriate color
fn format_threat_level(threat_level: &str) -> ColoredString {
    match threat_level.to_lowercase().as_str() {
        "critical" => threat_level.red().bold(),
        "high" => threat_level.red(),
        "medium" => threat_level.yellow(),
        "low" => threat_level.green(),
        _ => threat_level.normal(),
    }
}

// ============================================================================
// SECTION 4: Protocol Formatting Helpers
// ============================================================================

/// Helper struct for displaying intolerance check results
struct IntoleranceCheck<'a> {
    name: &'a str,
    is_intolerant: bool,
    success_message: &'a str,
    failure_message: &'a str,
    detail_key: &'a str,
    is_critical: bool,
}

impl<'a> IntoleranceCheck<'a> {
    fn display(&self, details: &HashMap<String, String>) {
        if self.is_intolerant {
            let name_colored = if self.is_critical {
                self.name.red().bold()
            } else {
                self.name.red()
            };
            println!("\n{} {}", "X".red().bold(), name_colored);

            let message_colored = if self.is_critical {
                self.failure_message.red().bold()
            } else {
                self.failure_message.yellow()
            };
            println!("  {}", message_colored);

            if let Some(detail) = details.get(self.detail_key) {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!("\n{} {}", "Y".green(), self.name.green());
            println!("  {}", self.success_message);
        }
    }
}

/// Build intolerance checks configuration
fn build_intolerance_checks(results: &IntoleranceTestResult) -> Vec<IntoleranceCheck<'_>> {
    vec![
        IntoleranceCheck {
            name: "Extension Intolerance",
            is_intolerant: results.extension_intolerance,
            success_message: "Server properly handles TLS extensions",
            failure_message: "Server rejects ClientHellos with certain extensions",
            detail_key: "extension_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Version Intolerance",
            is_intolerant: results.version_intolerance,
            success_message: "Server properly handles version negotiation",
            failure_message: "Server rejects high version numbers in record layer",
            detail_key: "version_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Long Handshake Intolerance",
            is_intolerant: results.long_handshake_intolerance,
            success_message: "Server accepts long ClientHello messages",
            failure_message: "Server rejects ClientHello messages > 256 bytes",
            detail_key: "long_handshake_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Incorrect SNI Alerts",
            is_intolerant: results.incorrect_sni_alerts,
            success_message: "Server sends correct alerts for SNI issues",
            failure_message: "Server sends wrong alert type for SNI failures",
            detail_key: "incorrect_sni_alerts",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Common DH Primes",
            is_intolerant: results.uses_common_dh_primes,
            success_message: "Server does not use known weak DH primes",
            failure_message: "Server uses known weak DH primes (CRITICAL SECURITY ISSUE)",
            detail_key: "uses_common_dh_primes",
            is_critical: true,
        },
    ]
}

// ============================================================================
// SECTION 5: Certificate Formatting Helpers
// ============================================================================

/// Format key size with color based on security strength
fn format_key_size(key_size: usize) -> ColoredString {
    if key_size >= 2048 {
        key_size.to_string().green()
    } else {
        key_size.to_string().red()
    }
}

/// Format revocation status with appropriate indicator
fn format_revocation_status(
    status: &crate::certificates::revocation::RevocationStatus,
) -> ColoredString {
    use crate::certificates::revocation::RevocationStatus;
    match status {
        RevocationStatus::Good => "Y Not Revoked".green(),
        RevocationStatus::Revoked => "X REVOKED".red().bold(),
        RevocationStatus::Unknown => "? Unknown".yellow(),
        RevocationStatus::Error => "X Check Failed".red(),
        RevocationStatus::NotChecked => "- Not Checked".normal(),
    }
}

/// Determine certificate type based on position in chain
fn get_cert_type(index: usize, chain_length: usize) -> &'static str {
    match index {
        0 => "Leaf Certificate",
        n if n == chain_length - 1 => "Root CA",
        _ => "Intermediate CA",
    }
}

// ============================================================================
// SECTION 6: Cipher Strength Formatting Helpers
// ============================================================================

/// Display cipher strength distribution with security indicators
fn display_cipher_strength_distribution(counts: &crate::ciphers::tester::CipherCounts) {
    println!("  Strength Distribution:");

    if counts.null_ciphers > 0 {
        println!(
            "    NULL:    {} {}",
            counts.null_ciphers,
            "!! CRITICAL".red().bold()
        );
    }
    if counts.export_ciphers > 0 {
        println!("    EXPORT:  {} {}", counts.export_ciphers, "!! WEAK".red());
    }
    if counts.low_strength > 0 {
        println!("    LOW:     {} {}", counts.low_strength, "!".yellow());
    }
    if counts.medium_strength > 0 {
        println!("    MEDIUM:  {}", counts.medium_strength);
    }
    if counts.high_strength > 0 {
        println!("    HIGH:    {} {}", counts.high_strength, "Y".green());
    }
}

/// Display cipher security features (forward secrecy, AEAD)
fn display_cipher_security_features(counts: &crate::ciphers::tester::CipherCounts) {
    let total = counts.total.max(1);
    println!("\n  Security Features:");
    println!(
        "    Forward Secrecy: {}/{} ({}%)",
        counts.forward_secrecy,
        counts.total,
        (counts.forward_secrecy * 100) / total
    );
    println!(
        "    AEAD:            {}/{} ({}%)",
        counts.aead,
        counts.total,
        (counts.aead * 100) / total
    );
}

// ============================================================================
// SECTION 7: HTTP Status Formatting Helper
// ============================================================================

/// Format HTTP status code with appropriate color
fn format_http_status(status_code: u16) -> ColoredString {
    let status_str = status_code.to_string();
    if (200..300).contains(&status_code) {
        status_str.green()
    } else if (300..400).contains(&status_code) {
        status_str.yellow()
    } else if status_code >= 400 {
        status_str.red()
    } else {
        status_str.normal()
    }
}

/// Format HTTP issue type icon
fn format_http_issue_icon(issue_type: &crate::http::headers::IssueType) -> &'static str {
    use crate::http::headers::IssueType;
    match issue_type {
        IssueType::Missing | IssueType::Invalid => "X",
        IssueType::Insecure | IssueType::Weak => "!",
        IssueType::Deprecated => "i",
    }
}

// ============================================================================
// SECTION 8: Client Simulation Summary Helper
// ============================================================================

/// Calculate and format client simulation summary statistics
fn format_client_sim_summary(successful: usize, total: usize) -> ColoredString {
    if successful == total {
        format!("{}/{} clients", successful, total).green()
    } else if successful == 0 {
        format!("{}/{} clients", successful, total).red()
    } else {
        format!("{}/{} clients", successful, total).yellow()
    }
}

// ============================================================================
// SECTION 9: ScannerFormatter - Main Orchestrator
// ============================================================================

/// Formatter for scanner output - handles all display/presentation logic
///
/// This struct implements the presentation layer for scan results, keeping
/// display logic separate from the scanning domain logic in Scanner.
pub struct ScannerFormatter<'a> {
    args: &'a Args,
}

impl<'a> ScannerFormatter<'a> {
    /// Create a new ScannerFormatter with the given Args configuration
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    // ------------------------------------------------------------------------
    // Scan Header and Progress Methods
    // ------------------------------------------------------------------------

    /// Print scan header with target information
    pub fn print_scan_header(&self, hostname: &str, port: u16, starttls_protocol: Option<&str>) {
        if let Some(starttls_proto) = starttls_protocol {
            println!(
                "\n{} {}:{} ({})\n",
                "Starting scan of".cyan().bold(),
                hostname.green().bold(),
                port.to_string().green().bold(),
                format!("STARTTLS {}", starttls_proto).yellow()
            );
            println!(
                "  {} STARTTLS negotiation will be performed before TLS handshake",
                "i".cyan()
            );
        } else {
            println!(
                "\n{} {}:{}\n",
                "Starting scan of".cyan().bold(),
                hostname.green().bold(),
                port.to_string().green().bold()
            );
        }
    }

    /// Print scan phase progress message
    pub fn print_phase_progress(&self, message: &str) {
        println!("{}", message.yellow().bold());
    }

    /// Print phase progress with newline prefix
    pub fn print_phase_progress_nl(&self, message: &str) {
        println!("\n{}", message.yellow().bold());
    }

    /// Print error message (red)
    pub fn print_error(&self, message: &str) {
        println!("  {}", message.red());
    }

    // ------------------------------------------------------------------------
    // Results Summary Display
    // ------------------------------------------------------------------------

    /// Display scan results summary
    pub fn display_results_summary(&self, results: &crate::scanner::ScanResults) {
        println!("\n{}", "=".repeat(60).cyan());
        println!("{}", "Scan Complete".cyan().bold());
        println!("{}", "=".repeat(60).cyan());
        println!("Target:          {}", results.target.green());
        println!("Scan Time:       {} ms", results.scan_time_ms);
        println!("Protocols:       {} tested", results.protocols.len());
        println!(
            "Ciphers:         {} protocols analyzed",
            results.ciphers.len()
        );

        self.display_certificate_summary(&results.certificate_chain);
        self.display_http_headers_summary(results.http_headers());

        println!(
            "Vulnerabilities: {} checks performed",
            results.vulnerabilities.len()
        );

        self.display_client_sim_summary(results.client_simulations());
        self.display_rating_summary(results.ssl_rating());
        self.display_ja3_summary(results.ja3_fingerprint(), results.ja3_match());

        println!("{}", "=".repeat(60).cyan());
    }

    /// Display certificate summary in results
    fn display_certificate_summary(&self, cert: &Option<CertificateAnalysisResult>) {
        if let Some(cert) = cert {
            let cert_status = if cert.validation.valid {
                "Valid".green()
            } else {
                "Invalid".red()
            };
            println!(
                "Certificate:     {} ({} certs, {} bytes)",
                cert_status, cert.chain.chain_length, cert.chain.chain_size_bytes
            );
        }
    }

    /// Display HTTP headers summary in results
    fn display_http_headers_summary(&self, headers: Option<&HeaderAnalysisResult>) {
        if let Some(headers) = headers {
            let grade_colored = format_http_grade(&headers.grade);
            println!(
                "HTTP Headers:    {} ({} issues)",
                grade_colored,
                headers.issues.len()
            );
        }
    }

    /// Display client simulation summary in results
    fn display_client_sim_summary(&self, clients: Option<&Vec<ClientSimulationResult>>) {
        if let Some(clients) = clients {
            let successful = clients.iter().filter(|c| c.success).count();
            let status_str = format_client_sim_summary(successful, clients.len());
            println!("Client Sims:     {}", status_str);
        }
    }

    /// Display rating summary in results
    fn display_rating_summary(&self, rating: Option<&RatingResult>) {
        if let Some(rating) = rating {
            let grade_colored = format_ssl_grade(&rating.grade);
            println!("SSL Labs Rating: {} ({}/100)", grade_colored, rating.score);
        }
    }

    /// Display JA3 summary in results
    fn display_ja3_summary(&self, ja3: Option<&Ja3Fingerprint>, ja3_match: Option<&Ja3Signature>) {
        if let Some(ja3) = ja3 {
            let match_str = if let Some(sig) = ja3_match {
                let threat_indicator = match sig.threat_level.as_str() {
                    "critical" | "high" => "!".red().to_string(),
                    "medium" => "!".yellow().to_string(),
                    _ => "Y".green().to_string(),
                };
                format!("{} {}", threat_indicator, sig.name)
                    .cyan()
                    .to_string()
            } else {
                "Unknown client".dimmed().to_string()
            };
            println!("JA3 Fingerprint: {} ({})", ja3.ja3_hash.green(), match_str);
        }
    }

    // ------------------------------------------------------------------------
    // Protocol Display Methods
    // ------------------------------------------------------------------------

    /// Display protocol test results
    pub fn display_protocol_results(&self, results: &[ProtocolTestResult]) {
        println!("\n{}", "Protocol Support:".cyan().bold());
        println!("{}", "-".repeat(50));

        for result in results {
            self.display_single_protocol_result(result);
        }

        self.display_protocol_features(results);
    }

    /// Display a single protocol test result
    fn display_single_protocol_result(&self, result: &ProtocolTestResult) {
        let status = if result.supported {
            "Supported".green()
        } else {
            "Not supported".red()
        };

        let deprecated = if result.protocol.is_deprecated() {
            " (DEPRECATED)".red()
        } else {
            "".normal()
        };

        let timing = format_timing(self.args.output.show_times, result.handshake_time_ms);
        let check_colored = format_status_indicator(result.supported);

        println!(
            "  {:<15} {} {}{}{}",
            result.protocol, check_colored, status, deprecated, timing
        );
    }

    /// Display protocol features (heartbeat extension)
    fn display_protocol_features(&self, results: &[ProtocolTestResult]) {
        let heartbeat_detected = results
            .iter()
            .filter(|r| r.supported && r.heartbeat_enabled.is_some())
            .count();

        if heartbeat_detected > 0 {
            println!("\n{}", "Protocol Features:".cyan().bold());
            println!("{}", "-".repeat(50));

            for result in results {
                if result.supported
                    && let Some(heartbeat_enabled) = result.heartbeat_enabled {
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

    /// Display TLS intolerance test results
    pub fn display_intolerance_results(&self, results: &IntoleranceTestResult) {
        print_section_header("TLS Intolerance Tests:");

        let checks = build_intolerance_checks(results);
        let issues_found = checks.iter().filter(|c| c.is_intolerant).count();

        for check in &checks {
            check.display(&results.details);
        }

        println!("\n{}", "=".repeat(50));
        if issues_found == 0 {
            println!("{}", "Y No TLS intolerance issues detected!".green().bold());
        } else {
            println!(
                "{} {} intolerance issue(s) detected",
                "!".yellow().bold(),
                issues_found.to_string().yellow().bold()
            );
            println!("  These issues may cause connectivity problems with some clients");
        }
    }

    /// Display ALPN results
    pub fn display_alpn_results(&self, alpn_report: &AlpnReport) {
        print_section_header("ALPN Protocol Negotiation:");

        if alpn_report.alpn_enabled {
            println!("  {} ALPN is enabled", "Y".green().bold());
            self.display_alpn_protocols(alpn_report);
        } else {
            println!(
                "  {} ALPN is not enabled or no protocols supported",
                "X".red()
            );
        }

        self.display_alpn_recommendations(alpn_report);
    }

    /// Display ALPN supported protocols
    fn display_alpn_protocols(&self, alpn_report: &AlpnReport) {
        if !alpn_report.alpn_result.supported_protocols.is_empty() {
            println!("\n  Supported Protocols:");
            for proto in &alpn_report.alpn_result.supported_protocols {
                println!("    - {}", proto.green());
            }

            if let Some(ref negotiated) = alpn_report.alpn_result.negotiated_protocol {
                println!("\n  Server Preferred: {}", negotiated.cyan().bold());
            }
        }

        if alpn_report.alpn_result.http2_supported {
            println!("\n  {} HTTP/2 (h2) is supported", "Y".green().bold());
        }

        if alpn_report.alpn_result.http3_supported {
            println!("\n  {} HTTP/3 (h3) is supported", "Y".green().bold());
        }
    }

    /// Display ALPN recommendations
    fn display_alpn_recommendations(&self, alpn_report: &AlpnReport) {
        if !alpn_report.recommendations.is_empty() {
            println!("\n  Recommendations:");
            for rec in &alpn_report.recommendations {
                println!("    - {}", rec.yellow());
            }
        }
    }

    // ------------------------------------------------------------------------
    // Cipher Display Methods
    // ------------------------------------------------------------------------

    /// Display cipher test results
    pub fn display_cipher_results(&self, results: &HashMap<Protocol, ProtocolCipherSummary>) {
        for (protocol, summary) in results {
            let timing_info =
                format_avg_timing(self.args.output.show_times, summary.avg_handshake_time_ms);

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

            display_cipher_strength_distribution(&summary.counts);
            display_cipher_security_features(&summary.counts);
            self.display_cipher_ordering(summary);
        }
    }

    /// Display cipher ordering preference
    fn display_cipher_ordering(&self, summary: &ProtocolCipherSummary) {
        if summary.server_ordered {
            println!("\n  {} Server enforces cipher order", "Y".green());
            if let Some(cipher) = &summary.preferred_cipher {
                let cipher_name = if self.args.output.iana_names {
                    &cipher.iana_name
                } else {
                    &cipher.openssl_name
                };

                let cipher_id = if self.args.output.show_cipher_ids {
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
            println!("\n  {} Client chooses cipher order", "!".yellow());
        }
    }

    // ------------------------------------------------------------------------
    // Certificate Display Methods
    // ------------------------------------------------------------------------

    /// Display certificate analysis results
    pub fn display_certificate_results(&self, result: &CertificateAnalysisResult) {
        println!("\n{}", "Certificate Analysis:".cyan().bold());
        println!("{}", "=".repeat(50));

        if let Some(cert) = result.chain.leaf() {
            self.display_certificate_info(cert);
        }

        self.display_chain_summary(&result.chain);
        self.display_validation_status(&result.validation);

        if let Some(revocation) = &result.revocation {
            self.display_revocation_status(revocation);
        }
    }

    /// Display certificate information (subject, issuer, validity, key details)
    fn display_certificate_info(&self, cert: &CertificateInfo) {
        println!("\n{}", "Certificate Information:".cyan());
        println!("  Subject:    {}", cert.subject);
        println!("  Issuer:     {}", cert.issuer);
        println!("  Valid From: {}", cert.not_before);
        println!("  Valid To:   {}", cert.not_after);

        if let Some(ref countdown) = cert.expiry_countdown {
            println!("  Expires:    {}", countdown.yellow());
        }

        println!("  Serial:     {}", cert.serial_number);
        self.display_certificate_key_info(cert);
        println!("  Signature:  {}", cert.signature_algorithm);
        self.display_certificate_fingerprints(cert);
        self.display_certificate_warnings(cert);
        self.display_certificate_sans(cert);
    }

    /// Display certificate key information
    fn display_certificate_key_info(&self, cert: &CertificateInfo) {
        if let Some(key_size) = cert.public_key_size {
            let key_color = format_key_size(key_size);
            print!(
                "  Key Size:   {} bits ({})",
                key_color, cert.public_key_algorithm
            );
            if let Some(ref exponent) = cert.rsa_exponent {
                print!(", {}", exponent);
            }
            println!();
        }
    }

    /// Display certificate fingerprints and pins
    fn display_certificate_fingerprints(&self, cert: &CertificateInfo) {
        if let Some(ref fingerprint) = cert.fingerprint_sha256 {
            println!("  Fingerprint SHA256: {}", fingerprint);
        }
        if let Some(ref pin) = cert.pin_sha256 {
            println!("  Pin SHA256 (HPKP):  {}", pin);
        }
        if let Some(ref aia_url) = cert.aia_url {
            println!("  AIA URL:            {}", aia_url);
        }
    }

    /// Display certificate warnings (e.g., Debian weak key)
    fn display_certificate_warnings(&self, cert: &CertificateInfo) {
        if let Some(true) = cert.debian_weak_key {
            println!(
                "  {}",
                "!! WARNING: Debian Weak Key Detected (CVE-2008-0166)"
                    .red()
                    .bold()
            );
        }
    }

    /// Display certificate SANs
    fn display_certificate_sans(&self, cert: &CertificateInfo) {
        if !cert.san.is_empty() {
            println!("\n  Subject Alternative Names:");
            for san in &cert.san {
                println!("    - {}", san);
            }
        }
    }

    /// Display certificate chain summary and optional full chain details
    fn display_chain_summary(&self, chain: &CertificateChain) {
        println!("\n{}", "Certificate Chain:".cyan());
        println!("  Chain Length: {} certificates", chain.chain_length);
        println!("  Chain Size:   {} bytes", chain.chain_size_bytes);
        println!(
            "  Complete:     {}",
            if chain.is_complete() {
                "Y Yes".green()
            } else {
                "! No root CA".yellow()
            }
        );

        if self.args.scan.show_certificates && chain.certificates.len() > 1 {
            self.display_full_certificate_chain(chain);
        }
    }

    /// Display full certificate chain details
    fn display_full_certificate_chain(&self, chain: &CertificateChain) {
        println!("\n  {}", "Full Certificate Chain:".cyan());
        let chain_len = chain.certificates.len();

        for (i, cert) in chain.certificates.iter().enumerate() {
            let cert_type = get_cert_type(i, chain_len);
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

    /// Display certificate validation status and issues
    fn display_validation_status(&self, validation: &ValidationResult) {
        println!("\n{}", "Validation:".cyan());
        let validation_status = if validation.valid {
            "Y Valid".green().bold()
        } else {
            "X Invalid".red().bold()
        };
        println!("  Status:           {}", validation_status);
        println!(
            "  Hostname Match:   {}",
            format_bool_indicator(validation.hostname_match, "Yes", "No")
        );
        println!(
            "  Not Expired:      {}",
            format_bool_indicator(validation.not_expired, "Yes", "Expired")
        );
        println!(
            "  Trust Chain:      {}",
            format_bool_indicator(validation.trust_chain_valid, "Valid", "Invalid")
        );

        if let Some(trusted_ca) = &validation.trusted_ca {
            println!("  Trusted CA:       {} {}", "Y".green(), trusted_ca);
        }

        if let Some(ref platform_trust) = validation.platform_trust {
            self.display_platform_trust_breakdown(platform_trust);
        }

        self.display_validation_issues(validation);
    }

    /// Display validation issues
    fn display_validation_issues(&self, validation: &ValidationResult) {
        if !validation.issues.is_empty() {
            println!("\n{}", "  Issues:".yellow());
            for issue in &validation.issues {
                println!(
                    "    [{}] {}",
                    issue.severity.colored_display(),
                    issue.description
                );
            }
        }
    }

    /// Display revocation status (OCSP/CRL)
    fn display_revocation_status(&self, revocation: &RevocationResult) {
        println!("\n{}", "Revocation Status:".cyan());
        let status_str = format_revocation_status(&revocation.status);
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

        if self.args.scan.ocsp {
            self.display_ocsp_details(revocation);
        }
    }

    /// Display extended OCSP details
    fn display_ocsp_details(&self, revocation: &RevocationResult) {
        use crate::certificates::revocation::{RevocationMethod, RevocationStatus};

        println!("\n  {}", "OCSP Details:".cyan());

        if matches!(revocation.method, RevocationMethod::OCSP) {
            println!(
                "    Stapling:     {}",
                if revocation.must_staple {
                    "Y Required by certificate".green()
                } else {
                    "Optional".yellow()
                }
            );

            match revocation.status {
                RevocationStatus::Good => {
                    println!(
                        "    Response:     {} Valid certificate, not revoked",
                        "Y".green()
                    );
                }
                RevocationStatus::Revoked => {
                    println!(
                        "    Response:     {} Certificate has been REVOKED",
                        "X".red().bold()
                    );
                }
                RevocationStatus::Unknown => {
                    println!(
                        "    Response:     {} Responder doesn't know about certificate",
                        "?".yellow()
                    );
                }
                _ => {}
            }
        } else if matches!(revocation.method, RevocationMethod::CRL) {
            println!("    Method:       Certificate Revocation List (CRL)");
            println!("    OCSP:         Not used");
        } else {
            println!("    Method:       None");
            println!("    OCSP:         Not configured");
        }
    }

    /// Display per-platform trust store breakdown
    pub fn display_platform_trust_breakdown(&self, platform_trust: &TrustValidationResult) {
        use crate::certificates::trust_stores::TrustStore;

        println!("\n{}", "Platform Trust Status:".cyan());

        let overall_status = self.format_overall_trust_status(platform_trust);
        println!("  Overall Trusted:  {}", overall_status);

        self.display_trusted_platforms(platform_trust);
        self.display_untrusted_platforms(platform_trust);
        self.display_per_platform_details(platform_trust, &TrustStore::all());
    }

    /// Format overall trust status
    fn format_overall_trust_status(&self, platform_trust: &TrustValidationResult) -> ColoredString {
        if platform_trust.overall_trusted {
            if platform_trust.trusted_count == platform_trust.total_platforms {
                "Y Yes (All platforms)".green().bold()
            } else {
                "! Partial".yellow().bold()
            }
        } else {
            "X No".red().bold()
        }
    }

    /// Display trusted platforms list
    fn display_trusted_platforms(&self, platform_trust: &TrustValidationResult) {
        let trusted = platform_trust.trusted_platforms();
        if !trusted.is_empty() {
            let trusted_names: Vec<String> =
                trusted.iter().map(|store| store.to_string()).collect();
            println!("  Trusted By:       {}", trusted_names.join(", ").green());
        }
    }

    /// Display untrusted platforms list
    fn display_untrusted_platforms(&self, platform_trust: &TrustValidationResult) {
        let untrusted = platform_trust.untrusted_platforms();
        if !untrusted.is_empty() {
            let untrusted_names: Vec<String> =
                untrusted.iter().map(|store| store.to_string()).collect();
            println!("  Not Trusted By:   {}", untrusted_names.join(", ").red());
        }
    }

    /// Display detailed per-platform status
    fn display_per_platform_details(
        &self,
        platform_trust: &TrustValidationResult,
        stores: &[crate::certificates::trust_stores::TrustStore],
    ) {
        println!("\n  {}", "Per-Platform Details:".cyan());
        for store in stores {
            if let Some(status) = platform_trust.platform_status.get(store) {
                self.display_platform_trust_detail(store, status);
            }
        }
    }

    /// Display individual platform trust detail
    fn display_platform_trust_detail(
        &self,
        store: &crate::certificates::trust_stores::TrustStore,
        status: &crate::certificates::trust_stores::PlatformTrustStatus,
    ) {
        let status_symbol = format_status_indicator(status.trusted);
        let platform_name = format!("{:<18}", store.name());

        if status.trusted {
            if let Some(ref root) = status.trusted_root {
                let root_display = truncate_with_ellipsis(root, 50);
                println!(
                    "    {} {} - {}",
                    status_symbol,
                    platform_name.cyan(),
                    root_display.dimmed()
                );
            } else {
                println!("    {} {}", status_symbol, platform_name.cyan());
            }
        } else {
            let message_display = truncate_with_ellipsis(&status.message, 50);
            println!(
                "    {} {} - {}",
                status_symbol,
                platform_name.cyan(),
                message_display.dimmed()
            );
        }
    }

    // ------------------------------------------------------------------------
    // HTTP Headers Display Methods
    // ------------------------------------------------------------------------

    /// Display HTTP security headers results
    pub fn display_http_headers_results(&self, result: &HeaderAnalysisResult) {
        println!("\n{}", "HTTP Security Headers:".cyan().bold());
        println!("{}", "=".repeat(50));

        self.display_http_response_metadata(result);

        let grade_colored = format_http_grade(&result.grade);
        println!("  {}", grade_colored);
        println!("  Score: {}/100", result.score);
        println!("  Total Issues: {}", result.issues.len());

        if !result.issues.is_empty() {
            self.display_http_issues(result);
        } else {
            println!(
                "\n{}",
                "  Y All security headers properly configured!"
                    .green()
                    .bold()
            );
        }

        self.display_advanced_header_analysis(result);
    }

    /// Display HTTP response metadata
    fn display_http_response_metadata(&self, result: &HeaderAnalysisResult) {
        if let Some(status_code) = result.http_status_code {
            println!("  HTTP Status: {}", format_http_status(status_code));
        }

        if let Some(ref redirect_location) = result.redirect_location {
            println!("  Redirect To: {}", redirect_location.yellow());
        }

        if let Some(ref server) = result.server_hostname {
            println!("  Server:      {}", server.cyan());
        }

        if result.http_status_code.is_some()
            || result.redirect_location.is_some()
            || result.server_hostname.is_some()
        {
            println!();
        }
    }

    /// Display HTTP header issues grouped by severity
    fn display_http_issues(&self, result: &HeaderAnalysisResult) {
        use crate::http::headers::IssueSeverity;

        println!("\n{}", "  Issues:".yellow());

        let mut by_severity: HashMap<IssueSeverity, Vec<_>> = HashMap::new();
        for issue in &result.issues {
            by_severity.entry(issue.severity).or_default().push(issue);
        }

        for severity in [
            IssueSeverity::Critical,
            IssueSeverity::High,
            IssueSeverity::Medium,
            IssueSeverity::Low,
            IssueSeverity::Info,
        ] {
            if let Some(issues) = by_severity.get(&severity) {
                for issue in issues {
                    let issue_icon = format_http_issue_icon(&issue.issue_type);

                    println!(
                        "\n    {} {} - {}",
                        issue_icon,
                        issue.header_name.cyan().bold(),
                        issue.severity.colored_display()
                    );
                    println!("      {}", issue.description);
                    println!("      Recommendation: {}", issue.recommendation.green());
                }
            }
        }
    }

    /// Display advanced header analysis results
    pub fn display_advanced_header_analysis(&self, result: &HeaderAnalysisResult) {
        self.display_hsts_analysis(result);
        self.display_hpkp_analysis(result);
        self.display_cookie_analysis(result);
        self.display_datetime_check(result);
        self.display_banner_detection(result);
        self.display_reverse_proxy_detection(result);
    }

    /// Display HSTS analysis
    fn display_hsts_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(hsts) = &result.hsts_analysis {
            println!("\n{}", "HSTS Analysis:".cyan());
            let status = if hsts.enabled {
                format!("Y Enabled - {}", hsts.details).green()
            } else {
                format!("X Disabled - {}", hsts.details).red()
            };
            println!("  Status: {}", status);
            println!("  Grade:  {:?}", hsts.grade);
            if hsts.enabled {
                if let Some(max_age) = hsts.max_age {
                    println!(
                        "    max-age:          {} ({} days)",
                        max_age,
                        max_age / 86400
                    );
                }
                println!("    includeSubDomains: {}", hsts.include_subdomains);
                println!("    preload:           {}", hsts.preload);
            }
        }
    }

    /// Display HPKP analysis
    fn display_hpkp_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(hpkp) = &result.hpkp_analysis
            && hpkp.enabled {
                println!("\n{}", "HPKP Analysis:".cyan());
                println!("  {} {}", "!".yellow(), hpkp.details.yellow());
                println!("  Pins: {}", hpkp.pins.len());
            }
    }

    /// Display cookie analysis
    fn display_cookie_analysis(&self, result: &HeaderAnalysisResult) {
        if let Some(cookies) = &result.cookie_analysis {
            println!("\n{}", "Cookie Security:".cyan());
            println!("  {}", cookies.details);
            println!("  Grade: {:?}", cookies.grade);

            if !cookies.cookies.is_empty() {
                println!("\n  Cookies:");
                for cookie in &cookies.cookies {
                    self.display_single_cookie(cookie);
                }
            }
        }
    }

    /// Display a single cookie's security status
    fn display_single_cookie(&self, cookie: &crate::http::headers_advanced::CookieInfo) {
        let samesite_str = cookie
            .samesite
            .as_ref()
            .map(|s| format!("SameSite={}", s))
            .unwrap_or_default();

        let security_flags = format!(
            "{}{}{}",
            if cookie.secure { "Secure " } else { "" },
            if cookie.httponly { "HttpOnly " } else { "" },
            samesite_str
        );

        let status = if cookie.secure && cookie.httponly && cookie.samesite.is_some() {
            "Y".green()
        } else {
            "!".yellow()
        };

        let flags_display = if security_flags.is_empty() {
            "no security flags".red().to_string()
        } else {
            security_flags
        };

        println!("    {} {} [{}]", status, cookie.name.cyan(), flags_display);
    }

    /// Display datetime check
    fn display_datetime_check(&self, result: &HeaderAnalysisResult) {
        if let Some(datetime) = &result.datetime_check
            && let Some(server_date) = &datetime.server_date {
                println!("\n{}", "Server Time:".cyan());
                let sync_status = if datetime.synchronized {
                    "Y Synchronized".green()
                } else {
                    "! Out of sync".yellow()
                };
                println!("  {}", sync_status);
                println!("  Server Date: {}", server_date);
                if let Some(skew) = datetime.skew_seconds {
                    println!("  Time Skew:   {} seconds", skew);
                }
            }
    }

    /// Display banner detection
    fn display_banner_detection(&self, result: &HeaderAnalysisResult) {
        if let Some(banners) = &result.banner_detection {
            println!("\n{}", "Server Banners:".cyan());
            let grade_color = format_advanced_grade(&banners.grade);
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
                println!("  {} Version information exposed", "!".red());
            } else {
                println!("  {} Version information hidden", "Y".green());
            }
        }
    }

    /// Display reverse proxy detection
    fn display_reverse_proxy_detection(&self, result: &HeaderAnalysisResult) {
        if let Some(proxy) = &result.reverse_proxy_detection
            && proxy.detected {
                println!("\n{}", "Reverse Proxy:".cyan());
                println!("  {}", proxy.details);
                if let Some(proxy_type) = &proxy.proxy_type {
                    println!("  Type: {}", proxy_type.cyan());
                }
                if let Some(via) = &proxy.via_header {
                    println!("  Via: {}", via);
                }

                let headers_found = self.collect_proxy_headers(proxy);
                if !headers_found.is_empty() {
                    println!("  Headers: {}", headers_found.join(", "));
                }
            }
    }

    /// Collect proxy header names that are present
    fn collect_proxy_headers(
        &self,
        proxy: &crate::http::headers_advanced::ReverseProxyDetection,
    ) -> Vec<&'static str> {
        let mut headers = Vec::new();
        if proxy.x_forwarded_for {
            headers.push("X-Forwarded-For");
        }
        if proxy.x_real_ip {
            headers.push("X-Real-IP");
        }
        if proxy.x_forwarded_proto {
            headers.push("X-Forwarded-Proto");
        }
        headers
    }

    // ------------------------------------------------------------------------
    // Vulnerability Display Methods
    // ------------------------------------------------------------------------

    /// Display vulnerability results
    pub fn display_vulnerability_results(&self, results: &[VulnerabilityResult]) {
        print_section_header("Vulnerability Assessment:");

        let mut vulnerable_count = 0;
        let mut by_severity: HashMap<crate::vulnerabilities::Severity, usize> = HashMap::new();

        for result in results {
            if result.vulnerable {
                vulnerable_count += 1;
                *by_severity.entry(result.severity).or_insert(0) += 1;
                self.display_single_vulnerability(result);
            }
        }

        self.display_vulnerability_summary(vulnerable_count, &by_severity);
    }

    /// Display a single vulnerability result
    fn display_single_vulnerability(&self, result: &VulnerabilityResult) {
        println!("\n{} {:?}", "X".red().bold(), result.vuln_type);
        println!("  Severity: {}", result.severity.colored_display());
        if let Some(cve) = &result.cve {
            println!("  CVE:      {}", cve);
        }
        println!("  Details:  {}", result.details);
    }

    /// Display vulnerability summary
    fn display_vulnerability_summary(
        &self,
        vulnerable_count: usize,
        by_severity: &HashMap<crate::vulnerabilities::Severity, usize>,
    ) {
        use crate::vulnerabilities::Severity;

        println!("\n{}", "=".repeat(50));
        if vulnerable_count == 0 {
            println!("{}", "Y No vulnerabilities found!".green().bold());
        } else {
            println!(
                "{} {} vulnerability(ies) found",
                "!".red().bold(),
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

    // ------------------------------------------------------------------------
    // Rating Display Methods
    // ------------------------------------------------------------------------

    /// Display SSL Labs rating results
    pub fn display_rating_results(&self, rating: &RatingResult) {
        print_section_header("SSL Labs Rating:");

        let grade_colored = format_ssl_grade(&rating.grade);
        println!("\n  {}", grade_colored);
        println!("  {}", rating.grade.description().dimmed());
        println!("\n  Overall Score: {}/100", rating.score);

        self.display_rating_components(rating);
        self.display_rating_warnings(rating);

        println!();
    }

    /// Display rating component scores
    fn display_rating_components(&self, rating: &RatingResult) {
        println!("\n{}", "  Component Scores:".cyan());
        println!("    Certificate:    {}/100", rating.certificate_score);
        println!("    Protocols:      {}/100", rating.protocol_score);
        println!("    Key Exchange:   {}/100", rating.key_exchange_score);
        println!("    Cipher Strength: {}/100", rating.cipher_strength_score);
    }

    /// Display rating warnings
    fn display_rating_warnings(&self, rating: &RatingResult) {
        if !rating.warnings.is_empty() {
            println!("\n{}", "  Warnings:".yellow());
            for warning in &rating.warnings {
                println!("    ! {}", warning.red());
            }
        }
    }

    // ------------------------------------------------------------------------
    // Client Simulation Display Methods
    // ------------------------------------------------------------------------

    /// Display client simulation results
    pub fn display_client_simulation_results(&self, results: &[ClientSimulationResult]) {
        print_section_header("Client Simulation:");

        let mut successful = 0;
        let mut failed = 0;

        for result in results {
            if result.is_success() {
                successful += 1;
                self.display_successful_client_sim(result);
            } else {
                failed += 1;
                self.display_failed_client_sim(result);
            }
        }

        self.display_client_sim_totals(results.len(), successful, failed);
    }

    /// Display successful client simulation
    fn display_successful_client_sim(&self, result: &ClientSimulationResult) {
        let handshake_time = result
            .handshake_time_ms
            .map(|ms| format!(" ({}ms)", ms))
            .unwrap_or_default();

        println!(
            "  {} {} - {} / {}{}",
            "Y".green(),
            result.client_name.cyan(),
            result
                .protocol
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            result.cipher.as_ref().unwrap_or(&"Unknown".to_string()),
            handshake_time.dimmed()
        );
    }

    /// Display failed client simulation
    fn display_failed_client_sim(&self, result: &ClientSimulationResult) {
        println!(
            "  {} {} - {}",
            "X".red(),
            result.client_name.cyan(),
            result
                .error
                .as_ref()
                .unwrap_or(&"Connection failed".to_string())
                .red()
        );
    }

    /// Display client simulation totals
    fn display_client_sim_totals(&self, total: usize, successful: usize, failed: usize) {
        println!("\n{}", "=".repeat(50));
        println!(
            "  Total: {} | {} Successful | {} Failed",
            total,
            successful.to_string().green(),
            failed.to_string().red()
        );

        if successful == total {
            println!(
                "\n{}",
                "  Y All clients can connect successfully!".green().bold()
            );
        } else if failed == total {
            println!("\n{}", "  X No clients can connect!".red().bold());
        }
    }

    // ------------------------------------------------------------------------
    // Signature and Group Display Methods
    // ------------------------------------------------------------------------

    /// Display signature algorithm results
    pub fn display_signature_results(&self, results: &SignatureEnumerationResult) {
        print_section_header("Signature Algorithms:");

        let supported: Vec<_> = results.algorithms.iter().filter(|a| a.supported).collect();
        let total = results.algorithms.len();

        println!("  Supported: {}/{}", supported.len(), total);
        println!();

        for algo in &results.algorithms {
            let status = format_status_indicator(algo.supported);
            println!("  {} {:<30} (0x{:04x})", status, algo.name, algo.iana_value);
        }
    }

    /// Display key exchange group results
    pub fn display_group_results(&self, results: &GroupEnumerationResult) {
        use crate::protocols::groups::GroupType;

        print_section_header("Key Exchange Groups:");

        let supported: Vec<_> = results.groups.iter().filter(|g| g.supported).collect();
        let total = results.groups.len();

        println!("  Supported: {}/{}", supported.len(), total);

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

        self.display_group_category("Elliptic Curve Groups:", &ec_groups);
        self.display_group_category("Finite Field (DHE) Groups:", &ff_groups);
        self.display_group_category("Post-Quantum Groups:", &pq_groups);
    }

    /// Display a category of key exchange groups
    fn display_group_category(
        &self,
        title: &str,
        groups: &[&crate::protocols::groups::KeyExchangeGroup],
    ) {
        if !groups.is_empty() {
            println!("\n  {}", title.cyan());
            for group in groups {
                let status = format_status_indicator(group.supported);
                println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
            }
        }
    }

    /// Display client CAs results
    pub fn display_client_cas_results(&self, results: &ClientCAsResult) {
        print_section_header("Client Certificate CAs:");

        if !results.requires_client_auth {
            println!(
                "  {}",
                "Server does not require client authentication".yellow()
            );
            return;
        }

        println!(
            "  {} Server requires client certificate authentication",
            "Y".green()
        );
        println!("  Acceptable CAs: {}", results.cas.len());

        if results.cas.is_empty() {
            println!("\n  {}", "No CA restrictions (any CA accepted)".cyan());
            return;
        }

        println!();
        for (i, ca) in results.cas.iter().enumerate() {
            self.display_single_client_ca(i, ca);
        }
    }

    /// Display a single client CA
    fn display_single_client_ca(&self, index: usize, ca: &crate::protocols::client_cas::ClientCA) {
        println!("  {}. Client CA:", index + 1);

        if let Some(cn) = &ca.common_name {
            println!("     CN:  {}", cn.green());
        }

        if let Some(org) = &ca.organization {
            println!("     Org: {}", org.cyan());
        }

        let dn_preview = truncate_with_ellipsis(&ca.distinguished_name, 60);
        println!("     DN:  {}", dn_preview.dimmed());
    }

    // ------------------------------------------------------------------------
    // Fingerprint Display Methods
    // ------------------------------------------------------------------------

    /// Display JA3 fingerprint results
    pub fn display_ja3_results(&self, ja3: &Ja3Fingerprint, signature: Option<&Ja3Signature>) {
        print_section_header("JA3 Fingerprint:");

        println!("  JA3 Hash:       {}", ja3.ja3_hash.green().bold());
        println!(
            "  SSL Version:    {} ({})",
            ja3.ssl_version_name().cyan(),
            ja3.ssl_version
        );
        println!("  Cipher Suites:  {} suites", ja3.ciphers.len());
        println!("  Extensions:     {} extensions", ja3.extensions.len());
        println!("  Curves:         {} curves", ja3.curves.len());
        println!("  Point Formats:  {} formats", ja3.point_formats.len());

        if !ja3.curves.is_empty() {
            let curve_names = ja3.curve_names();
            println!("  Named Curves:   {}", curve_names.join(", ").cyan());
        }

        println!("\n  JA3 String:");
        println!("  {}", ja3.ja3_string.dimmed());

        self.display_ja3_signature_match(signature);
    }

    /// Display JA3 signature match
    fn display_ja3_signature_match(&self, signature: Option<&Ja3Signature>) {
        println!("\n{}", "Database Match:".cyan().bold());
        println!("{}", "-".repeat(50));

        if let Some(sig) = signature {
            let threat_color = format_threat_level(&sig.threat_level);

            println!("  Name:         {}", sig.name.green().bold());
            println!("  Category:     {}", sig.category.cyan());
            println!("  Description:  {}", sig.description);
            println!("  Threat Level: {}", threat_color);

            if sig.threat_level != "none" {
                println!(
                    "\n  {} This fingerprint may indicate suspicious activity!",
                    "!".yellow().bold()
                );
            }
        } else {
            println!("  {} No match found in signature database", "i".cyan());
            println!("  This is a unique or unknown TLS client fingerprint");
        }
    }

    /// Display JA3S fingerprint results
    pub fn display_ja3s_results(&self, ja3s: &Ja3sFingerprint, signature: Option<&Ja3sSignature>) {
        print_section_header("JA3S Fingerprint:");

        println!("  JA3S Hash:      {}", ja3s.ja3s_hash.green().bold());
        println!(
            "  SSL Version:    {} ({})",
            ja3s.version_name().cyan(),
            ja3s.ssl_version
        );
        println!(
            "  Cipher:         {} (0x{:04X})",
            ja3s.cipher_name().cyan(),
            ja3s.cipher
        );
        println!("  Extensions:     {} extensions", ja3s.extensions.len());

        if !ja3s.extensions.is_empty() {
            let ext_names = ja3s.extension_names();
            println!("  Extension List: {}", ext_names.join(", ").cyan());
        }

        println!("\n  JA3S String:");
        println!("  {}", ja3s.ja3s_string.dimmed());

        self.display_ja3s_signature_match(signature);
    }

    /// Display JA3S signature match
    fn display_ja3s_signature_match(&self, signature: Option<&Ja3sSignature>) {
        println!("\n{}", "Database Match:".cyan().bold());
        println!("{}", "-".repeat(50));

        if let Some(sig) = signature {
            println!("  Name:         {}", sig.name.green().bold());
            println!(
                "  Type:         {}",
                format!("{}", sig.server_type).yellow()
            );
            println!("  Description:  {}", sig.description);

            if !sig.common_ports.is_empty() {
                let ports_str: Vec<String> =
                    sig.common_ports.iter().map(|p| p.to_string()).collect();
                println!("  Common Ports: {}", ports_str.join(", ").cyan());
            }

            if !sig.indicators.is_empty() {
                println!("\n  Indicators:");
                for indicator in &sig.indicators {
                    println!("    - {}", indicator.dimmed());
                }
            }
        } else {
            println!("  {} No match found in signature database", "i".cyan());
            println!("  This is a unique or unknown TLS server fingerprint");
        }
    }

    /// Display JARM fingerprint results
    pub fn display_jarm_results(&self, jarm: &JarmFingerprint) {
        println!("\n{}", "JARM Fingerprint:".cyan().bold());
        println!("{}", "=".repeat(80));

        println!("  JARM Hash:      {}", jarm.hash.green().bold());

        self.display_jarm_signature_match(jarm);

        let successful_probes = jarm.raw_responses.iter().filter(|r| *r != "|||").count();
        println!("\n  Successful Probes: {}/10", successful_probes);

        self.display_jarm_probe_status(successful_probes);
    }

    /// Display JARM signature match
    fn display_jarm_signature_match(&self, jarm: &JarmFingerprint) {
        if let Some(ref sig) = jarm.signature {
            println!("\n{}", "Database Match:".green().bold());
            println!("{}", "-".repeat(80));
            println!("  Name:           {}", sig.name.green().bold());
            println!("  Server Type:    {}", sig.server_type.yellow());

            if let Some(ref desc) = sig.description {
                println!("  Description:    {}", desc.cyan());
            }

            if let Some(ref threat_level) = sig.threat_level {
                let threat_display = format_threat_level(threat_level);
                println!("  Threat Level:   {}", threat_display);

                if threat_level.to_lowercase() == "critical"
                    || threat_level.to_lowercase() == "high"
                {
                    println!(
                        "\n  {} This fingerprint is associated with known malicious infrastructure!",
                        "WARNING:".red().bold()
                    );
                }
            }
        } else {
            println!("\n{}", "Database Match:".cyan().bold());
            println!("{}", "-".repeat(80));
            println!("  {} No match found in signature database", "i".cyan());
            println!("  This is a unique or unknown JARM fingerprint");
        }
    }

    /// Display JARM probe status message
    fn display_jarm_probe_status(&self, successful_probes: usize) {
        if successful_probes == 0 {
            println!(
                "  {} All JARM probes failed (server may be offline or blocking)",
                "!".yellow()
            );
        } else if successful_probes < 10 {
            println!(
                "  {} Some JARM probes failed (partial fingerprint)",
                "i".cyan()
            );
        }
    }
}

// ============================================================================
// SECTION 10: Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_formatter_creation() {
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);
        assert!(!formatter.args.output.show_times);
    }

    #[test]
    fn test_format_bool_indicator() {
        let yes_result = format_bool_indicator(true, "Yes", "No");
        assert!(yes_result.to_string().contains("Y Yes"));

        let no_result = format_bool_indicator(false, "Yes", "No");
        assert!(no_result.to_string().contains("X No"));
    }

    #[test]
    fn test_truncate_with_ellipsis() {
        assert_eq!(truncate_with_ellipsis("short", 10), "short");
        assert_eq!(
            truncate_with_ellipsis("this is a long string", 10),
            "this is..."
        );
    }

    #[test]
    fn test_format_timing() {
        assert_eq!(format_timing(false, Some(100)), "");
        let timing = format_timing(true, Some(100));
        assert!(timing.contains("100"));
        assert_eq!(format_timing(true, None), "");
    }

    #[test]
    fn test_format_status_indicator() {
        let yes = format_status_indicator(true);
        assert!(yes.to_string().contains("Y"));

        let no = format_status_indicator(false);
        assert!(no.to_string().contains("X"));
    }

    #[test]
    fn test_get_cert_type() {
        assert_eq!(get_cert_type(0, 3), "Leaf Certificate");
        assert_eq!(get_cert_type(1, 3), "Intermediate CA");
        assert_eq!(get_cert_type(2, 3), "Root CA");
    }
}
