// CipherRun - Multi-IP Terminal Output Module
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

//! Terminal output formatting for multi-IP scan reports
//!
//! This module provides formatted terminal output for multi-IP scanning,
//! including per-IP breakdowns, inconsistency detection, and aggregated results.

use crate::scanner::aggregation::AggregatedScanResult;
use crate::scanner::inconsistency::{
    Inconsistency, InconsistencyDetails, InconsistencyType, SingleIpScanResult,
};
use crate::scanner::multi_ip::MultiIpScanReport;
use colored::*;
use std::fmt;

/// Display implementation for MultiIpScanReport
impl fmt::Display for MultiIpScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header
        writeln!(
            f,
            "\n╔═══════════════════════════════════════════════════════════╗"
        )?;
        writeln!(
            f,
            "║              MULTI-IP SCAN REPORT                         ║"
        )?;
        writeln!(
            f,
            "╚═══════════════════════════════════════════════════════════╝\n"
        )?;

        writeln!(
            f,
            "Target: {}:{}",
            self.target.hostname.green().bold(),
            self.target.port
        )?;
        writeln!(
            f,
            "IPs Scanned: {}/{} successful",
            self.successful_scans.to_string().green(),
            self.total_ips
        )?;
        writeln!(
            f,
            "Total Duration: {:.2}s\n",
            self.total_duration_ms as f64 / 1000.0
        )?;

        // Inconsistency warning if present
        if !self.inconsistencies.is_empty() {
            writeln!(
                f,
                "{}",
                "⚠ LOAD BALANCER INCONSISTENCIES DETECTED".yellow().bold()
            )?;
            writeln!(
                f,
                "  {} configuration difference{} found across backends\n",
                self.inconsistencies.len(),
                if self.inconsistencies.len() == 1 {
                    ""
                } else {
                    "s"
                }
            )?;
        }

        // Per-IP Results Section
        writeln!(f, "{}", "Per-IP Results:".cyan().bold())?;
        writeln!(f, "{}", "═".repeat(60))?;
        writeln!(f)?;

        // Sort IPs for consistent display
        let mut ips: Vec<_> = self.per_ip_results.keys().collect();
        ips.sort();

        for ip in ips {
            if let Some(result) = self.per_ip_results.get(ip) {
                self.display_single_ip_result(f, result)?;
            }
        }

        // Inconsistencies Section
        if !self.inconsistencies.is_empty() {
            writeln!(f, "\n{}", "Inconsistencies Detected:".yellow().bold())?;
            writeln!(f, "{}", "═".repeat(60))?;
            writeln!(f)?;

            for inconsistency in &self.inconsistencies {
                self.display_inconsistency(f, inconsistency)?;
            }
        }

        // Aggregated Results Section
        writeln!(
            f,
            "\n{}",
            "Aggregated Results (Conservative):".cyan().bold()
        )?;
        writeln!(f, "{}", "═".repeat(60))?;
        writeln!(f)?;

        self.display_aggregated_results(f, &self.aggregated)?;

        // Recommendations Section
        if !self.inconsistencies.is_empty() {
            writeln!(f, "\n{}", "Recommendations:".green().bold())?;
            writeln!(f, "{}", "═".repeat(60))?;
            writeln!(f)?;
            self.display_recommendations(f)?;
        }

        Ok(())
    }
}

impl MultiIpScanReport {
    /// Display a single IP's scan result
    fn display_single_ip_result(
        &self,
        f: &mut fmt::Formatter<'_>,
        result: &SingleIpScanResult,
    ) -> fmt::Result {
        if let Some(ref error) = result.error {
            writeln!(
                f,
                "  {} {} - {}",
                "✗".red(),
                result.ip.to_string().yellow(),
                "FAILED".red().bold()
            )?;
            writeln!(f, "    Error: {}", error.red())?;
            writeln!(f, "    Scan Time: {}ms\n", result.scan_duration_ms)?;
        } else {
            writeln!(f, "  {} {}", "✓".green(), result.ip.to_string().yellow())?;

            // Display grade if available
            if let Some(ref rating) = result.scan_result.rating {
                let grade_str = format!("{}", rating.grade);
                let grade_colored = Self::color_grade(&grade_str, rating.score);
                writeln!(f, "    Grade: {} ({}/100)", grade_colored, rating.score)?;
            }

            // Display protocol support
            let tls13 = result
                .scan_result
                .protocols
                .iter()
                .any(|p| p.protocol == crate::protocols::Protocol::TLS13 && p.supported);
            let tls12 = result
                .scan_result
                .protocols
                .iter()
                .any(|p| p.protocol == crate::protocols::Protocol::TLS12 && p.supported);

            writeln!(
                f,
                "    TLS 1.3: {}",
                if tls13 { "✓".green() } else { "✗".red() }
            )?;
            writeln!(
                f,
                "    TLS 1.2: {}",
                if tls12 { "✓".green() } else { "✗".red() }
            )?;

            // Display cipher count
            let cipher_count: usize = result
                .scan_result
                .ciphers
                .values()
                .map(|s| s.supported_ciphers.len())
                .sum();
            if cipher_count > 0 {
                writeln!(f, "    Cipher Suites: {} total", cipher_count)?;
            }

            // Display certificate info
            if let Some(ref cert_chain) = result.scan_result.certificate_chain {
                let cert_status = if cert_chain.validation.valid {
                    "Valid".green()
                } else {
                    "Invalid".red()
                };
                writeln!(f, "    Certificate: {}", cert_status)?;
            }

            writeln!(f, "    Scan Time: {}ms\n", result.scan_duration_ms)?;
        }

        Ok(())
    }

    /// Display a detected inconsistency
    fn display_inconsistency(
        &self,
        f: &mut fmt::Formatter<'_>,
        inconsistency: &Inconsistency,
    ) -> fmt::Result {
        let severity_colored = match inconsistency.severity {
            crate::vulnerabilities::Severity::Critical => "CRITICAL".red().bold(),
            crate::vulnerabilities::Severity::High => "HIGH".red(),
            crate::vulnerabilities::Severity::Medium => "MEDIUM".yellow(),
            crate::vulnerabilities::Severity::Low => "LOW".normal(),
            crate::vulnerabilities::Severity::Info => "INFO".cyan(),
        };

        writeln!(
            f,
            "{} {} - {}",
            "⚠".yellow(),
            inconsistency.inconsistency_type,
            severity_colored
        )?;
        writeln!(f, "  {}", inconsistency.description)?;

        // Display specific details based on type
        match &inconsistency.details {
            InconsistencyDetails::Protocols {
                protocol,
                ips_with_support,
                ips_without_support,
            } => {
                writeln!(
                    f,
                    "  IPs WITH {}: {}",
                    protocol.name(),
                    ips_with_support
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                        .green()
                )?;
                writeln!(
                    f,
                    "  IPs WITHOUT {}: {}",
                    protocol.name(),
                    ips_without_support
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                        .red()
                )?;
            }
            InconsistencyDetails::Certificates { fingerprints } => {
                writeln!(f, "  Different certificates detected:")?;
                for (ip, fingerprint) in fingerprints {
                    writeln!(
                        f,
                        "    {} -> {}",
                        ip.to_string().yellow(),
                        fingerprint[..16].to_string().dimmed()
                    )?;
                }
            }
            InconsistencyDetails::Grades { grades } => {
                writeln!(f, "  Grade distribution:")?;
                for (ip, (grade, score)) in grades {
                    let grade_colored = Self::color_grade(grade, *score);
                    writeln!(
                        f,
                        "    {} -> {} ({}/100)",
                        ip.to_string().yellow(),
                        grade_colored,
                        score
                    )?;
                }
            }
            InconsistencyDetails::CipherSuites { differences } => {
                writeln!(
                    f,
                    "  {} unique cipher configurations detected",
                    differences.len()
                )?;
            }
            InconsistencyDetails::SessionResumption {
                ips_with_caching,
                ips_with_tickets,
                ips_without,
            } => {
                if !ips_with_caching.is_empty() {
                    writeln!(
                        f,
                        "  With Caching: {}",
                        ips_with_caching
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                if !ips_with_tickets.is_empty() {
                    writeln!(
                        f,
                        "  With Tickets: {}",
                        ips_with_tickets
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                if !ips_without.is_empty() {
                    writeln!(
                        f,
                        "  Without Resumption: {}",
                        ips_without
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                            .red()
                    )?;
                }
            }
            InconsistencyDetails::Alpn { protocols_by_ip } => {
                writeln!(f, "  ALPN protocols by IP:")?;
                for (ip, protocols) in protocols_by_ip {
                    writeln!(
                        f,
                        "    {} -> {}",
                        ip.to_string().yellow(),
                        protocols.join(", ")
                    )?;
                }
            }
        }

        writeln!(f)?;
        Ok(())
    }

    /// Display aggregated results
    fn display_aggregated_results(
        &self,
        f: &mut fmt::Formatter<'_>,
        aggregated: &AggregatedScanResult,
    ) -> fmt::Result {
        let grade_colored = Self::color_grade(&aggregated.grade.0, aggregated.grade.1);
        writeln!(
            f,
            "  Overall Grade: {} ({}/100)",
            grade_colored, aggregated.grade.1
        )?;
        writeln!(f, "  {} Based on WORST backend performance\n", "ℹ".cyan())?;

        writeln!(f, "  Protocols (supported by ALL backends):")?;
        for protocol_result in &aggregated.protocols {
            if protocol_result.supported {
                writeln!(f, "    {} {}", "✓".green(), protocol_result.protocol.name())?;
            }
        }

        if !aggregated.certificate_consistent {
            writeln!(
                f,
                "\n  {} Multiple different certificates detected across backends",
                "⚠".yellow()
            )?;
        }

        if !aggregated.alpn_protocols.is_empty() {
            writeln!(f, "\n  ALPN Protocols (supported by all):")?;
            writeln!(f, "    {}", aggregated.alpn_protocols.join(", ").cyan())?;
        }

        writeln!(f, "\n  Session Resumption:")?;
        writeln!(
            f,
            "    Caching: {}",
            if aggregated.session_resumption_caching {
                "✓ All backends".green()
            } else {
                "✗ Not all backends".red()
            }
        )?;
        writeln!(
            f,
            "    Tickets: {}",
            if aggregated.session_resumption_tickets {
                "✓ All backends".green()
            } else {
                "✗ Not all backends".red()
            }
        )?;

        Ok(())
    }

    /// Display recommendations based on detected inconsistencies
    fn display_recommendations(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_protocol_inconsistency = self
            .inconsistencies
            .iter()
            .any(|i| i.inconsistency_type == InconsistencyType::ProtocolSupport);
        let has_cert_inconsistency = self
            .inconsistencies
            .iter()
            .any(|i| i.inconsistency_type == InconsistencyType::Certificates);
        let has_cipher_inconsistency = self
            .inconsistencies
            .iter()
            .any(|i| i.inconsistency_type == InconsistencyType::CipherSuites);

        if has_protocol_inconsistency {
            writeln!(
                f,
                "  {} Standardize TLS protocol support across all backend servers",
                "⚠".yellow()
            )?;
            writeln!(
                f,
                "     Enable TLS 1.3 on all backends for consistent security posture"
            )?;
        }

        if has_cert_inconsistency {
            writeln!(
                f,
                "  {} Ensure all backend servers use the same certificate",
                "⚠".yellow()
            )?;
            writeln!(
                f,
                "     Different certificates can cause browser warnings and trust issues"
            )?;
        }

        if has_cipher_inconsistency {
            writeln!(
                f,
                "  {} Align cipher suite configurations across all backends",
                "⚠".yellow()
            )?;
            writeln!(
                f,
                "     Use the same cipher suite list and preferences on all servers"
            )?;
        }

        writeln!(
            f,
            "\n  {} Configuration inconsistencies can lead to:",
            "ℹ".cyan()
        )?;
        writeln!(f, "     - Unpredictable behavior for end users")?;
        writeln!(f, "     - Security vulnerabilities if weak backends exist")?;
        writeln!(f, "     - Difficult troubleshooting and maintenance")?;

        Ok(())
    }

    /// Helper to color grade strings
    fn color_grade(grade: &str, score: u8) -> colored::ColoredString {
        use crate::rating::Grade;

        // Parse the grade based on score
        let grade_enum = Grade::from_score(score);
        let grade_str = grade.to_string();

        match grade_enum {
            Grade::APlus | Grade::A => grade_str.green().bold(),
            Grade::AMinus | Grade::B => grade_str.blue().bold(),
            Grade::C => grade_str.yellow(),
            Grade::D | Grade::E | Grade::F => grade_str.red(),
            Grade::T | Grade::M => grade_str.red().bold(),
        }
    }
}
