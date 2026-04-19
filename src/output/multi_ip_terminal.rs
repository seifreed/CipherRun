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
use crate::utils::network::canonical_target;
use colored::*;
use std::fmt;
use std::net::IpAddr;

fn sorted_ip_entries<V>(map: &std::collections::HashMap<IpAddr, V>) -> Vec<(&IpAddr, &V)> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(ip, _)| **ip);
    entries
}

fn sorted_ip_list(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut ips = ips.to_vec();
    ips.sort();
    ips
}

fn join_sorted_ips(ips: &[IpAddr]) -> String {
    sorted_ip_list(ips)
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_sorted_strings(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.join(", ")
}

fn preview_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(16).collect()
}

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
            "Target: {}",
            canonical_target(&self.target.hostname, self.target.port)
                .green()
                .bold()
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
            if let Some(rating) = result.scan_result.ssl_rating() {
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
                    join_sorted_ips(ips_with_support).green()
                )?;
                writeln!(
                    f,
                    "  IPs WITHOUT {}: {}",
                    protocol.name(),
                    join_sorted_ips(ips_without_support).red()
                )?;
            }
            InconsistencyDetails::Certificates { fingerprints } => {
                writeln!(f, "  Different certificates detected:")?;
                for (ip, fingerprint) in sorted_ip_entries(fingerprints) {
                    writeln!(
                        f,
                        "    {} -> {}",
                        ip.to_string().yellow(),
                        preview_fingerprint(fingerprint).dimmed()
                    )?;
                }
            }
            InconsistencyDetails::Grades { grades } => {
                writeln!(f, "  Grade distribution:")?;
                for (ip, (grade, score)) in sorted_ip_entries(grades) {
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
                    writeln!(f, "  With Caching: {}", join_sorted_ips(ips_with_caching))?;
                }
                if !ips_with_tickets.is_empty() {
                    writeln!(f, "  With Tickets: {}", join_sorted_ips(ips_with_tickets))?;
                }
                if !ips_without.is_empty() {
                    writeln!(
                        f,
                        "  Without Resumption: {}",
                        join_sorted_ips(ips_without).red()
                    )?;
                }
            }
            InconsistencyDetails::Alpn { protocols_by_ip } => {
                writeln!(f, "  ALPN protocols by IP:")?;
                for (ip, protocols) in sorted_ip_entries(protocols_by_ip) {
                    writeln!(
                        f,
                        "    {} -> {}",
                        ip.to_string().yellow(),
                        join_sorted_strings(protocols)
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
            match aggregated.session_resumption_caching {
                Some(true) => "✓ All measured backends".green(),
                Some(false) => "✗ Not all measured backends".red(),
                None => "? Inconclusive / not measured".yellow(),
            }
        )?;
        writeln!(
            f,
            "    Tickets: {}",
            match aggregated.session_resumption_tickets {
                Some(true) => "✓ All measured backends".green(),
                Some(false) => "✗ Not all measured backends".red(),
                None => "? Inconclusive / not measured".yellow(),
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

    /// Helper to color grade strings using the explicit aggregated grade.
    fn color_grade(grade: &str, _score: u8) -> colored::ColoredString {
        match grade {
            "A+" | "A" => grade.green().bold(),
            "A-" | "B" => grade.blue().bold(),
            "C" => grade.yellow(),
            "D" | "E" | "F" => grade.red(),
            "T" | "M" => grade.red().bold(),
            _ => grade.normal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::network::Target;
    use std::collections::HashMap;

    #[test]
    fn test_color_grade_includes_grade_text() {
        let grade = MultiIpScanReport::color_grade("A", 95).to_string();
        assert!(grade.contains('A'));

        let grade = MultiIpScanReport::color_grade("F", 10).to_string();
        assert!(grade.contains('F'));
    }

    #[test]
    fn test_color_grade_preserves_explicit_grade_when_score_disagrees() {
        let grade = MultiIpScanReport::color_grade("T", 95).to_string();
        assert!(grade.contains('T'));
        assert!(!grade.contains("A+"));
    }

    #[test]
    fn test_display_report_includes_header_and_target() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.10".parse().unwrap()],
        )
        .unwrap();

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 0,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: Vec::new(),
        };

        let output = format!("{}", report);
        assert!(output.contains("MULTI-IP SCAN REPORT"));
        assert!(output.contains("Target:"));
        assert!(output.contains("example.com"));
    }

    #[test]
    fn test_display_report_brackets_ipv6_target() {
        let target =
            Target::with_ips("::1".to_string(), 443, vec!["192.0.2.10".parse().unwrap()]).unwrap();

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 0,
            failed_scans: 1,
            total_duration_ms: 0,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("F".to_string(), 0),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: Vec::new(),
        };

        let output = format!("{}", report);
        assert!(output.contains("Target: [::1]:443"));
        assert!(!output.contains("Target: ::1:443"));
    }

    #[test]
    fn test_display_report_includes_totals() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.11".parse().unwrap()],
        )
        .unwrap();

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 2,
            successful_scans: 1,
            failed_scans: 1,
            total_duration_ms: 123,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("B".to_string(), 80),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: Vec::new(),
        };

        let output = format!("{}", report);
        assert!(output.contains("IPs Scanned:"));
        assert!(output.contains("1"));
        assert!(output.contains("/2 successful"));
    }

    #[test]
    fn test_display_report_includes_inconsistency_warning() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.12".parse().unwrap()],
        )
        .unwrap();

        let inconsistency = Inconsistency {
            inconsistency_type: InconsistencyType::ProtocolSupport,
            severity: crate::vulnerabilities::Severity::High,
            description: "Protocol mismatch".to_string(),
            ips_affected: vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()],
            details: InconsistencyDetails::Protocols {
                protocol: crate::protocols::Protocol::TLS12,
                ips_with_support: vec!["192.0.2.10".parse().unwrap()],
                ips_without_support: vec!["192.0.2.11".parse().unwrap()],
            },
        };

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 2,
            successful_scans: 2,
            failed_scans: 0,
            total_duration_ms: 20,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("A".to_string(), 95),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: vec![inconsistency],
        };

        let output = format!("{}", report);
        assert!(output.contains("INCONSISTENCIES DETECTED"));
        assert!(output.contains("Protocol mismatch"));
    }

    #[test]
    fn test_display_report_without_inconsistencies() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.13".parse().unwrap()],
        )
        .unwrap();

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 5,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("A".to_string(), 95),
                certificate_info: None,
                certificate_consistent: true,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: Vec::new(),
        };

        let output = format!("{}", report);
        assert!(!output.contains("INCONSISTENCIES DETECTED"));
        assert!(!output.contains("Recommendations:"));
        assert!(output.contains("Aggregated Results"));
    }

    #[test]
    fn test_display_certificate_inconsistency_handles_short_fingerprint() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["192.0.2.14".parse().unwrap()],
        )
        .unwrap();

        let ip: IpAddr = "192.0.2.14".parse().unwrap();
        let mut fingerprints = HashMap::new();
        fingerprints.insert(ip, "<empty>".to_string());

        let report = MultiIpScanReport {
            target,
            per_ip_results: HashMap::new(),
            total_ips: 1,
            successful_scans: 1,
            failed_scans: 0,
            total_duration_ms: 1,
            aggregated: AggregatedScanResult {
                protocols: Vec::new(),
                ciphers: HashMap::new(),
                grade: ("A".to_string(), 95),
                certificate_info: None,
                certificate_consistent: false,
                inconsistencies: Vec::new(),
                alpn_protocols: Vec::new(),
                session_resumption_caching: Some(false),
                session_resumption_tickets: Some(false),
            },
            inconsistencies: vec![Inconsistency {
                inconsistency_type: InconsistencyType::Certificates,
                severity: crate::vulnerabilities::Severity::High,
                description: "Certificate mismatch".to_string(),
                ips_affected: vec![ip],
                details: InconsistencyDetails::Certificates { fingerprints },
            }],
        };

        let output = format!("{}", report);
        assert!(output.contains("Different certificates detected"));
        assert!(output.contains("<empty>"));
    }
}
