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

mod advanced_tls;
mod certificates;
mod ciphers;
mod client_simulation;
mod dns_only;
mod fingerprints;
mod header;
mod helpers;
mod http_headers;
mod protocols;
mod rating;
mod summary;
mod vulnerabilities;

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
pub(crate) use helpers::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WarningMode {
    Default,
    Off,
    Batch,
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

    pub(crate) fn warning_mode(&self) -> WarningMode {
        match self
            .args
            .output
            .warnings
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("off") => WarningMode::Off,
            Some("batch") => WarningMode::Batch,
            _ => WarningMode::Default,
        }
    }

    pub(crate) fn show_warnings_inline(&self) -> bool {
        self.warning_mode() == WarningMode::Default
    }

    pub(crate) fn collect_human_warnings(
        &self,
        results: &crate::scanner::ScanResults,
    ) -> Vec<String> {
        let mut warnings = Vec::new();

        if let Some(rating) = results.ssl_rating() {
            warnings.extend(rating.warnings.iter().cloned());
        }

        if let Some(cert) = &results.certificate_chain
            && let Some(leaf) = cert.chain.leaf()
            && let Some(true) = leaf.debian_weak_key
        {
            warnings.push("Debian weak key detected (CVE-2008-0166)".to_string());
        }

        warnings.extend(
            results
                .vulnerabilities
                .iter()
                .filter(|result| result.inconclusive)
                .map(|result| format!("{:?}: inconclusive - {}", result.vuln_type, result.details)),
        );

        warnings.extend(results.scan_metadata.human_warnings.iter().cloned());
        warnings.sort();
        warnings.dedup();
        warnings
    }

    pub(crate) fn section_header(&self, title: &str) -> ColoredString {
        if self.args.output.colorblind {
            title.blue().bold()
        } else {
            title.cyan().bold()
        }
    }

    pub(crate) fn divider(&self, width: usize) -> String {
        let effective = if self.args.output.wide {
            width.saturating_mul(2)
        } else {
            width
        };
        "=".repeat(effective)
    }

    pub(crate) fn expand_width(&self, width: usize) -> usize {
        if self.args.output.wide {
            width.saturating_mul(2)
        } else {
            width
        }
    }

    pub(crate) fn print_section(&self, title: &str, width: usize) {
        println!("\n{}", self.section_header(title));
        println!("{}", self.divider(width));
    }

    // ------------------------------------------------------------------------
    // Results Summary Display
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Rating Display Methods
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Client Simulation Display Methods
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Signature and Group Display Methods
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Fingerprint Display Methods
    // ------------------------------------------------------------------------
}

#[cfg(test)]
mod tests;
