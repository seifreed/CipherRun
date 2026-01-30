// Certificate Analysis Phase - Analyzes server certificate chain
//
// This phase is responsible for analyzing the SSL/TLS certificate chain
// presented by the target server, including validation and revocation checking.
//
// Responsibilities (Single Responsibility Principle):
// - Parse certificate chain from TLS handshake
// - Validate certificate chain against platform trust stores
// - Check revocation status (OCSP/CRL) if enabled
// - Store certificate analysis results in scan context
//
// Dependencies:
// - CertificateParser (parse certificate chain)
// - CertificateValidator (validate chain against trust stores)
// - RevocationChecker (OCSP/CRL checking)
// - Args (CLI configuration for validation options)

use super::{ScanContext, ScanPhase};
use crate::certificates::{
    parser::{CertificateChain, CertificateParser},
    revocation::{RevocationChecker, RevocationResult},
    validator::{CertificateValidator, ValidationResult},
};
use crate::{Args, Result};
use async_trait::async_trait;

/// Certificate analysis phase
///
/// Analyzes the server's certificate chain including:
/// - Certificate chain parsing (leaf, intermediates, root)
/// - Chain validation (expiry, trust, hostname matching)
/// - Revocation status checking (OCSP, CRL)
///
/// Configuration sources (from Args):
/// - Certificate validation (--no-check-certificate disables validation)
/// - Revocation checking (--phone-out enables OCSP/CRL checks)
/// - mTLS client authentication (--mtls, --pk, --certs)
pub struct CertificatePhase;

impl CertificatePhase {
    /// Create a new certificate analysis phase
    pub fn new() -> Self {
        Self
    }

    /// Parse certificate chain from server
    ///
    /// Establishes TLS connection to server and extracts the certificate
    /// chain from the handshake. Supports both standard TLS and mTLS.
    async fn parse_certificate_chain(&self, context: &ScanContext) -> Result<CertificateChain> {
        let target = context.target();

        // Create parser with optional mTLS configuration
        let parser = if let Some(ref mtls_config) = context.mtls_config {
            CertificateParser::with_mtls(target, mtls_config.clone())
        } else {
            CertificateParser::new(target)
        };

        // Extract certificate chain from TLS handshake
        parser.get_certificate_chain().await
    }

    /// Validate certificate chain
    ///
    /// Performs comprehensive certificate validation including:
    /// - Expiration checks (not before, not after dates)
    /// - Trust chain verification (against platform trust stores)
    /// - Hostname matching (against target hostname)
    /// - Key usage validation (digitalSignature, keyEncipherment)
    ///
    /// Platform trust stores used:
    /// - macOS: Security.framework
    /// - Windows: CryptoAPI
    /// - Linux: /etc/ssl/certs, /etc/pki/tls/certs
    fn validate_certificate_chain(
        &self,
        context: &ScanContext,
        chain: &CertificateChain,
    ) -> Result<ValidationResult> {
        let hostname = context.target.hostname.clone();

        // Create validator with platform trust
        // If --no-check-certificate is set, disable strict validation
        let validator = if context.args.scan.no_check_certificate {
            CertificateValidator::with_config(hostname, true, true)?
        } else {
            CertificateValidator::with_platform_trust(hostname)?
        };

        // Validate entire chain
        validator.validate_chain(chain)
    }

    /// Check certificate revocation status
    ///
    /// Checks if the leaf certificate has been revoked using:
    /// 1. OCSP (Online Certificate Status Protocol)
    /// 2. CRL (Certificate Revocation List)
    ///
    /// This requires network access (--phone-out flag).
    /// If the issuer certificate is available, it is used to verify
    /// OCSP responses and CRL signatures.
    async fn check_revocation_status(
        &self,
        context: &ScanContext,
        chain: &CertificateChain,
    ) -> Option<RevocationResult> {
        // Only check revocation if phone-out is enabled
        // Phone-out means the scanner is allowed to make external network calls
        if !context.args.tls.phone_out {
            return None;
        }

        // Extract leaf certificate (the server's certificate)
        let leaf_cert = chain.certificates.first()?;

        // Extract issuer certificate (for OCSP/CRL verification)
        let issuer_cert = if chain.certificates.len() >= 2 {
            chain.certificates.get(1)
        } else {
            None
        };

        // Perform revocation check
        let checker = RevocationChecker::new(true);
        checker
            .check_revocation_status(leaf_cert, issuer_cert)
            .await
            .ok()
    }
}

impl Default for CertificatePhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for CertificatePhase {
    fn name(&self) -> &'static str {
        "Analyzing Certificate"
    }

    fn should_run(&self, args: &Args) -> bool {
        // Run if:
        // - Full scan mode (--all)
        // - Default scan (target specified without other flags)
        args.scan.all || args.target.is_some()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Phase 1: Parse certificate chain from server
        let chain = self.parse_certificate_chain(context).await?;

        // Phase 2: Validate certificate chain
        let validation = self.validate_certificate_chain(context, &chain)?;

        // Phase 3: Check revocation status (optional, requires --phone-out)
        let revocation = self.check_revocation_status(context, &chain).await;

        // Store results in context
        context.results.certificate_chain = Some(crate::scanner::CertificateAnalysisResult {
            chain,
            validation,
            revocation,
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_certificate_phase_should_run() {
        let phase = CertificatePhase::new();

        // Test with --all flag
        let mut args = Args::default();
        args.scan.all = true;
        assert!(phase.should_run(&args));

        // Test with target specified (default scan)
        let mut args = Args::default();
        args.target = Some("example.com".to_string());
        assert!(phase.should_run(&args));

        // Test with no relevant flags
        let args = Args::default();
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_certificate_phase_name() {
        let phase = CertificatePhase::new();
        assert_eq!(phase.name(), "Analyzing Certificate");
    }
}
