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
// - ScanRequest (scan configuration for validation options)

use super::{ScanContext, ScanPhase};
use crate::Result;
use crate::application::ScanRequest;
use crate::certificates::{
    parser::{CertificateChain, CertificateParser},
    revocation::{RevocationChecker, RevocationResult},
    revocation_strict::StrictRevocationChecker,
    validator::{CertificateValidator, ValidationResult},
};
use crate::external::openssl_client::{OpenSslClient, OpenSslClientOptions};
use async_trait::async_trait;
use std::time::Duration;

/// Certificate analysis phase
///
/// Analyzes the server's certificate chain including:
/// - Certificate chain parsing (leaf, intermediates, root)
/// - Chain validation (expiry, trust, hostname matching)
/// - Revocation status checking (OCSP, CRL)
///
/// Configuration sources (from ScanRequest):
/// - Certificate validation (--no-check-certificate disables validation)
/// - Revocation checking (--phone-out enables OCSP/CRL checks)
/// - mTLS client authentication (--mtls, --pk, --certs)
pub struct CertificatePhase;

impl CertificatePhase {
    /// Create a new certificate analysis phase
    pub fn new() -> Self {
        Self
    }

    /// Resolve the TLS hostname used for certificate fetch and validation.
    fn tls_hostname(context: &ScanContext) -> String {
        context
            .args
            .as_ref()
            .effective_sni(&context.target.hostname)
    }

    /// Parse certificate chain from server
    ///
    /// Establishes TLS connection to server and extracts the certificate
    /// chain from the handshake. Supports both standard TLS and mTLS.
    async fn parse_certificate_chain(&self, context: &ScanContext) -> Result<CertificateChain> {
        if context.args.tls.ssl_native {
            return self.parse_certificate_chain_with_openssl(context).await;
        }

        let mut target = context.target();
        target.hostname = Self::tls_hostname(context);

        // Create parser with optional mTLS configuration
        let parser = if let Some(ref mtls_config) = context.mtls_config {
            CertificateParser::with_mtls(target, mtls_config.clone())
        } else {
            CertificateParser::new(target)
        };

        // Extract certificate chain from TLS handshake
        parser.get_certificate_chain().await
    }

    async fn parse_certificate_chain_with_openssl(
        &self,
        context: &ScanContext,
    ) -> Result<CertificateChain> {
        let target = context.target();
        let connect_host = target.primary_ip().to_string();
        let openssl = if let Some(path) = &context.args.tls.openssl_path {
            OpenSslClient::with_path(path.display().to_string())
        } else {
            OpenSslClient::new()
        };

        let options = OpenSslClientOptions {
            host: connect_host,
            port: target.port,
            starttls: Self::openssl_starttls(context),
            xmpphost: context.args.starttls.xmpphost.clone(),
            servername: Some(Self::tls_hostname(context)),
            showcerts: true,
            timeout: context.args.tls.openssl_timeout.map(Duration::from_secs),
            verify_locations: context
                .args
                .tls
                .add_ca
                .as_ref()
                .map(|path| path.display().to_string()),
            cert: context
                .args
                .tls
                .mtls_cert
                .as_ref()
                .map(|path| path.display().to_string()),
            key: context
                .args
                .tls
                .client_key
                .as_ref()
                .map(|path| path.display().to_string()),
            pass: context.args.tls.client_key_password.clone(),
            proxy: context.args.network.proxy.clone(),
            bugs: context.args.tls.bugs,
            ..Default::default()
        };

        let result = openssl.run(&options)?;
        if !result.success {
            let error_output = if result.stderr.trim().is_empty() {
                result.stdout.trim()
            } else {
                result.stderr.trim()
            };
            return Err(crate::TlsError::Other(format!(
                "OpenSSL certificate fetch failed: {}",
                error_output
            )));
        }

        Self::parse_pem_certificate_chain(&result.stdout)
    }

    fn parse_pem_certificate_chain(pem_bundle: &str) -> Result<CertificateChain> {
        let certificates = openssl::x509::X509::stack_from_pem(pem_bundle.as_bytes())?;
        if certificates.is_empty() {
            return Err(crate::TlsError::Other(
                "OpenSSL did not return any certificates".to_string(),
            ));
        }

        let mut parsed_certs = Vec::with_capacity(certificates.len());
        for certificate in certificates {
            let der = certificate.to_der()?;
            parsed_certs.push(CertificateParser::parse_certificate(&der)?);
        }

        let chain_size_bytes: usize = parsed_certs.iter().map(|c| c.der_bytes.len()).sum();
        Ok(CertificateChain {
            chain_length: parsed_certs.len(),
            chain_size_bytes,
            certificates: parsed_certs,
        })
    }

    fn openssl_starttls(context: &ScanContext) -> Option<String> {
        if context.args.starttls.xmpp_server {
            return Some("xmpp-server".to_string());
        }

        match context.args.starttls_protocol() {
            Some(crate::starttls::StarttlsProtocol::SMTP) => Some("smtp".to_string()),
            Some(crate::starttls::StarttlsProtocol::POP3) => Some("pop3".to_string()),
            Some(crate::starttls::StarttlsProtocol::IMAP) => Some("imap".to_string()),
            Some(crate::starttls::StarttlsProtocol::FTP) => Some("ftp".to_string()),
            Some(crate::starttls::StarttlsProtocol::XMPP) => Some("xmpp".to_string()),
            Some(crate::starttls::StarttlsProtocol::LDAP) => Some("ldap".to_string()),
            Some(crate::starttls::StarttlsProtocol::IRC) => Some("irc".to_string()),
            Some(crate::starttls::StarttlsProtocol::POSTGRES) => Some("postgres".to_string()),
            Some(crate::starttls::StarttlsProtocol::MYSQL) => Some("mysql".to_string()),
            Some(crate::starttls::StarttlsProtocol::NNTP) => Some("nntp".to_string()),
            Some(crate::starttls::StarttlsProtocol::SIEVE) => Some("sieve".to_string()),
            Some(crate::starttls::StarttlsProtocol::LMTP) => Some("lmtp".to_string()),
            _ => None,
        }
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
        // When --no-check-certificate is set, skip all validation and return a
        // permissive result. skip_warnings=true only suppresses minor advisories
        // (e.g. expiring-soon), not critical failures like expired or untrusted certs.
        if context.args.scan.certs.no_check_certificate {
            return Ok(ValidationResult {
                valid: true,
                not_expired: true,
                hostname_match: true,
                trust_chain_valid: true,
                signature_valid: true,
                trusted_ca: None,
                platform_trust: None,
                issues: vec![],
            });
        }

        let hostname = Self::tls_hostname(context);

        let validator = if let Some(additional_ca) = context.args.tls.add_ca.as_deref() {
            CertificateValidator::with_platform_trust_and_additional_ca(hostname, additional_ca)?
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
    ) -> Result<Option<RevocationResult>> {
        // Revocation details can come from two sources:
        // - direct OCSP/CRL lookups when phone-out is enabled
        // - stapling analysis when --ocsp requested and pre-handshake data exists
        if !context.args.tls.phone_out && !context.args.scan.certs.ocsp {
            return Ok(None);
        }

        // Extract leaf certificate (the server's certificate)
        let Some(leaf_cert) = chain.certificates.first() else {
            return Ok(None);
        };

        // Extract issuer certificate (for OCSP/CRL verification)
        let issuer_cert = if chain.certificates.len() >= 2 {
            chain.certificates.get(1)
        } else {
            None
        };

        // Perform revocation check
        let stapling_checker = RevocationChecker::new(context.args.tls.phone_out);
        let mut revocation = if context.args.tls.phone_out {
            StrictRevocationChecker::new(context.args.tls.phone_out, context.args.tls.hardfail)
                .check_revocation_with_hardfail(leaf_cert, issuer_cert)
                .await?
                .base_result
        } else {
            RevocationResult {
                status: crate::certificates::revocation::RevocationStatus::NotChecked,
                method: crate::certificates::revocation::RevocationMethod::None,
                details: "Phone-out disabled; remote OCSP/CRL lookups were skipped".to_string(),
                ocsp_stapling: false,
                ocsp_stapling_details: None,
                must_staple: stapling_checker.check_must_staple(leaf_cert)?,
            }
        };

        if let Some(pre_handshake) = context.pre_handshake.as_ref() {
            let stapling = stapling_checker.check_ocsp_stapling(&pre_handshake.handshake_data);
            revocation.ocsp_stapling = stapling.stapled_response_present;
            revocation.ocsp_stapling_details = Some(stapling);
        }

        Ok(Some(revocation))
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

    fn should_run(&self, args: &ScanRequest) -> bool {
        args.should_run_certificate_phase()
    }

    async fn execute(&self, context: &mut ScanContext) -> Result<()> {
        // Phase 1: Parse certificate chain from server
        let chain = self.parse_certificate_chain(context).await?;

        // Phase 2: Validate certificate chain
        let validation = self.validate_certificate_chain(context, &chain)?;

        // Phase 3: Check revocation status (optional, requires --phone-out)
        let revocation = self.check_revocation_status(context, &chain).await?;

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
        let mut args = ScanRequest::default();
        args.scan.scope.all = true;
        assert!(phase.should_run(&args));

        // Target alone should not imply baseline scanning
        let args = ScanRequest {
            target: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!phase.should_run(&args));

        // Test with no relevant flags
        let args = ScanRequest::default();
        assert!(!phase.should_run(&args));
    }

    #[test]
    fn test_certificate_phase_name() {
        let phase = CertificatePhase::new();
        assert_eq!(phase.name(), "Analyzing Certificate");
    }

    #[test]
    fn test_certificate_phase_tls_hostname_prefers_explicit_sni() {
        let target = crate::utils::network::Target::with_ips(
            "93.184.216.34".to_string(),
            443,
            vec!["93.184.216.34".parse().unwrap()],
        )
        .unwrap();

        let mut args = ScanRequest::default();
        args.tls.sni_name = Some("cdn.example".to_string());

        let context = ScanContext::new(target, Arc::new(args), None, None);

        assert_eq!(CertificatePhase::tls_hostname(&context), "cdn.example");
    }

    #[tokio::test]
    async fn test_revocation_check_skipped_without_phone_out() {
        let target = crate::utils::network::Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let args = Arc::new(ScanRequest::default());
        let context = ScanContext::new(target, args, None, None);

        let chain = CertificateChain {
            certificates: vec![crate::certificates::parser::CertificateInfo::default()],
            chain_length: 1,
            chain_size_bytes: 0,
        };

        let phase = CertificatePhase::new();
        let result = phase
            .check_revocation_status(&context, &chain)
            .await
            .expect("revocation check should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_certificate_phase_should_run_for_explicit_certificate_analysis() {
        let phase = CertificatePhase::new();
        let mut args = ScanRequest::default();
        args.scan.certs.analyze_certificates = true;
        assert!(phase.should_run(&args));
    }
}
