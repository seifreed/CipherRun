use super::{
    CertificateAnalysisResult, CertificateChain, CertificateInfo, ColoredString, RevocationResult,
    ScannerFormatter, TrustValidationResult, ValidationResult, format_bool_indicator,
    format_key_size, format_revocation_status, format_status_indicator, get_cert_type,
    truncate_with_ellipsis,
};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    /// Display certificate analysis results
    pub fn display_certificate_results(&self, result: &CertificateAnalysisResult) {
        self.print_section("Certificate Analysis:", 50);

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
        println!("\n{}", self.section_header("Certificate Information:"));
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
        if self.warning_mode() != super::WarningMode::Default {
            return;
        }

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
        println!("\n{}", self.section_header("Certificate Chain:"));
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
        println!("\n  {}", self.section_header("Full Certificate Chain:"));
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
        println!("\n{}", self.section_header("Validation:"));
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
        println!("\n{}", self.section_header("Revocation Status:"));
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

        println!("\n  {}", self.section_header("OCSP Details:"));

        println!(
            "    Must-Staple:  {}",
            if revocation.must_staple {
                "Y Required by certificate".green()
            } else {
                "No".normal()
            }
        );

        if let Some(stapling) = &revocation.ocsp_stapling_details {
            println!(
                "    Supported:    {}",
                if stapling.stapling_supported {
                    "Y Advertised by server".green()
                } else {
                    "No".yellow()
                }
            );
            println!(
                "    Stapled Resp: {}",
                if stapling.stapled_response_present {
                    "Y Present in handshake".green()
                } else {
                    "No".yellow()
                }
            );
            if let Some(valid) = stapling.stapled_response_valid {
                println!(
                    "    Validation:   {}",
                    if valid {
                        "Y Response structure looks valid".green()
                    } else {
                        "X Invalid stapled response".red()
                    }
                );
            }
            println!("    Handshake:    {}", stapling.details);
        } else {
            println!("    Stapling:     Information unavailable for this connection");
        }

        if matches!(revocation.method, RevocationMethod::OCSP) {
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
                let root_display = truncate_with_ellipsis(root, self.expand_width(50));
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
            let message_display = truncate_with_ellipsis(&status.message, self.expand_width(50));
            println!(
                "    {} {} - {}",
                status_symbol,
                platform_name.cyan(),
                message_display.dimmed()
            );
        }
    }
}
