use super::{
    Ja3Fingerprint, Ja3Signature, Ja3sFingerprint, Ja3sSignature, JarmFingerprint,
    ScannerFormatter, format_threat_level, print_section_header,
};
use colored::*;

impl<'a> ScannerFormatter<'a> {
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
