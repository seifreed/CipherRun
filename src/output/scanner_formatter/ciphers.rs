use super::{
    Protocol, ProtocolCipherSummary, ScannerFormatter, display_cipher_security_features,
    display_cipher_strength_distribution, format_avg_timing,
};
use colored::*;
use std::collections::HashMap;

impl<'a> ScannerFormatter<'a> {
    /// Display cipher test results
    pub fn display_cipher_results(&self, results: &HashMap<Protocol, ProtocolCipherSummary>) {
        let mut results: Vec<_> = results.iter().collect();
        results.sort_by_key(|(protocol, _)| **protocol);

        for (protocol, summary) in results {
            let timing_info =
                format_avg_timing(self.args.output.show_times, summary.avg_handshake_time_ms);

            println!(
                "\n{} - {} ciphers{}",
                self.section_header(&protocol.to_string()),
                summary.counts.total,
                timing_info
            );
            println!("{}", "-".repeat(self.expand_width(50)));

            if summary.counts.total == 0 {
                println!("  {}", "No ciphers supported".red());
                continue;
            }

            if self.args.scan.each_cipher {
                self.display_each_cipher_list(summary);
            } else if self.args.scan.categories {
                self.display_category_focus(summary);
            } else if self.args.scan.forward_secrecy {
                self.display_forward_secrecy_focus(summary);
            } else if self.args.scan.server_defaults || self.args.scan.server_preference {
                self.display_server_preference_focus(summary);
            } else {
                display_cipher_strength_distribution(&summary.counts);
                display_cipher_security_features(&summary.counts);
                self.display_cipher_ordering(summary);
            }
        }
    }

    fn display_each_cipher_list(&self, summary: &ProtocolCipherSummary) {
        display_cipher_strength_distribution(&summary.counts);
        println!("\n  Supported Cipher Suites:");

        for cipher in &summary.supported_ciphers {
            let cipher_name = self.format_cipher_name(cipher);
            let mut details = Vec::new();

            details.push(match cipher.strength() {
                crate::ciphers::CipherStrength::NULL => "NULL".red().bold().to_string(),
                crate::ciphers::CipherStrength::Export => "EXPORT".red().to_string(),
                crate::ciphers::CipherStrength::Low => "LOW".yellow().to_string(),
                crate::ciphers::CipherStrength::Medium => "MEDIUM".normal().to_string(),
                crate::ciphers::CipherStrength::High => "HIGH".green().to_string(),
            });

            if cipher.has_forward_secrecy() {
                details.push("FS".green().to_string());
            }
            if cipher.is_aead() {
                details.push("AEAD".green().to_string());
            }

            println!("    - {} [{}]", cipher_name, details.join(", "));
        }

        self.display_cipher_ordering(summary);
    }

    fn display_category_focus(&self, summary: &ProtocolCipherSummary) {
        println!("  {}", self.section_header("Category Summary:"));
        display_cipher_strength_distribution(&summary.counts);
        println!(
            "\n  Total by category: null={}, export={}, low={}, medium={}, high={}",
            summary.counts.null_ciphers,
            summary.counts.export_ciphers,
            summary.counts.low_strength,
            summary.counts.medium_strength,
            summary.counts.high_strength
        );
    }

    fn display_forward_secrecy_focus(&self, summary: &ProtocolCipherSummary) {
        println!("  {}", self.section_header("Forward Secrecy Focus:"));
        display_cipher_security_features(&summary.counts);

        let non_fs: Vec<_> = summary
            .supported_ciphers
            .iter()
            .filter(|cipher| !cipher.has_forward_secrecy())
            .collect();

        if non_fs.is_empty() {
            println!(
                "    {} All supported ciphers provide forward secrecy",
                "Y".green()
            );
            return;
        }

        println!(
            "    {} {} cipher suites do not provide forward secrecy:",
            "!".yellow(),
            non_fs.len()
        );
        for cipher in non_fs {
            println!("      - {}", self.format_cipher_name(cipher));
        }
    }

    fn display_server_preference_focus(&self, summary: &ProtocolCipherSummary) {
        println!("  {}", self.section_header("Server Preference Focus:"));
        self.display_cipher_ordering(summary);

        if summary.server_preference.is_empty() {
            println!("    Preference list unavailable");
            return;
        }

        println!("\n  Preference Order:");
        for (index, cipher_hex) in summary.server_preference.iter().enumerate() {
            let rendered = summary
                .supported_ciphers
                .iter()
                .find(|cipher| cipher.hexcode.eq_ignore_ascii_case(cipher_hex))
                .map(|cipher| self.format_cipher_name(cipher))
                .unwrap_or_else(|| format!("0x{}", cipher_hex));
            println!("    {}. {}", index + 1, rendered);
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

    fn format_cipher_name(&self, cipher: &crate::ciphers::CipherSuite) -> String {
        let cipher_name = if self.args.output.iana_names {
            &cipher.iana_name
        } else {
            &cipher.openssl_name
        };

        if self.args.output.show_cipher_ids {
            format!("{} (0x{})", cipher_name, cipher.hexcode)
        } else {
            cipher_name.to_string()
        }
    }
}
