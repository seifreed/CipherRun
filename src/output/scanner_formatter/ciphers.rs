use super::{
    Protocol, ProtocolCipherSummary, ScannerFormatter, display_cipher_security_features,
    display_cipher_strength_distribution, format_avg_timing,
};
use colored::*;
use std::collections::HashMap;

impl<'a> ScannerFormatter<'a> {
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
}
