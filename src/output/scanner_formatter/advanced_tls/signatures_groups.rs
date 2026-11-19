use super::super::{
    GroupEnumerationResult, ScannerFormatter, SignatureEnumerationResult, format_status_indicator,
};
use colored::Colorize;
impl<'a> ScannerFormatter<'a> {
    pub fn display_signature_results(&self, results: &SignatureEnumerationResult) {
        self.print_section("Signature Algorithms:", 50);

        let supported: Vec<_> = results.algorithms.iter().filter(|a| a.supported).collect();
        let total = results.algorithms.len();

        println!("  Supported: {}/{}", supported.len(), total);
        println!();

        for algo in &results.algorithms {
            let status = format_status_indicator(algo.supported);
            println!("  {} {:<30} (0x{:04x})", status, algo.name, algo.iana_value);
        }
    }

    pub fn display_group_results(&self, results: &GroupEnumerationResult) {
        use crate::protocols::groups::GroupType;

        self.print_section("Key Exchange Groups:", 50);

        if !results.measured {
            println!("  Status:    {}", "Inconclusive".yellow().bold());
            println!("  Details:   {}", results.details);
            return;
        }

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

        // --no-cipher-details hides per-curve names and DHE key lengths, leaving
        // only the supported/total counts for the EC and finite-field categories.
        let hide_details = self.args.scan.no_cipher_details;
        self.display_group_category("Elliptic Curve Groups:", &ec_groups, hide_details);
        self.display_group_category("Finite Field (DHE) Groups:", &ff_groups, hide_details);
        self.display_group_category("Post-Quantum Groups:", &pq_groups, false);
    }

    fn display_group_category(
        &self,
        title: &str,
        groups: &[&crate::protocols::groups::KeyExchangeGroup],
        hide_details: bool,
    ) {
        if groups.is_empty() {
            return;
        }

        println!("\n  {}", title.cyan());

        if hide_details {
            let supported = groups.iter().filter(|g| g.supported).count();
            println!(
                "    Supported: {}/{} (details hidden)",
                supported,
                groups.len()
            );
            return;
        }

        for group in groups {
            let status = format_status_indicator(group.supported);
            println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScannerFormatter;
    use crate::cli::Args;
    use crate::protocols::groups::{GroupEnumerationResult, GroupType, KeyExchangeGroup};
    use crate::protocols::signatures::{SignatureAlgorithm, SignatureEnumerationResult};

    #[test]
    fn displays_signature_algorithms_and_measured_group_categories() {
        colored::control::set_override(false);
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);
        formatter.display_signature_results(&SignatureEnumerationResult {
            algorithms: vec![
                SignatureAlgorithm {
                    name: "rsa_pkcs1_sha256".to_string(),
                    iana_value: 0x0401,
                    supported: true,
                },
                SignatureAlgorithm {
                    name: "rsa_pkcs1_sha1".to_string(),
                    iana_value: 0x0201,
                    supported: false,
                },
            ],
            inconclusive: false,
        });

        formatter.display_group_results(&GroupEnumerationResult {
            groups: Vec::new(),
            measured: false,
            details: "probe failed".to_string(),
        });

        formatter.display_group_results(&GroupEnumerationResult {
            groups: vec![
                group("secp256r1", GroupType::EllipticCurve, true),
                group("ffdhe2048", GroupType::FiniteField, false),
                group("X25519MLKEM768", GroupType::PostQuantum, true),
            ],
            measured: true,
            details: String::new(),
        });
    }

    #[test]
    fn group_details_respect_the_no_cipher_details_option() {
        colored::control::set_override(false);
        let mut args = Args::default();
        args.scan.no_cipher_details = true;
        let formatter = ScannerFormatter::new(&args);

        formatter.display_group_results(&GroupEnumerationResult {
            groups: vec![
                group("secp256r1", GroupType::EllipticCurve, true),
                group("ffdhe2048", GroupType::FiniteField, false),
                group("X25519MLKEM768", GroupType::PostQuantum, true),
            ],
            measured: true,
            details: String::new(),
        });
    }

    fn group(name: &str, group_type: GroupType, supported: bool) -> KeyExchangeGroup {
        KeyExchangeGroup {
            name: name.to_string(),
            iana_value: 0x001d,
            group_type,
            bits: 256,
            supported,
            quantum_vulnerable: group_type != GroupType::PostQuantum,
        }
    }
}
