use super::super::{
    GroupEnumerationResult, ScannerFormatter, SignatureEnumerationResult, format_status_indicator,
};
use colored::*;

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

        self.display_group_category("Elliptic Curve Groups:", &ec_groups);
        self.display_group_category("Finite Field (DHE) Groups:", &ff_groups);
        self.display_group_category("Post-Quantum Groups:", &pq_groups);
    }

    fn display_group_category(
        &self,
        title: &str,
        groups: &[&crate::protocols::groups::KeyExchangeGroup],
    ) {
        if !groups.is_empty() {
            println!("\n  {}", title.cyan());
            for group in groups {
                let status = format_status_indicator(group.supported);
                println!("    {} {:<30} ({} bits)", status, group.name, group.bits);
            }
        }
    }
}
