use super::{ScannerFormatter, VulnerabilityResult, print_section_header};
use colored::*;
use std::collections::HashMap;

impl<'a> ScannerFormatter<'a> {
    /// Display vulnerability results
    pub fn display_vulnerability_results(&self, results: &[VulnerabilityResult]) {
        print_section_header("Vulnerability Assessment:");

        let mut vulnerable_count = 0;
        let mut inconclusive_count = 0;
        let mut by_severity: HashMap<crate::vulnerabilities::Severity, usize> = HashMap::new();

        for result in results {
            if result.vulnerable {
                vulnerable_count += 1;
                *by_severity.entry(result.severity).or_insert(0) += 1;
                self.display_single_vulnerability(result);
            } else if result.inconclusive {
                inconclusive_count += 1;
                self.display_single_vulnerability(result);
            }
        }

        self.display_vulnerability_summary(vulnerable_count, inconclusive_count, &by_severity);
    }

    /// Display a single vulnerability result
    fn display_single_vulnerability(&self, result: &VulnerabilityResult) {
        let marker = if result.vulnerable {
            "X".red().bold().to_string()
        } else {
            "?".yellow().bold().to_string()
        };
        println!("\n{} {:?}", marker, result.vuln_type);
        println!("  Severity: {}", result.severity.colored_display());
        println!("  Status:   {}", result.status_label());
        if let Some(cve) = &result.cve {
            println!("  CVE:      {}", cve);
        }
        println!("  Details:  {}", result.details);
    }

    /// Display vulnerability summary
    fn display_vulnerability_summary(
        &self,
        vulnerable_count: usize,
        inconclusive_count: usize,
        by_severity: &HashMap<crate::vulnerabilities::Severity, usize>,
    ) {
        use crate::vulnerabilities::Severity;

        println!("\n{}", "=".repeat(50));
        if vulnerable_count == 0 && inconclusive_count == 0 {
            println!("{}", "Y No vulnerabilities found!".green().bold());
        } else {
            if vulnerable_count > 0 {
                println!(
                    "{} {} vulnerability(ies) found",
                    "!".red().bold(),
                    vulnerable_count.to_string().red().bold()
                );
            }
            if inconclusive_count > 0 {
                println!(
                    "{} {} inconclusive vulnerability check(s)",
                    "?".yellow().bold(),
                    inconclusive_count.to_string().yellow().bold()
                );
            }

            if let Some(count) = by_severity.get(&Severity::Critical) {
                println!("  Critical: {}", count.to_string().red().bold());
            }
            if let Some(count) = by_severity.get(&Severity::High) {
                println!("  High:     {}", count.to_string().red());
            }
            if let Some(count) = by_severity.get(&Severity::Medium) {
                println!("  Medium:   {}", count.to_string().yellow());
            }
            if let Some(count) = by_severity.get(&Severity::Low) {
                println!("  Low:      {}", count);
            }
        }
    }
}
