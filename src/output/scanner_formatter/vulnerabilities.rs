use super::{ScannerFormatter, VulnerabilityResult, print_section_header};
use colored::*;
use std::collections::HashMap;

fn ordered_vulnerability_severity_counts(
    by_severity: &HashMap<crate::vulnerabilities::Severity, usize>,
) -> Vec<(crate::vulnerabilities::Severity, usize)> {
    use crate::vulnerabilities::Severity;

    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .filter_map(|severity| {
        by_severity
            .get(&severity)
            .copied()
            .map(|count| (severity, count))
    })
    .collect()
}

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

            for (severity, count) in ordered_vulnerability_severity_counts(by_severity) {
                match severity {
                    Severity::Critical => {
                        println!("  Critical: {}", count.to_string().red().bold())
                    }
                    Severity::High => println!("  High:     {}", count.to_string().red()),
                    Severity::Medium => println!("  Medium:   {}", count.to_string().yellow()),
                    Severity::Low => println!("  Low:      {}", count),
                    Severity::Info => println!("  Info:     {}", count.to_string().cyan()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::Severity;

    #[test]
    fn test_ordered_vulnerability_severity_counts_includes_info() {
        let mut by_severity = HashMap::new();
        by_severity.insert(Severity::Info, 2);
        by_severity.insert(Severity::High, 1);

        let ordered = ordered_vulnerability_severity_counts(&by_severity);

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0], (Severity::High, 1));
        assert_eq!(ordered[1], (Severity::Info, 2));
    }
}
