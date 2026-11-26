use super::{ScannerFormatter, VulnerabilityResult};
use crate::vulnerabilities::FindingStatus;
use colored::Colorize;
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
        println!("\n{}", self.section_header("Vulnerability Assessment:"));
        println!("{}", "=".repeat(self.expand_width(50)));

        let mut vulnerable_count = 0;
        let mut potential_count = 0;
        let mut inconclusive_count = 0;
        let mut by_severity: HashMap<crate::vulnerabilities::Severity, usize> = HashMap::new();
        let show_inconclusive_inline = self.show_warnings_inline();

        for result in results {
            match result.status() {
                FindingStatus::ConfirmedVulnerable => {
                    vulnerable_count += 1;
                    *by_severity.entry(result.severity).or_insert(0) += 1;
                    self.display_single_vulnerability(result);
                }
                FindingStatus::PotentialExposure => {
                    potential_count += 1;
                    self.display_single_vulnerability(result);
                }
                FindingStatus::Inconclusive => {
                    inconclusive_count += 1;
                    if show_inconclusive_inline {
                        self.display_single_vulnerability(result);
                    }
                }
                FindingStatus::NotVulnerable
                | FindingStatus::NotApplicable
                | FindingStatus::NotExecuted => {}
            }
        }

        self.display_vulnerability_summary(
            vulnerable_count,
            potential_count,
            inconclusive_count,
            &by_severity,
            show_inconclusive_inline,
        );
    }

    /// Display a single vulnerability result
    fn display_single_vulnerability(&self, result: &VulnerabilityResult) {
        let marker = match result.status() {
            FindingStatus::ConfirmedVulnerable => "X".red().bold().to_string(),
            FindingStatus::PotentialExposure => "!".yellow().bold().to_string(),
            _ => "?".yellow().bold().to_string(),
        };
        println!("\n{} {:?}", marker, result.vuln_type);
        println!("  Severity: {}", result.severity.colored_display());
        println!("  Status:   {}", result.status_label());
        if let Some(cve) = &result.cve {
            println!("  CVE:      {}", cve);
        }
        println!("  Details:  {}", result.details);

        if self.args.output.hints {
            if let Some(hint) =
                crate::utils::hints::get_vulnerability_hint(&format!("{:?}", result.vuln_type))
            {
                println!("  Hint:     {}", hint.remediation);
            } else {
                let hint = crate::utils::hints::get_severity_hint(result.severity);
                println!("  Hint:     {}", hint.remediation);
            }
        }
    }

    /// Display vulnerability summary
    fn display_vulnerability_summary(
        &self,
        vulnerable_count: usize,
        potential_count: usize,
        inconclusive_count: usize,
        by_severity: &HashMap<crate::vulnerabilities::Severity, usize>,
        show_inconclusive_inline: bool,
    ) {
        use crate::vulnerabilities::Severity;

        println!("\n{}", "=".repeat(self.expand_width(50)));
        if vulnerable_count == 0 && potential_count == 0 && inconclusive_count == 0 {
            println!("{}", "Y No vulnerabilities found!".green().bold());
        } else if vulnerable_count == 0
            && potential_count == 0
            && inconclusive_count > 0
            && !show_inconclusive_inline
        {
            println!("{}", "? No confirmed vulnerabilities found".yellow().bold());
        } else {
            if vulnerable_count > 0 {
                println!(
                    "{} {} vulnerability(ies) found",
                    "!".red().bold(),
                    vulnerable_count.to_string().red().bold()
                );
            }
            if potential_count > 0 {
                println!(
                    "{} {} potential exposure(s) require review",
                    "!".yellow().bold(),
                    potential_count.to_string().yellow().bold()
                );
            }
            if inconclusive_count > 0 && show_inconclusive_inline {
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
    use crate::vulnerabilities::{Severity, VulnerabilityType};

    fn result(
        vuln_type: VulnerabilityType,
        vulnerable: bool,
        inconclusive: bool,
        severity: Severity,
    ) -> VulnerabilityResult {
        VulnerabilityResult {
            vuln_type,
            vulnerable,
            inconclusive,
            details: "test details".to_string(),
            cve: Some("CVE-2014-0160".to_string()),
            cwe: None,
            severity,
        }
    }

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

    #[test]
    fn display_results_covers_findings_severities_and_hint_paths() {
        let mut args = crate::Args::default();
        args.output.hints = true;
        let formatter = ScannerFormatter::new(&args);
        let results = [
            result(
                VulnerabilityType::Heartbleed,
                true,
                false,
                Severity::Critical,
            ),
            result(VulnerabilityType::CCSInjection, true, false, Severity::High),
            result(
                VulnerabilityType::Ticketbleed,
                true,
                false,
                Severity::Medium,
            ),
            result(VulnerabilityType::ROBOT, true, false, Severity::Low),
            result(VulnerabilityType::POODLE, true, false, Severity::Info),
            result(VulnerabilityType::FREAK, true, true, Severity::Medium),
            result(VulnerabilityType::ROBOT, false, true, Severity::Low),
            result(VulnerabilityType::GREASE, false, false, Severity::Info),
        ];

        formatter.display_vulnerability_results(&results);
        formatter.display_vulnerability_results(&[result(
            VulnerabilityType::FREAK,
            true,
            true,
            Severity::Medium,
        )]);
        let mut without_cve = result(VulnerabilityType::Heartbleed, true, false, Severity::Info);
        without_cve.cve = None;
        formatter.display_vulnerability_results(&[without_cve]);
    }

    #[test]
    fn display_results_handles_empty_and_hidden_inconclusive_summaries() {
        let mut args = crate::Args::default();
        args.output.warnings = Some("off".to_string());
        let formatter = ScannerFormatter::new(&args);

        formatter.display_vulnerability_results(&[]);
        formatter.display_vulnerability_results(&[result(
            VulnerabilityType::Heartbleed,
            false,
            true,
            Severity::High,
        )]);
        formatter.display_vulnerability_results(&[result(
            VulnerabilityType::Heartbleed,
            true,
            false,
            Severity::Critical,
        )]);
    }
}
