use super::super::{IntoleranceTestResult, ScannerFormatter, build_intolerance_checks};
use colored::Colorize;
impl<'a> ScannerFormatter<'a> {
    pub fn display_intolerance_results(&self, results: &IntoleranceTestResult) {
        self.print_section("TLS Intolerance Tests:", 50);

        let checks = build_intolerance_checks(results);
        let issues_found = checks.iter().filter(|c| c.is_intolerant).count();
        let inconclusive_count = checks.iter().filter(|c| c.inconclusive).count();

        for check in &checks {
            check.display(&results.details);
        }

        println!("\n{}", self.divider(50));
        if issues_found == 0 && inconclusive_count == 0 {
            println!("{}", "Y No TLS intolerance issues detected!".green().bold());
        } else if issues_found == 0 {
            println!(
                "{} {} TLS intolerance check(s) inconclusive",
                "?".yellow().bold(),
                inconclusive_count.to_string().yellow().bold()
            );
        } else {
            println!(
                "{} {} intolerance issue(s) detected",
                "!".yellow().bold(),
                issues_found.to_string().yellow().bold()
            );
            println!("  These issues may cause connectivity problems with some clients");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;
    use std::collections::HashMap;

    fn result(extension_intolerance: bool, inconclusive: bool) -> IntoleranceTestResult {
        IntoleranceTestResult {
            extension_intolerance,
            version_intolerance: false,
            long_handshake_intolerance: false,
            incorrect_sni_alerts: false,
            uses_common_dh_primes: false,
            inconclusive,
            inconclusive_checks: if inconclusive {
                vec!["extension_intolerance".to_string()]
            } else {
                Vec::new()
            },
            details: HashMap::from([(
                "extension_intolerance".to_string(),
                "synthetic diagnostic detail".to_string(),
            )]),
        }
    }

    #[test]
    fn display_intolerance_results_handles_clean_inconclusive_and_issue_outcomes() {
        colored::control::set_override(false);
        let args = Args::default();
        let formatter = ScannerFormatter::new(&args);

        formatter.display_intolerance_results(&result(false, false));
        formatter.display_intolerance_results(&result(false, true));
        formatter.display_intolerance_results(&result(true, false));
    }
}
