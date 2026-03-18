use super::super::{
    IntoleranceTestResult, ScannerFormatter, build_intolerance_checks, print_section_header,
};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn display_intolerance_results(&self, results: &IntoleranceTestResult) {
        print_section_header("TLS Intolerance Tests:");

        let checks = build_intolerance_checks(results);
        let issues_found = checks.iter().filter(|c| c.is_intolerant).count();

        for check in &checks {
            check.display(&results.details);
        }

        println!("\n{}", "=".repeat(50));
        if issues_found == 0 {
            println!("{}", "Y No TLS intolerance issues detected!".green().bold());
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
