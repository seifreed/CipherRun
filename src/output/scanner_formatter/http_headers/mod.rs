mod advanced;

use super::{ScannerFormatter, format_http_grade, format_http_issue_icon, format_http_status};
use crate::http::tester::HeaderAnalysisResult;
use colored::*;
use std::collections::HashMap;

impl<'a> ScannerFormatter<'a> {
    pub fn display_http_headers_results(&self, result: &HeaderAnalysisResult) {
        println!("\n{}", "HTTP Security Headers:".cyan().bold());
        println!("{}", "=".repeat(50));

        self.display_http_response_metadata(result);

        let grade_colored = format_http_grade(&result.grade);
        println!("  {}", grade_colored);
        println!("  Score: {}/100", result.score);
        println!("  Total Issues: {}", result.issues.len());

        if !result.issues.is_empty() {
            self.display_http_issues(result);
        } else {
            println!(
                "\n{}",
                "  Y All security headers properly configured!"
                    .green()
                    .bold()
            );
        }

        self.display_advanced_header_analysis(result);
    }

    fn display_http_response_metadata(&self, result: &HeaderAnalysisResult) {
        if let Some(status_code) = result.http_status_code {
            println!("  HTTP Status: {}", format_http_status(status_code));
        }

        if let Some(ref redirect_location) = result.redirect_location {
            println!("  Redirect To: {}", redirect_location.yellow());
        }

        if let Some(ref server) = result.server_hostname {
            println!("  Server:      {}", server.cyan());
        }

        if result.http_status_code.is_some()
            || result.redirect_location.is_some()
            || result.server_hostname.is_some()
        {
            println!();
        }
    }

    fn display_http_issues(&self, result: &HeaderAnalysisResult) {
        use crate::http::headers::IssueSeverity;

        println!("\n{}", "  Issues:".yellow());

        let mut by_severity: HashMap<IssueSeverity, Vec<_>> = HashMap::new();
        for issue in &result.issues {
            by_severity.entry(issue.severity).or_default().push(issue);
        }

        for severity in [
            IssueSeverity::Critical,
            IssueSeverity::High,
            IssueSeverity::Medium,
            IssueSeverity::Low,
            IssueSeverity::Info,
        ] {
            if let Some(issues) = by_severity.get(&severity) {
                for issue in issues {
                    let issue_icon = format_http_issue_icon(&issue.issue_type);

                    println!(
                        "\n    {} {} - {}",
                        issue_icon,
                        issue.header_name.cyan().bold(),
                        issue.severity.colored_display()
                    );
                    println!("      {}", issue.description);
                    println!("      Recommendation: {}", issue.recommendation.green());
                }
            }
        }
    }
}
