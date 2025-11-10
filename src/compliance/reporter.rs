// Compliance reporter - Generates reports in various formats

use crate::compliance::{ComplianceReport, ComplianceStatus, RequirementStatus, Severity};
use anyhow::Result;
use colored::*;

/// Reporter for generating compliance reports in various formats
pub struct Reporter;

impl Reporter {
    /// Generate a terminal-friendly report
    pub fn to_terminal(report: &ComplianceReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n{}\n",
            "=".repeat(70).cyan()
        ));
        output.push_str(&format!(
            "Compliance Report: {}\n",
            report.framework.name.cyan().bold()
        ));
        output.push_str(&format!(
            "{}\n",
            "=".repeat(70).cyan()
        ));

        // Metadata
        output.push_str(&format!("Framework:    {} v{}\n", report.framework.name, report.framework.version));
        output.push_str(&format!("Organization: {}\n", report.framework.organization));
        output.push_str(&format!("Target:       {}\n", report.target.green()));
        output.push_str(&format!("Scan Time:    {}\n", report.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC")));

        // Overall status
        let status_str = match report.overall_status {
            ComplianceStatus::Pass => "PASS".green().bold(),
            ComplianceStatus::Fail => "FAIL".red().bold(),
            ComplianceStatus::Warning => "WARNING".yellow().bold(),
        };
        output.push_str(&format!("Overall Status: {}\n", status_str));

        // Summary
        output.push_str(&format!("\n{}\n", "Summary:".cyan().bold()));
        output.push_str(&format!("  Total Requirements: {}\n", report.summary.total));
        output.push_str(&format!("  {} Passed:  {}\n", "✓".green(), report.summary.passed));
        output.push_str(&format!("  {} Failed:  {}\n", "✗".red(), report.summary.failed));
        output.push_str(&format!("  {} Warnings: {}\n", "⚠".yellow(), report.summary.warnings));
        if report.summary.not_applicable > 0 {
            output.push_str(&format!("  - N/A:      {}\n", report.summary.not_applicable));
        }

        // Failed requirements
        let failed_reqs = report.failed_requirements();
        if !failed_reqs.is_empty() {
            output.push_str(&format!("\n{}\n", "Failed Requirements:".red().bold()));
            output.push_str(&format!("{}\n", "-".repeat(70)));

            for req in failed_reqs {
                let severity_str = match req.severity {
                    Severity::Critical => "CRITICAL".red().bold(),
                    Severity::High => "HIGH".red(),
                    Severity::Medium => "MEDIUM".yellow(),
                    Severity::Low => "LOW".normal(),
                    Severity::Info => "INFO".cyan(),
                };

                output.push_str(&format!("\n[{}] {} - {}\n", severity_str, req.requirement_id.yellow(), req.name));
                output.push_str(&format!("  Category:    {}\n", req.category));
                output.push_str(&format!("  Status:      {}\n", "FAIL".red()));

                for violation in &req.violations {
                    output.push_str(&format!("\n  Violation:   {}\n", violation.violation_type.red()));
                    output.push_str(&format!("  Description: {}\n", violation.description));
                    output.push_str(&format!("  Evidence:    {}\n", violation.evidence));
                }

                if !req.remediation.is_empty() {
                    output.push_str("\n  Remediation:\n");
                    for line in req.remediation.lines() {
                        output.push_str(&format!("    {}\n", line.green()));
                    }
                }
            }
        }

        // Warning requirements
        let warning_reqs = report.warning_requirements();
        if !warning_reqs.is_empty() {
            output.push_str(&format!("\n{}\n", "Requirements with Warnings:".yellow().bold()));
            output.push_str(&format!("{}\n", "-".repeat(70)));

            for req in warning_reqs {
                output.push_str(&format!("\n[{}] {} - {}\n", "WARNING".yellow(), req.requirement_id.yellow(), req.name));
                output.push_str(&format!("  Category: {}\n", req.category));

                for violation in &req.violations {
                    output.push_str(&format!("  Issue:    {}\n", violation.description.yellow()));
                    output.push_str(&format!("  Evidence: {}\n", violation.evidence));
                }
            }
        }

        // Passed requirements summary
        if report.summary.passed > 0 {
            output.push_str(&format!("\n{}\n", "Passed Requirements:".green().bold()));
            let passed_reqs: Vec<_> = report
                .requirements
                .iter()
                .filter(|r| r.status == RequirementStatus::Pass)
                .collect();

            for req in passed_reqs.iter().take(5) {
                output.push_str(&format!("  {} {} - {}\n", "✓".green(), req.requirement_id, req.name));
            }

            if passed_reqs.len() > 5 {
                output.push_str(&format!("  ... and {} more\n", passed_reqs.len() - 5));
            }
        }

        output.push_str(&format!("\n{}\n", "=".repeat(70).cyan()));

        output
    }

    /// Generate JSON report
    pub fn to_json(report: &ComplianceReport, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(report)?)
        } else {
            Ok(serde_json::to_string(report)?)
        }
    }

    /// Generate CSV report
    pub fn to_csv(report: &ComplianceReport) -> Result<String> {
        let mut csv = String::new();

        // Header
        csv.push_str("Requirement ID,Name,Category,Severity,Status,Violations,Evidence\n");

        // Data rows
        for req in &report.requirements {
            let violations_summary = if req.violations.is_empty() {
                "None".to_string()
            } else {
                req.violations
                    .iter()
                    .map(|v| v.violation_type.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            };

            let evidence_summary = req
                .violations
                .iter()
                .map(|v| v.evidence.clone())
                .collect::<Vec<_>>()
                .join("; ");

            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",{:?},{},{},\"{}\"\n",
                req.requirement_id.replace('"', "\"\""),
                req.name.replace('"', "\"\""),
                req.category.replace('"', "\"\""),
                req.severity,
                req.status,
                violations_summary.replace('"', "\"\""),
                evidence_summary.replace('"', "\"\"")
            ));
        }

        Ok(csv)
    }

    /// Generate HTML report
    pub fn to_html(report: &ComplianceReport) -> Result<String> {
        let mut html = String::new();

        // HTML header
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str(&format!(
            "<title>Compliance Report: {}</title>\n",
            report.framework.name
        ));
        html.push_str("<style>\n");
        html.push_str(include_str!("../../data/compliance_report.css"));
        html.push_str("</style>\n");
        html.push_str("</head>\n<body>\n");

        // Report header
        html.push_str("<div class=\"container\">\n");
        html.push_str(&format!(
            "<h1>Compliance Report: {}</h1>\n",
            report.framework.name
        ));

        // Metadata
        html.push_str("<div class=\"metadata\">\n");
        html.push_str(&format!("<p><strong>Framework:</strong> {} v{}</p>\n", report.framework.name, report.framework.version));
        html.push_str(&format!("<p><strong>Organization:</strong> {}</p>\n", report.framework.organization));
        html.push_str(&format!("<p><strong>Target:</strong> {}</p>\n", report.target));
        html.push_str(&format!("<p><strong>Scan Time:</strong> {}</p>\n", report.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC")));

        let status_class = match report.overall_status {
            ComplianceStatus::Pass => "status-pass",
            ComplianceStatus::Fail => "status-fail",
            ComplianceStatus::Warning => "status-warning",
        };
        html.push_str(&format!(
            "<p><strong>Overall Status:</strong> <span class=\"{}\">{}</span></p>\n",
            status_class, report.overall_status
        ));
        html.push_str("</div>\n");

        // Summary
        html.push_str("<div class=\"summary\">\n");
        html.push_str("<h2>Summary</h2>\n");
        html.push_str("<table>\n");
        html.push_str(&format!("<tr><th>Total Requirements</th><td>{}</td></tr>\n", report.summary.total));
        html.push_str(&format!("<tr><th>Passed</th><td class=\"status-pass\">{}</td></tr>\n", report.summary.passed));
        html.push_str(&format!("<tr><th>Failed</th><td class=\"status-fail\">{}</td></tr>\n", report.summary.failed));
        html.push_str(&format!("<tr><th>Warnings</th><td class=\"status-warning\">{}</td></tr>\n", report.summary.warnings));
        html.push_str("</table>\n");
        html.push_str("</div>\n");

        // Requirements
        html.push_str("<h2>Requirements</h2>\n");
        html.push_str("<table class=\"requirements\">\n");
        html.push_str("<thead>\n");
        html.push_str("<tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Status</th><th>Violations</th></tr>\n");
        html.push_str("</thead>\n");
        html.push_str("<tbody>\n");

        for req in &report.requirements {
            let status_class = match req.status {
                RequirementStatus::Pass => "status-pass",
                RequirementStatus::Fail => "status-fail",
                RequirementStatus::Warning => "status-warning",
                RequirementStatus::NotApplicable => "status-na",
            };

            html.push_str("<tr>\n");
            html.push_str(&format!("<td>{}</td>\n", req.requirement_id));
            html.push_str(&format!("<td>{}</td>\n", req.name));
            html.push_str(&format!("<td>{}</td>\n", req.category));
            html.push_str(&format!("<td>{:?}</td>\n", req.severity));
            html.push_str(&format!("<td class=\"{}\">{}</td>\n", status_class, req.status));
            html.push_str("<td>\n");

            if req.violations.is_empty() {
                html.push_str("None");
            } else {
                html.push_str("<ul>\n");
                for violation in &req.violations {
                    html.push_str(&format!(
                        "<li><strong>{}:</strong> {} ({})</li>\n",
                        violation.violation_type, violation.description, violation.evidence
                    ));
                }
                html.push_str("</ul>\n");
            }

            html.push_str("</td>\n");
            html.push_str("</tr>\n");
        }

        html.push_str("</tbody>\n");
        html.push_str("</table>\n");
        html.push_str("</div>\n");
        html.push_str("</body>\n</html>\n");

        Ok(html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::{ComplianceFramework, ComplianceReport};

    #[test]
    fn test_to_json() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![],
        };

        let mut report = ComplianceReport::new(&framework, "test.com:443".to_string());
        report.finalize();

        let json = Reporter::to_json(&report, false).unwrap();
        assert!(json.contains("test.com:443"));
        assert!(json.contains("Test Framework"));
    }

    #[test]
    fn test_to_csv() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![],
        };

        let mut report = ComplianceReport::new(&framework, "test.com:443".to_string());
        report.finalize();

        let csv = Reporter::to_csv(&report).unwrap();
        assert!(csv.contains("Requirement ID,Name,Category"));
    }
}
