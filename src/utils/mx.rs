// MX Record Testing - Scan all mail servers for a domain

use crate::Args;
use crate::Result;
use crate::scanner::{ScanResults, Scanner};
use colored::*;
use std::process::Command;
use std::str;

/// MX record information
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: u16,
    pub hostname: String,
}

/// MX Record tester for mail domains
pub struct MxTester {
    domain: String,
}

impl MxTester {
    pub fn new(domain: String) -> Self {
        Self { domain }
    }

    /// Query MX records for the domain
    pub fn query_mx_records(&self) -> Result<Vec<MxRecord>> {
        println!(
            "\n{} MX records for {}...",
            "Querying".cyan().bold(),
            self.domain.yellow()
        );

        // Use dig or nslookup to get MX records
        let output = Command::new("dig")
            .args(["+short", "MX", &self.domain])
            .output();

        let mx_records = if let Ok(output) = output {
            self.parse_dig_output(&output.stdout)?
        } else {
            // Fallback to nslookup if dig is not available
            let output = Command::new("nslookup")
                .args(["-type=MX", &self.domain])
                .output()?;

            self.parse_nslookup_output(&output.stdout)?
        };

        if mx_records.is_empty() {
            return Err(crate::error::TlsError::Other(format!(
                "No MX records found for domain: {}",
                self.domain
            )));
        }

        // Sort by priority (lowest first)
        let mut sorted_records = mx_records;
        sorted_records.sort_by_key(|r| r.priority);

        println!(
            "\n{} Found {} MX record(s):",
            "✓".green().bold(),
            sorted_records.len()
        );
        for record in &sorted_records {
            println!(
                "  Priority: {:<3} | Host: {}",
                record.priority.to_string().cyan(),
                record.hostname.yellow()
            );
        }

        Ok(sorted_records)
    }

    /// Parse dig output
    fn parse_dig_output(&self, output: &[u8]) -> Result<Vec<MxRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(priority) = parts[0].parse::<u16>()
            {
                let hostname = parts[1].trim_end_matches('.').to_string();
                records.push(MxRecord { priority, hostname });
            }
        }

        Ok(records)
    }

    /// Parse nslookup output
    fn parse_nslookup_output(&self, output: &[u8]) -> Result<Vec<MxRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if line.contains("mail exchanger") {
                // Format: "example.com    mail exchanger = 10 mx.example.com."
                let parts: Vec<&str> = line.split('=').collect();
                if parts.len() >= 2 {
                    let right_side = parts[1].trim();
                    let mx_parts: Vec<&str> = right_side.split_whitespace().collect();
                    if mx_parts.len() >= 2
                        && let Ok(priority) = mx_parts[0].parse::<u16>()
                    {
                        let hostname = mx_parts[1].trim_end_matches('.').to_string();
                        records.push(MxRecord { priority, hostname });
                    }
                }
            }
        }

        Ok(records)
    }

    /// Scan all MX records
    pub async fn scan_all_mx(&self, args: Args) -> Result<Vec<(MxRecord, Result<ScanResults>)>> {
        let mx_records = self.query_mx_records()?;

        println!("\n{}", "=".repeat(80).cyan());
        println!(
            "{} Scanning {} mail servers (port 25 - SMTP)",
            "Starting".cyan().bold(),
            mx_records.len()
        );
        println!("{}\n", "=".repeat(80).cyan());

        let mut results = Vec::new();

        for (idx, record) in mx_records.iter().enumerate() {
            println!(
                "{} Scanning MX {}/{}: {} (priority {})",
                "[+]".green(),
                idx + 1,
                mx_records.len(),
                record.hostname.yellow(),
                record.priority
            );

            // Create modified args for this MX host
            let mut mx_args = args.clone();
            mx_args.target = Some(format!("{}:25", record.hostname));
            mx_args.quiet = true;

            // Create scanner and run
            let result = match Scanner::new(mx_args.clone()) {
                Ok(mut scanner) => scanner.run().await,
                Err(e) => Err(e),
            };

            match &result {
                Ok(scan_results) => {
                    println!("  {} Scan completed", "✓".green());
                    if let Some(rating) = &scan_results.rating {
                        println!("  {} SSL Labs Grade: {}", "→".blue(), rating.grade);
                    }
                }
                Err(e) => {
                    println!("  {} Scan failed: {}", "✗".red(), e);
                }
            }

            results.push((record.clone(), result));
            println!();
        }

        Ok(results)
    }

    /// Generate MX scan summary
    pub fn generate_mx_summary(results: &[(MxRecord, Result<ScanResults>)]) -> String {
        let mut summary = String::new();

        summary.push_str(&format!("\n{}\n", "=".repeat(80)));
        summary.push_str(&format!("{}\n", "MX RECORDS SCAN SUMMARY".cyan().bold()));
        summary.push_str(&format!("{}\n\n", "=".repeat(80)));

        let total = results.len();
        let successful = results.iter().filter(|(_, r)| r.is_ok()).count();
        let failed = total - successful;

        summary.push_str(&format!(
            "{}: {} | {}: {} | {}: {}\n\n",
            "Total MX Servers".bold(),
            total,
            "Successful".green().bold(),
            successful,
            "Failed".red().bold(),
            failed
        ));

        // Grade distribution
        let mut grade_counts = std::collections::HashMap::new();
        for (_, result) in results {
            if let Ok(scan_result) = result
                && let Some(rating) = &scan_result.rating
            {
                *grade_counts.entry(format!("{}", rating.grade)).or_insert(0) += 1;
            }
        }

        if !grade_counts.is_empty() {
            summary.push_str(&format!("{}:\n", "SSL Labs Grade Distribution".bold()));
            let mut grades: Vec<_> = grade_counts.iter().collect();
            grades.sort_by(|a, b| b.1.cmp(a.1));
            for (grade, count) in grades {
                summary.push_str(&format!("  {}: {}\n", grade, count));
            }
            summary.push('\n');
        }

        // Individual results
        summary.push_str(&format!("{}:\n", "Individual MX Server Results".bold()));
        summary.push_str(&format!("{}\n", "-".repeat(80)));

        for (mx_record, result) in results {
            match result {
                Ok(scan_result) => {
                    let grade = scan_result
                        .rating
                        .as_ref()
                        .map(|r| format!("{}", r.grade))
                        .unwrap_or_else(|| "N/A".to_string());

                    let cert_status = scan_result
                        .certificate_chain
                        .as_ref()
                        .map(|c| {
                            if c.validation.valid {
                                "✓".green()
                            } else {
                                "✗".red()
                            }
                        })
                        .unwrap_or_else(|| "?".yellow());

                    let vuln_count = scan_result
                        .vulnerabilities
                        .iter()
                        .filter(|v| v.vulnerable)
                        .count();

                    summary.push_str(&format!(
                        "Priority {:<3} | {:<40} | Grade: {:<4} | Cert: {} | Vulns: {}\n",
                        mx_record.priority.to_string().cyan(),
                        mx_record.hostname.green(),
                        grade,
                        cert_status,
                        if vuln_count > 0 {
                            vuln_count.to_string().red()
                        } else {
                            vuln_count.to_string().green()
                        }
                    ));
                }
                Err(e) => {
                    summary.push_str(&format!(
                        "Priority {:<3} | {:<40} | {}: {}\n",
                        mx_record.priority.to_string().cyan(),
                        mx_record.hostname.red(),
                        "ERROR".red().bold(),
                        e
                    ));
                }
            }
        }

        summary.push_str(&format!("{}\n", "=".repeat(80)));

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mx_record_creation() {
        let mx = MxRecord {
            priority: 10,
            hostname: "mx.example.com".to_string(),
        };

        assert_eq!(mx.priority, 10);
        assert_eq!(mx.hostname, "mx.example.com");
    }

    #[test]
    fn test_parse_dig_output() {
        let tester = MxTester::new("example.com".to_string());
        let output = b"10 mx1.example.com.\n20 mx2.example.com.\n";

        let records = tester.parse_dig_output(output).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].priority, 10);
        assert_eq!(records[0].hostname, "mx1.example.com");
    }
}
