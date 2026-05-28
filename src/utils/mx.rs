// MX Record Testing - Scan all mail servers for a domain

use crate::Result;
use crate::application::ScanRequest;
use crate::rating::RatingCalculator;
use crate::scanner::{
    CertificateAnalysisResult, RatingResults, aggregation::ConservativeAggregator,
    inconsistency::SingleIpScanResult,
};
use crate::scanner::{ScanResults, Scanner};
use crate::utils::custom_resolvers::CustomResolver;
use crate::utils::network::canonical_target;
use crate::vulnerabilities::{VulnerabilityResult, merge_vulnerability_result};
use colored::Colorize;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
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
    resolvers: Vec<String>,
}

impl MxTester {
    pub fn new(domain: String) -> Self {
        Self::with_resolvers(domain, Vec::new())
    }

    pub fn with_resolvers(domain: String, resolvers: Vec<String>) -> Self {
        Self { domain, resolvers }
    }

    /// Query MX records for the domain
    pub async fn query_mx_records(&self) -> Result<Vec<MxRecord>> {
        println!(
            "\n{} MX records for {}...",
            "Querying".cyan().bold(),
            self.domain.yellow()
        );

        let mx_records = if self.resolvers.is_empty() {
            // Use dig or nslookup to get MX records
            let output = Command::new("dig")
                .args(["+short", "MX", &self.domain])
                .output();

            if let Ok(output) = output {
                self.parse_dig_output(&output.stdout)?
            } else {
                // Fallback to nslookup if dig is not available
                let output = Command::new("nslookup")
                    .args(["-type=MX", &self.domain])
                    .output()?;

                self.parse_nslookup_output(&output.stdout)?
            }
        } else {
            let resolver = CustomResolver::new(self.resolvers.clone())?;
            resolver
                .lookup_mx(&self.domain)
                .await?
                .into_iter()
                .map(|(priority, hostname)| MxRecord { priority, hostname })
                .collect()
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
            let mut parts = line.split_whitespace();
            let Some(priority_str) = parts.next() else {
                continue;
            };
            let Some(hostname_raw) = parts.next() else {
                continue;
            };
            let Ok(priority) = priority_str.parse::<u16>() else {
                continue;
            };

            let hostname = hostname_raw.trim_end_matches('.').to_string();
            records.push(MxRecord { priority, hostname });
        }

        Ok(records)
    }

    /// Parse nslookup output
    fn parse_nslookup_output(&self, output: &[u8]) -> Result<Vec<MxRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if line.to_ascii_lowercase().contains("mail exchanger") {
                // Format: "example.com    mail exchanger = 10 mx.example.com."
                let Some((_, right_side)) = line.split_once('=') else {
                    continue;
                };
                let mut mx_parts = right_side.split_whitespace();
                let Some(priority_str) = mx_parts.next() else {
                    continue;
                };
                let Some(hostname_raw) = mx_parts.next() else {
                    continue;
                };
                let Ok(priority) = priority_str.parse::<u16>() else {
                    continue;
                };

                let hostname = hostname_raw.trim_end_matches('.').to_string();
                records.push(MxRecord { priority, hostname });
            }
        }

        Ok(records)
    }

    /// Scan all MX records
    ///
    /// `base_request` is the domain scan request (built once by the caller from
    /// its own configuration); each MX host is scanned by cloning it and
    /// retargeting to `<hostname>:25`. `parallel`/`max_parallel` control the MX
    /// fan-out concurrency and are orchestration concerns, not part of the
    /// per-scan request.
    pub async fn scan_all_mx(
        &self,
        base_request: &ScanRequest,
        parallel: bool,
        max_parallel: usize,
    ) -> Result<Vec<(MxRecord, Result<ScanResults>)>> {
        let mx_records = self.query_mx_records().await?;

        println!("\n{}", "=".repeat(80).cyan());
        println!(
            "{} Scanning {} mail servers (port 25 - SMTP)",
            "Starting".cyan().bold(),
            mx_records.len()
        );
        println!("{}\n", "=".repeat(80).cyan());

        let results = if parallel {
            println!(
                "{} Running MX scans in parallel (max {} concurrent)\n",
                "[*]".cyan(),
                max_parallel.max(1)
            );
            self.scan_all_mx_parallel(&mx_records, base_request, max_parallel.max(1))
                .await?
        } else {
            self.scan_all_mx_serial(&mx_records, base_request).await?
        };

        Ok(results)
    }

    async fn scan_all_mx_serial(
        &self,
        mx_records: &[MxRecord],
        base_request: &ScanRequest,
    ) -> Result<Vec<(MxRecord, Result<ScanResults>)>> {
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

            let result = Self::scan_mx_record(base_request, record).await;
            Self::print_scan_result(&result);
            results.push((record.clone(), result));
            println!();
        }

        Ok(results)
    }

    async fn scan_all_mx_parallel(
        &self,
        mx_records: &[MxRecord],
        base_request: &ScanRequest,
        max_parallel: usize,
    ) -> Result<Vec<(MxRecord, Result<ScanResults>)>> {
        let mut completed = 0usize;

        let mut results =
            stream::iter(mx_records.iter().cloned().enumerate().map(|(idx, record)| {
                let request = base_request.clone();
                async move {
                    let result = Self::scan_mx_record(&request, &record).await;
                    (idx, record, result)
                }
            }))
            .buffer_unordered(max_parallel);

        let mut collected = Vec::with_capacity(mx_records.len());
        while let Some((idx, record, result)) = results.next().await {
            completed += 1;
            println!(
                "{} Completed MX {}/{}: {} (priority {})",
                "[+]".green(),
                completed,
                mx_records.len(),
                record.hostname.yellow(),
                record.priority
            );
            Self::print_scan_result(&result);
            println!();
            collected.push((idx, record, result));
        }

        collected.sort_by_key(|(idx, _, _)| *idx);
        Ok(collected
            .into_iter()
            .map(|(_, record, result)| (record, result))
            .collect())
    }

    async fn scan_mx_record(base_request: &ScanRequest, record: &MxRecord) -> Result<ScanResults> {
        let mut request = base_request.clone();
        request.target = Some(format!("{}:25", record.hostname));

        match Scanner::new(request) {
            Ok(scanner) => scanner.run().await,
            Err(e) => Err(e),
        }
    }

    fn print_scan_result(result: &Result<ScanResults>) {
        match result {
            Ok(scan_results) => {
                println!("  {} Scan completed", "✓".green());
                if let Some(rating) = scan_results.ssl_rating() {
                    println!("  {} SSL Labs Grade: {}", "→".blue(), rating.grade);
                }
            }
            Err(e) => {
                println!("  {} Scan failed: {}", "✗".red(), e);
            }
        }
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
                && let Some(rating) = scan_result.ssl_rating()
            {
                *grade_counts.entry(rating.grade.to_string()).or_insert(0) += 1;
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
                        .ssl_rating()
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

    /// Build a conservative aggregated scan result across all successful MX hosts.
    ///
    /// The aggregate is used for post-processing features such as compliance,
    /// policy evaluation, storage and non-JSON exports.
    pub fn aggregate_scan_results(
        &self,
        results: &[(MxRecord, Result<ScanResults>)],
    ) -> Result<ScanResults> {
        Self::aggregate_scan_results_for_domain(&self.domain, results)
    }

    pub fn aggregate_scan_results_for_domain(
        domain: &str,
        results: &[(MxRecord, Result<ScanResults>)],
    ) -> Result<ScanResults> {
        let successful_results: Vec<&ScanResults> = results
            .iter()
            .filter_map(|(_, result)| result.as_ref().ok())
            .collect();

        if successful_results.is_empty() {
            return Err(crate::error::TlsError::Other(format!(
                "All MX scans failed for domain: {}",
                domain
            )));
        }

        let mut per_backend_results = HashMap::new();
        for (index, scan_result) in successful_results.iter().enumerate() {
            let ip = synthetic_backend_ip(index);
            per_backend_results.insert(
                ip,
                SingleIpScanResult {
                    ip,
                    scan_result: (*scan_result).clone(),
                    scan_duration_ms: scan_result.scan_time_ms,
                    error: None,
                },
            );
        }

        let aggregated = ConservativeAggregator::new(per_backend_results, Vec::new()).aggregate();
        let certificate_chain = select_common_certificate_chain(&successful_results);
        let vulnerabilities = aggregate_vulnerabilities(results);
        let incomplete_coverage = results.iter().any(|(_, result)| result.is_err());

        let mut aggregate = ScanResults {
            target: canonical_target(domain, 25),
            scan_time_ms: successful_results
                .iter()
                .map(|result| result.scan_time_ms)
                .sum(),
            protocols: aggregated.protocols,
            ciphers: aggregated.ciphers,
            certificate_chain,
            vulnerabilities,
            ..Default::default()
        };

        if incomplete_coverage {
            aggregate.add_human_warning(
                "Incomplete MX coverage - at least one MX host failed during scanning",
            );
        }

        let certificate_validation = aggregate
            .certificate_chain
            .as_ref()
            .map(|cert| &cert.validation);
        aggregate.rating = Some(RatingResults {
            ssl_rating: Some(RatingCalculator::calculate(
                &aggregate.protocols,
                &aggregate.ciphers,
                certificate_validation,
                &aggregate.vulnerabilities,
            )),
        });

        Ok(aggregate)
    }
}

fn synthetic_backend_ip(index: usize) -> IpAddr {
    let high = ((index >> 16) & 0xffff) as u16;
    let low = ((index & 0xffff) as u16).saturating_add(1);
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, high, low))
}

fn select_common_certificate_chain(results: &[&ScanResults]) -> Option<CertificateAnalysisResult> {
    let mut chains: HashMap<String, (usize, CertificateAnalysisResult)> = HashMap::new();

    for result in results {
        let Some(chain) = result.certificate_chain.as_ref() else {
            continue;
        };
        let signature = certificate_chain_signature(chain);
        let entry = chains
            .entry(signature)
            .or_insert_with(|| (0, chain.clone()));
        entry.0 += 1;
    }

    chains
        .into_iter()
        .max_by_key(|(_, (count, _))| *count)
        .map(|(_, (_, chain))| chain)
}

fn certificate_chain_signature(chain: &CertificateAnalysisResult) -> String {
    if chain.chain.certificates.is_empty() {
        return "<empty>".to_string();
    }

    chain
        .chain
        .certificates
        .iter()
        .map(|certificate| {
            if let Some(fingerprint) = certificate.fingerprint_sha256.as_ref() {
                return format!("fp:{fingerprint}");
            }

            if !certificate.der_bytes.is_empty() {
                return format!("der:{}", hex::encode(&certificate.der_bytes));
            }

            format!(
                "subject={};issuer={};serial={};not_before={};not_after={}",
                certificate.subject,
                certificate.issuer,
                certificate.serial_number,
                certificate.not_before,
                certificate.not_after
            )
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

fn aggregate_vulnerabilities(
    results: &[(MxRecord, Result<ScanResults>)],
) -> Vec<VulnerabilityResult> {
    let mut aggregated: Vec<VulnerabilityResult> = Vec::new();
    let incomplete_coverage = results.iter().any(|(_, result)| result.is_err());

    for (_, result) in results {
        let Ok(scan_result) = result else {
            continue;
        };

        for vulnerability in &scan_result.vulnerabilities {
            if let Some(existing) = aggregated
                .iter_mut()
                .find(|item| item.vuln_type == vulnerability.vuln_type)
            {
                merge_vulnerability_result(existing, vulnerability);
            } else {
                aggregated.push(vulnerability.clone());
            }
        }
    }

    if incomplete_coverage {
        for vulnerability in &mut aggregated {
            vulnerability.inconclusive = true;
            if !vulnerability.details.contains("incomplete MX coverage") {
                vulnerability.details = format!(
                    "{}; incomplete MX coverage - at least one MX host failed during scanning",
                    vulnerability.details
                );
            }
        }
    }

    aggregated.sort_by_key(|vulnerability| vulnerability.vuln_type.sort_key());
    aggregated
}

#[cfg(test)]
#[path = "mx_tests.rs"]
mod tests;
