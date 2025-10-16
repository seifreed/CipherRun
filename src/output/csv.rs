// CSV Output Module

use crate::Result;
use crate::scanner::ScanResults;
use csv::Writer;

/// Generate CSV output from scan results
/// Produces multiple CSV tables: protocols, vulnerabilities, and summary
pub fn generate_csv(results: &ScanResults) -> Result<String> {
    let mut output = String::new();

    // Summary
    output.push_str("=== SCAN SUMMARY ===\n");
    output.push_str("Target,Scan Time (ms),Protocols Tested,Vulnerabilities Tested\n");
    output.push_str(&format!(
        "{},{},{},{}\n",
        results.target,
        results.scan_time_ms,
        results.protocols.len(),
        results.vulnerabilities.len()
    ));
    output.push('\n');

    // Protocols
    output.push_str("=== PROTOCOLS ===\n");
    output.push_str("Protocol,Supported,Deprecated\n");
    for protocol in &results.protocols {
        output.push_str(&format!(
            "{},{},{}\n",
            protocol.protocol,
            protocol.supported,
            protocol.protocol.is_deprecated()
        ));
    }
    output.push('\n');

    // Vulnerabilities
    output.push_str("=== VULNERABILITIES ===\n");
    output.push_str("Type,Vulnerable,Severity,CVE,Details\n");
    for vuln in &results.vulnerabilities {
        output.push_str(&format!(
            "{:?},{},{:?},{},{}\n",
            vuln.vuln_type,
            vuln.vulnerable,
            vuln.severity,
            vuln.cve.as_deref().unwrap_or("N/A"),
            vuln.details.replace(',', ";").replace('\n', " ")
        ));
    }
    output.push('\n');

    // HTTP Headers Issues (if available)
    if let Some(headers) = &results.http_headers {
        output.push_str("=== HTTP SECURITY HEADERS ===\n");
        output.push_str("Grade,Score\n");
        output.push_str(&format!("{:?},{}\n", headers.grade, headers.score));
        output.push('\n');

        if !headers.issues.is_empty() {
            output.push_str("=== HEADER ISSUES ===\n");
            output.push_str("Header,Type,Severity,Description,Recommendation\n");
            for issue in &headers.issues {
                output.push_str(&format!(
                    "{},{:?},{:?},{},{}\n",
                    issue.header_name,
                    issue.issue_type,
                    issue.severity,
                    issue.description.replace(',', ";"),
                    issue.recommendation.replace(',', ";")
                ));
            }
            output.push('\n');
        }
    }

    // Rating (if available)
    if let Some(rating) = &results.rating {
        output.push_str("=== SSL LABS RATING ===\n");
        output.push_str("Grade,Overall Score,Certificate Score,Protocol Score,Key Exchange Score,Cipher Strength Score\n");
        output.push_str(&format!(
            "{},{},{},{},{},{}\n",
            rating.grade,
            rating.score,
            rating.certificate_score,
            rating.protocol_score,
            rating.key_exchange_score,
            rating.cipher_strength_score
        ));
        output.push('\n');
    }

    // Client Simulations (if available)
    if let Some(clients) = &results.client_simulations {
        output.push_str("=== CLIENT COMPATIBILITY ===\n");
        output.push_str("Client,Success,Protocol,Cipher,Handshake Time (ms)\n");
        for client in clients {
            output.push_str(&format!(
                "{},{},{},{},{}\n",
                client.client_name,
                client.success,
                client
                    .protocol
                    .as_ref()
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| "N/A".to_string()),
                client.cipher.as_ref().unwrap_or(&"N/A".to_string()),
                client.handshake_time_ms.unwrap_or(0)
            ));
        }
        output.push('\n');
    }

    Ok(output)
}

/// Write CSV to file
pub fn write_csv_file(results: &ScanResults, path: &str) -> Result<()> {
    let csv = generate_csv(results)?;
    std::fs::write(path, csv)?;
    Ok(())
}

/// Generate CSV for vulnerabilities only (traditional format)
pub fn generate_vulnerabilities_csv(results: &ScanResults) -> Result<String> {
    let mut wtr = Writer::from_writer(vec![]);

    // Write header
    wtr.write_record(["Type", "Severity", "Vulnerable", "CVE", "Details"])?;

    // Write data
    for vuln in &results.vulnerabilities {
        wtr.write_record(&[
            format!("{:?}", vuln.vuln_type),
            format!("{:?}", vuln.severity),
            format!("{}", vuln.vulnerable),
            vuln.cve.as_deref().unwrap_or("N/A").to_string(),
            vuln.details.replace(',', ";"),
        ])?;
    }

    let data = wtr.into_inner()?;
    Ok(String::from_utf8(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let csv = generate_csv(&results).unwrap();
        assert!(csv.contains("SCAN SUMMARY"));
        assert!(csv.contains("example.com"));
    }

    #[test]
    fn test_vulnerabilities_csv() {
        let results = ScanResults::default();
        let csv = generate_vulnerabilities_csv(&results).unwrap();
        assert!(csv.contains("Type,Severity,Vulnerable,CVE,Details"));
    }
}
