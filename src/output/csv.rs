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

        // Advanced Header Analysis
        if let Some(hsts) = &headers.hsts_analysis {
            output.push_str("=== HSTS ANALYSIS ===\n");
            output.push_str("Enabled,Grade,Max-Age,IncludeSubDomains,Preload,Details\n");
            output.push_str(&format!(
                "{},{:?},{},{},{},{}\n",
                hsts.enabled,
                hsts.grade,
                hsts.max_age.unwrap_or(0),
                hsts.include_subdomains,
                hsts.preload,
                hsts.details.replace(',', ";")
            ));
            output.push('\n');
        }

        if let Some(cookies) = &headers.cookie_analysis {
            output.push_str("=== COOKIE SECURITY ===\n");
            output.push_str(
                "Total Cookies,Secure Count,HttpOnly Count,SameSite Count,Insecure Count,Grade\n",
            );
            output.push_str(&format!(
                "{},{},{},{},{},{:?}\n",
                cookies.cookies.len(),
                cookies.secure_count,
                cookies.httponly_count,
                cookies.samesite_count,
                cookies.insecure_count,
                cookies.grade
            ));
            output.push('\n');

            if !cookies.cookies.is_empty() {
                output.push_str("=== COOKIE DETAILS ===\n");
                output.push_str("Name,Secure,HttpOnly,SameSite,Domain,Path\n");
                for cookie in &cookies.cookies {
                    output.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        cookie.name,
                        cookie.secure,
                        cookie.httponly,
                        cookie.samesite.as_deref().unwrap_or("N/A"),
                        cookie.domain.as_deref().unwrap_or("N/A"),
                        cookie.path.as_deref().unwrap_or("N/A")
                    ));
                }
                output.push('\n');
            }
        }

        if let Some(datetime) = &headers.datetime_check {
            output.push_str("=== DATE/TIME CHECK ===\n");
            output.push_str("Server Date,Synchronized,Skew (seconds),Details\n");
            output.push_str(&format!(
                "{},{},{},{}\n",
                datetime.server_date.as_deref().unwrap_or("N/A"),
                datetime.synchronized,
                datetime.skew_seconds.unwrap_or(0),
                datetime.details.replace(',', ";")
            ));
            output.push('\n');
        }

        if let Some(banners) = &headers.banner_detection {
            output.push_str("=== SERVER BANNERS ===\n");
            output.push_str("Server,X-Powered-By,Application,Version Exposed,Grade\n");
            output.push_str(&format!(
                "{},{},{},{},{:?}\n",
                banners.server.as_deref().unwrap_or("N/A"),
                banners.powered_by.as_deref().unwrap_or("N/A"),
                banners.application.as_deref().unwrap_or("N/A"),
                banners.version_exposed,
                banners.grade
            ));
            output.push('\n');
        }

        if let Some(proxy) = &headers.reverse_proxy_detection
            && proxy.detected
        {
            output.push_str("=== REVERSE PROXY DETECTION ===\n");
            output
                .push_str("Detected,Type,Via Header,X-Forwarded-For,X-Real-IP,X-Forwarded-Proto\n");
            output.push_str(&format!(
                "{},{},{},{},{},{}\n",
                proxy.detected,
                proxy.proxy_type.as_deref().unwrap_or("N/A"),
                proxy.via_header.as_deref().unwrap_or("N/A"),
                proxy.x_forwarded_for,
                proxy.x_real_ip,
                proxy.x_forwarded_proto
            ));
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
