// HTML Report Generator

use crate::Result;
use crate::scanner::ScanResults;
use handlebars::Handlebars;
use serde_json::json;

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CipherRun Security Scan Report - {{target}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-bottom: 10px; font-size: 2.5em; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; }
        .header h1 { color: white; }
        .grade-box { display: inline-block; padding: 20px 40px; font-size: 3em; font-weight: bold; border-radius: 8px; margin: 20px 0; }
        .grade-A-plus, .grade-A { background: #27ae60; color: white; }
        .grade-A-minus, .grade-B-plus, .grade-B { background: #3498db; color: white; }
        .grade-B-minus, .grade-C { background: #f39c12; color: white; }
        .grade-D, .grade-E, .grade-F { background: #e74c3c; color: white; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }
        .summary-card .value { font-size: 2em; font-weight: bold; color: #3498db; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        tr:hover { background: #f8f9fa; }
        .status-success { color: #27ae60; font-weight: bold; }
        .status-fail { color: #e74c3c; font-weight: bold; }
        .status-warn { color: #f39c12; font-weight: bold; }
        .severity-critical { background: #c0392b; color: white; padding: 4px 8px; border-radius: 4px; }
        .severity-high { background: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; }
        .severity-medium { background: #f39c12; color: white; padding: 4px 8px; border-radius: 4px; }
        .severity-low { background: #95a5a6; color: white; padding: 4px 8px; border-radius: 4px; }
        .score-bar { height: 30px; background: #ecf0f1; border-radius: 15px; overflow: hidden; margin: 10px 0; }
        .score-fill { height: 100%; background: linear-gradient(90deg, #e74c3c 0%, #f39c12 50%, #27ae60 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CipherRun Security Scan Report</h1>
            <div>Target: {{target}} | Scan Time: {{scan_time_ms}}ms | Generated: {{timestamp}}</div>
        </div>

        {{#if rating}}
        <section>
            <h2>Overall Security Rating</h2>
            <div style="text-align: center;">
                <div class="grade-box grade-{{rating.grade}}">{{rating.grade}}</div>
                <div class="score-bar">
                    <div class="score-fill" style="width: {{rating.score}}%">{{rating.score}}/100</div>
                </div>
            </div>
            <div class="summary-grid">
                <div class="summary-card"><h3>Certificate</h3><div class="value">{{rating.certificate_score}}/100</div></div>
                <div class="summary-card"><h3>Protocols</h3><div class="value">{{rating.protocol_score}}/100</div></div>
                <div class="summary-card"><h3>Key Exchange</h3><div class="value">{{rating.key_exchange_score}}/100</div></div>
                <div class="summary-card"><h3>Cipher Strength</h3><div class="value">{{rating.cipher_strength_score}}/100</div></div>
            </div>
        </section>
        {{/if}}

        <section>
            <h2>Supported Protocols</h2>
            <table>
                <thead><tr><th>Protocol</th><th>Status</th><th>Secure Renegotiation</th><th>Session Resumption (Caching)</th><th>Session Resumption (Tickets)</th></tr></thead>
                <tbody>
                {{#each protocols}}
                    <tr>
                        <td>{{protocol}}</td>
                        <td>{{#if supported}}<span class="status-success">Supported</span>{{else}}<span class="status-fail">Not Supported</span>{{/if}}</td>
                        <td>{{{secure_renegotiation_html}}}</td>
                        <td>{{{session_resumption_caching_html}}}</td>
                        <td>{{{session_resumption_tickets_html}}}</td>
                    </tr>
                {{/each}}
                </tbody>
            </table>
        </section>

        {{#if vulnerabilities}}
        <section>
            <h2>Vulnerabilities</h2>
            <table>
                <thead><tr><th>Vulnerability</th><th>Status</th><th>Severity</th><th>Details</th></tr></thead>
                <tbody>
                {{#each vulnerabilities}}
                    <tr>
                        <td>{{vuln_type}}</td>
                        <td>
                            {{#if vulnerable}}
                                <span class="status-fail">VULNERABLE</span>
                            {{else}}
                                {{#if inconclusive}}
                                    <span class="status-warn">INCONCLUSIVE</span>
                                {{else}}
                                    <span class="status-success">Not Vulnerable</span>
                                {{/if}}
                            {{/if}}
                        </td>
                        <td><span class="severity-{{severity}}">{{severity}}</span></td>
                        <td>{{details}}</td>
                    </tr>
                {{/each}}
                </tbody>
            </table>
        </section>
        {{/if}}

        <div class="footer">
            <p>Generated by CipherRun - A fast, modular TLS/SSL security scanner</p>
        </div>
    </div>
</body>
</html>"#;

/// Generate HTML report from scan results
pub fn generate_html_report(results: &ScanResults) -> Result<String> {
    let handlebars = Handlebars::new();
    // Default escape function handles HTML escaping for {{double-brace}} fields.
    // Fields needing raw HTML use {{{triple-brace}}} in the template.

    let data = json!({
        "target": results.target,
        "scan_time_ms": results.scan_time_ms,
        "timestamp": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        "rating": results.ssl_rating().map(|r| {
            let grade_str = format!("{}", r.grade);
            let grade_class = match grade_str.as_str() {
                "A+" => "A-plus",
                "A-" => "A-minus",
                "B+" => "B-plus",
                "B-" => "B-minus",
                other => other,
            };
            json!({
                "grade": grade_class,
                "score": r.score,
                "certificate_score": r.certificate_score,
                "protocol_score": r.protocol_score,
                "key_exchange_score": r.key_exchange_score,
                "cipher_strength_score": r.cipher_strength_score,
            })
        }),
        "protocols": results.protocols.iter().map(|p| json!({
            "protocol": format!("{}", p.protocol),
            "supported": p.supported,
            "secure_renegotiation_html": render_optional_protocol_status(
                p.supported,
                p.secure_renegotiation,
                "Supported",
                "Not supported",
            ),
            "session_resumption_caching_html": render_optional_protocol_status(
                p.supported,
                p.session_resumption_caching,
                "Yes",
                "No (IDs empty)",
            ),
            "session_resumption_tickets_html": render_optional_protocol_status(
                p.supported,
                p.session_resumption_tickets,
                "Yes",
                "No",
            ),
        })).collect::<Vec<_>>(),
        "vulnerabilities": results.vulnerabilities.iter().map(|v| json!({
            "vuln_type": format!("{:?}", v.vuln_type),
            "vulnerable": v.vulnerable,
            "inconclusive": v.inconclusive,
            "severity": format!("{:?}", v.severity).to_lowercase(),
            "details": v.details,
        })).collect::<Vec<_>>(),
    });

    let html = handlebars.render_template(HTML_TEMPLATE, &data)?;
    Ok(html)
}

fn render_optional_protocol_status(
    protocol_supported: bool,
    value: Option<bool>,
    true_label: &str,
    false_label: &str,
) -> String {
    match value {
        Some(true) => format!("<span class=\"status-success\">{}</span>", true_label),
        Some(false) => format!("<span class=\"status-fail\">{}</span>", false_label),
        None if protocol_supported => "<span class=\"status-warn\">Inconclusive</span>".to_string(),
        None => "-".to_string(),
    }
}

/// Write HTML report to file
pub fn write_html_file(results: &ScanResults, path: &str) -> Result<()> {
    let html = generate_html_report(results)?;
    std::fs::write(path, html)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rating::{Grade, RatingResult};
    use crate::scanner::RatingResults;
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

    #[test]
    fn test_html_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 5000,
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("CipherRun Security Scan Report"));
        assert!(html.contains("example.com:443"));
    }

    #[test]
    fn test_html_grade_class_formatting() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 10,
            rating: Some(RatingResults {
                ssl_rating: Some(RatingResult {
                    grade: Grade::APlus,
                    score: 95,
                    certificate_score: 95,
                    protocol_score: 95,
                    key_exchange_score: 95,
                    cipher_strength_score: 95,
                    warnings: Vec::new(),
                }),
            }),
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("grade-A-plus"));
    }

    #[test]
    fn test_html_includes_vulnerabilities() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: true,
                inconclusive: false,
                details: "Test detail".to_string(),
                cve: Some("CVE-2014-0160".to_string()),
                cwe: None,
                severity: Severity::High,
            }],
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("VULNERABLE"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("Test detail"));
    }

    #[test]
    fn test_html_protocol_none_is_inconclusive() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![crate::protocols::ProtocolTestResult {
                protocol: crate::protocols::Protocol::TLS12,
                supported: true,
                preferred: false,
                ciphers_count: 0,
                handshake_time_ms: None,
                heartbeat_enabled: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("Inconclusive"));
    }

    #[test]
    fn test_write_html_file_round_trip() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            ..Default::default()
        };
        let path = std::env::temp_dir().join("cipherrun-report.html");
        write_html_file(&results, path.to_str().unwrap()).expect("write should succeed");
        let contents = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(contents.contains("CipherRun Security Scan Report"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_html_omits_vulnerabilities_when_empty() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            vulnerabilities: Vec::new(),
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(!html.contains("<h2>Vulnerabilities</h2>"));
    }

    #[test]
    fn test_html_includes_protocol_section_even_when_empty() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            protocols: Vec::new(),
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("<h2>Supported Protocols</h2>"));
    }

    #[test]
    fn test_html_contains_head_and_body() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            ..Default::default()
        };
        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("<head>"));
        assert!(html.contains("<body>"));
    }
}
