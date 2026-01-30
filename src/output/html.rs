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
        .grade-A-minus, .grade-B { background: #3498db; color: white; }
        .grade-C { background: #f39c12; color: white; }
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
                        <td>
                            {{#if secure_renegotiation}}
                                <span class="status-success">Supported</span>
                            {{else}}
                                {{#if supported}}<span class="status-fail">Not supported</span>{{else}}-{{/if}}
                            {{/if}}
                        </td>
                        <td>
                            {{#if session_resumption_caching}}
                                <span class="status-success">Yes</span>
                            {{else}}
                                {{#if supported}}<span class="status-fail">No (IDs empty)</span>{{else}}-{{/if}}
                            {{/if}}
                        </td>
                        <td>
                            {{#if session_resumption_tickets}}
                                <span class="status-success">Yes</span>
                            {{else}}
                                {{#if supported}}<span class="status-fail">No</span>{{else}}-{{/if}}
                            {{/if}}
                        </td>
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
                        <td>{{#if vulnerable}}<span class="status-fail">VULNERABLE</span>{{else}}<span class="status-success">Not Vulnerable</span>{{/if}}</td>
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
    let mut handlebars = Handlebars::new();
    handlebars.register_escape_fn(handlebars::no_escape);

    let data = json!({
        "target": results.target,
        "scan_time_ms": results.scan_time_ms,
        "timestamp": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        "rating": results.ssl_rating().map(|r| json!({
            "grade": format!("{}", r.grade).replace("+", "-plus").replace("-", "-minus"),
            "score": r.score,
            "certificate_score": r.certificate_score,
            "protocol_score": r.protocol_score,
            "key_exchange_score": r.key_exchange_score,
            "cipher_strength_score": r.cipher_strength_score,
        })),
        "protocols": results.protocols.iter().map(|p| json!({
            "protocol": format!("{}", p.protocol),
            "supported": p.supported,
        })).collect::<Vec<_>>(),
        "vulnerabilities": results.vulnerabilities.iter().map(|v| json!({
            "vuln_type": format!("{:?}", v.vuln_type),
            "vulnerable": v.vulnerable,
            "severity": format!("{:?}", v.severity).to_lowercase(),
            "details": v.details,
        })).collect::<Vec<_>>(),
    });

    let html = handlebars.render_template(HTML_TEMPLATE, &data)?;
    Ok(html)
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
}
