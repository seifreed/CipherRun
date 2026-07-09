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
        .grade-D, .grade-E, .grade-F, .grade-T, .grade-M { background: #e74c3c; color: white; }
        .grade-Unverified { background: #95a5a6; color: white; font-size: 1.5em; }
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
        .severity-info { background: #3498db; color: white; padding: 4px 8px; border-radius: 4px; }
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
                <div class="grade-box grade-{{rating.grade_class}}">{{rating.grade}}</div>
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
                        <td>{{#if supported}}<span class="status-success">Supported</span>{{else}}{{#if inconclusive}}<span class="status-warn">Inconclusive</span>{{else}}<span class="status-fail">Not Supported</span>{{/if}}{{/if}}</td>
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

        {{#if certificate_chain}}
        <section>
            <h2>Certificate</h2>
            <table>
                <tbody>
                    <tr><th>Subject</th><td>{{certificate_chain.subject}}</td></tr>
                    <tr><th>Issuer</th><td>{{certificate_chain.issuer}}</td></tr>
                    <tr><th>Serial</th><td>{{certificate_chain.serial_number}}</td></tr>
                    <tr><th>Valid From</th><td>{{certificate_chain.valid_from}}</td></tr>
                    <tr><th>Valid To</th><td>{{certificate_chain.valid_to}}</td></tr>
                    <tr><th>Expires</th><td>{{certificate_chain.expires}}</td></tr>
                    <tr><th>Certificate Authority</th><td>{{certificate_chain.is_ca}}</td></tr>
                    <tr><th>Signature Algorithm</th><td>{{certificate_chain.signature_algorithm}}</td></tr>
                    <tr><th>Public Key</th><td>{{certificate_chain.public_key_algorithm}} {{certificate_chain.public_key_size}}</td></tr>
                    <tr><th>RSA Exponent</th><td>{{certificate_chain.rsa_exponent}}</td></tr>
                    <tr><th>SANs</th><td>{{certificate_chain.sans}}</td></tr>
                    <tr><th>Fingerprint SHA256</th><td>{{certificate_chain.fingerprint_sha256}}</td></tr>
                    <tr><th>Certificate Transparency</th><td>{{certificate_chain.certificate_transparency}}</td></tr>
                    <tr><th>Validation</th><td>Valid: {{certificate_chain.validation_valid}} | Hostname Match: {{certificate_chain.validation_hostname_match}} | Trust Chain: {{certificate_chain.validation_trust_chain_valid}} | Not Expired: {{certificate_chain.validation_not_expired}}</td></tr>
                </tbody>
            </table>
        </section>
        {{/if}}

        {{#if revocation}}
        <section>
            <h2>Revocation</h2>
            <table>
                <tbody>
                    <tr><th>Status</th><td>{{revocation.status}}</td></tr>
                    <tr><th>Method</th><td>{{revocation.method}}</td></tr>
                    <tr><th>Details</th><td>{{revocation.details}}</td></tr>
                    <tr><th>OCSP Stapling</th><td>{{revocation.ocsp_stapling}}</td></tr>
                    <tr><th>Must Staple</th><td>{{revocation.must_staple}}</td></tr>
                    <tr><th>Stapling Supported</th><td>{{revocation.ocsp_stapling_supported}}</td></tr>
                    <tr><th>Stapled Response Present</th><td>{{revocation.ocsp_stapling_present}}</td></tr>
                    <tr><th>Stapled Response Valid</th><td>{{revocation.ocsp_stapling_valid}}</td></tr>
                    <tr><th>Stapling Details</th><td>{{revocation.ocsp_stapling_details}}</td></tr>
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
                "grade": grade_str,
                "grade_class": grade_class,
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
            "inconclusive": p.inconclusive,
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
        "certificate_chain": results.certificate_chain.as_ref().and_then(|cert| {
            cert.chain.leaf().map(|leaf| json!({
                "subject": leaf.subject,
                "issuer": leaf.issuer,
                "serial_number": leaf.serial_number,
                "valid_from": leaf.not_before,
                "valid_to": leaf.not_after,
                "expires": leaf.expiry_countdown.as_deref().unwrap_or("N/A"),
                "is_ca": if leaf.is_ca { "Yes" } else { "No" },
                "signature_algorithm": leaf.signature_algorithm,
                "public_key_algorithm": leaf.public_key_algorithm,
                "public_key_size": leaf.public_key_size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                "rsa_exponent": leaf.rsa_exponent.as_deref().unwrap_or("N/A"),
                "sans": if leaf.san.is_empty() { "N/A".to_string() } else { leaf.san.join("; ") },
                "fingerprint_sha256": leaf.fingerprint_sha256.as_deref().unwrap_or("N/A"),
                "certificate_transparency": leaf
                    .certificate_transparency
                    .as_deref()
                    .unwrap_or("N/A"),
                "validation_valid": cert.validation.valid,
                "validation_hostname_match": cert.validation.hostname_match,
                "validation_trust_chain_valid": cert.validation.trust_chain_valid,
                "validation_not_expired": cert.validation.not_expired,
            }))
        }),
        "revocation": results.certificate_chain.as_ref().and_then(|cert| {
            cert.revocation.as_ref().map(|revocation| json!({
                "status": format!("{:?}", revocation.status),
                "method": format!("{:?}", revocation.method),
                "details": revocation.details,
                "ocsp_stapling": revocation.ocsp_stapling,
                "must_staple": revocation.must_staple,
                "ocsp_stapling_supported": revocation
                    .ocsp_stapling_details
                    .as_ref()
                    .map(|details| details.stapling_supported)
                    .unwrap_or(false),
                "ocsp_stapling_present": revocation
                    .ocsp_stapling_details
                    .as_ref()
                    .map(|details| details.stapled_response_present)
                    .unwrap_or(false),
                "ocsp_stapling_valid": revocation
                    .ocsp_stapling_details
                    .as_ref()
                    .and_then(|details| details.stapled_response_valid)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                "ocsp_stapling_details": revocation
                    .ocsp_stapling_details
                    .as_ref()
                    .map(|details| details.details.clone())
                    .unwrap_or_else(|| "N/A".to_string()),
            }))
        }),
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
    use crate::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
    use crate::certificates::{
        parser::CertificateChain, parser::CertificateInfo, validator::ValidationResult,
    };
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
    fn test_html_generation_includes_certificate_section() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 5000,
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain: CertificateChain {
                    certificates: vec![CertificateInfo {
                        subject: "CN=example.com".to_string(),
                        issuer: "CN=Test CA".to_string(),
                        serial_number: "01AB".to_string(),
                        not_before: "2026-01-01".to_string(),
                        not_after: "2027-01-01".to_string(),
                        expiry_countdown: Some("expires in 1 year".to_string()),
                        signature_algorithm: "sha256WithRSAEncryption".to_string(),
                        public_key_algorithm: "RSA".to_string(),
                        public_key_size: Some(2048),
                        rsa_exponent: Some("e 65537".to_string()),
                        san: vec!["example.com".to_string(), "www.example.com".to_string()],
                        is_ca: false,
                        key_usage: vec![],
                        extended_key_usage: vec![],
                        extended_validation: false,
                        ev_oids: vec![],
                        pin_sha256: None,
                        fingerprint_sha256: Some("AA:BB".to_string()),
                        debian_weak_key: None,
                        aia_url: None,
                        certificate_transparency: Some("Yes (certificate)".to_string()),
                        der_bytes: vec![],
                    }],
                    chain_length: 1,
                    chain_size_bytes: 1,
                },
                validation: ValidationResult {
                    valid: true,
                    issues: Vec::new(),
                    trust_chain_valid: true,
                    hostname_match: true,
                    not_expired: true,
                    signature_valid: true,
                    trusted_ca: None,
                    platform_trust: None,
                },
                revocation: Some(RevocationResult {
                    status: RevocationStatus::Good,
                    method: RevocationMethod::OCSP,
                    details: "OCSP check via https://ocsp.example.com".to_string(),
                    ocsp_stapling: true,
                    ocsp_stapling_details: None,
                    must_staple: false,
                }),
            }),
            ..Default::default()
        };

        let html = generate_html_report(&results).expect("test assertion should succeed");
        assert!(html.contains("<h2>Certificate</h2>"));
        assert!(html.contains("Certificate Authority"));
        assert!(html.contains("expires in 1 year"));
        assert!(html.contains("<h2>Revocation</h2>"));
        assert!(html.contains("OCSP"));
        assert!(html.contains("OCSP check via https://ocsp.example.com"));
    }

    #[test]
    fn test_html_grade_class_red_for_trust_and_mismatch_grades() {
        // Grades T (certificate not trusted) and M (hostname mismatch) are failure
        // grades and must render with a red grade-box class, matching Grade::color()
        // (F/T/M -> red). Previously the CSS only coloured F, leaving T/M unstyled.
        for grade in [Grade::T, Grade::M] {
            let results = ScanResults {
                target: "example.com:443".to_string(),
                rating: Some(RatingResults {
                    ssl_rating: Some(RatingResult {
                        grade,
                        score: 0,
                        certificate_score: 0,
                        protocol_score: 0,
                        key_exchange_score: 0,
                        cipher_strength_score: 0,
                        warnings: Vec::new(),
                    }),
                }),
                ..Default::default()
            };
            let html = generate_html_report(&results).expect("test assertion should succeed");
            // The grade-box must carry the matching red class.
            let expected_class = match grade {
                Grade::T => "grade-T",
                Grade::M => "grade-M",
                _ => unreachable!(),
            };
            assert!(
                html.contains(expected_class),
                "grade {grade:?} must emit class {expected_class}"
            );
        }
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
        assert!(html.contains(">A+<"));
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
                inconclusive: false,
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
    fn test_html_inconclusive_protocol_not_rendered_as_not_supported() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![crate::protocols::ProtocolTestResult {
                protocol: crate::protocols::Protocol::TLS10,
                supported: false,
                inconclusive: true,
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
        assert!(
            !html.contains("Not Supported"),
            "an inconclusive protocol must not be rendered as a definitive Not Supported"
        );
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
