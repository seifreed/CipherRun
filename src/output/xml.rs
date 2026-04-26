// XML Output Format

use crate::Result;
use crate::scanner::ScanResults;

pub fn generate_xml_report(results: &ScanResults) -> Result<String> {
    let mut xml = String::new();

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<document title=\"CipherRun Scan Results\">\n");

    // Target info
    xml.push_str(&format!(
        "  <target>{}</target>\n",
        escape_xml(&results.target)
    ));
    xml.push_str(&format!(
        "  <scantime_ms>{}</scantime_ms>\n",
        results.scan_time_ms
    ));

    // Protocols
    write_protocols_block(&mut xml, &results.protocols);

    // Vulnerabilities
    write_vulnerabilities_block(&mut xml, &results.vulnerabilities);

    // Certificate
    if let Some(cert_data) = &results.certificate_chain {
        xml.push_str("  <certificate>\n");
        if let Some(leaf) = cert_data.chain.leaf() {
            xml.push_str(&format!(
                "    <subject>{}</subject>\n",
                escape_xml(&leaf.subject)
            ));
            xml.push_str(&format!(
                "    <issuer>{}</issuer>\n",
                escape_xml(&leaf.issuer)
            ));
            xml.push_str(&format!(
                "    <serial>{}</serial>\n",
                escape_xml(&leaf.serial_number)
            ));
            xml.push_str(&format!(
                "    <valid_from>{}</valid_from>\n",
                escape_xml(&leaf.not_before)
            ));
            xml.push_str(&format!(
                "    <valid_to>{}</valid_to>\n",
                escape_xml(&leaf.not_after)
            ));
            xml.push_str(&format!(
                "    <extended_validation>{}</extended_validation>\n",
                leaf.extended_validation
            ));
        }
        xml.push_str(&format!(
            "    <valid>{}</valid>\n",
            cert_data.validation.valid
        ));
        xml.push_str("  </certificate>\n");
    }

    // Rating
    if let Some(rating) = results.ssl_rating() {
        xml.push_str("  <rating>\n");
        xml.push_str(&format!("    <grade>{}</grade>\n", rating.grade));
        xml.push_str(&format!("    <score>{}</score>\n", rating.score));
        xml.push_str("  </rating>\n");
    }

    xml.push_str("</document>\n");

    Ok(xml)
}

fn write_optional_bool_field(xml: &mut String, tag: &str, value: Option<bool>) {
    xml.push_str(&format!(
        "      <{}_status>{}</{}_status>\n",
        tag,
        option_status_label(value),
        tag
    ));
    if let Some(v) = value {
        xml.push_str(&format!("      <{0}>{1}</{0}>\n", tag, v));
    }
}

fn write_protocols_block(xml: &mut String, protocols: &[crate::protocols::ProtocolTestResult]) {
    xml.push_str("  <protocols>\n");
    for protocol in protocols {
        xml.push_str("    <protocol>\n");
        xml.push_str(&format!(
            "      <name>{}</name>\n",
            escape_xml(&protocol.protocol.to_string())
        ));
        xml.push_str(&format!(
            "      <supported>{}</supported>\n",
            protocol.supported
        ));
        write_optional_bool_field(xml, "secure_renegotiation", protocol.secure_renegotiation);
        write_optional_bool_field(
            xml,
            "session_resumption_caching",
            protocol.session_resumption_caching,
        );
        write_optional_bool_field(
            xml,
            "session_resumption_tickets",
            protocol.session_resumption_tickets,
        );
        write_optional_bool_field(xml, "heartbeat_enabled", protocol.heartbeat_enabled);
        xml.push_str("    </protocol>\n");
    }
    xml.push_str("  </protocols>\n");
}

fn write_vulnerabilities_block(
    xml: &mut String,
    vulnerabilities: &[crate::vulnerabilities::VulnerabilityResult],
) {
    xml.push_str("  <vulnerabilities>\n");
    for vuln in vulnerabilities {
        xml.push_str("    <vulnerability>\n");
        xml.push_str(&format!("      <type>{:?}</type>\n", vuln.vuln_type));
        xml.push_str(&format!(
            "      <status>{}</status>\n",
            escape_xml(vuln.status_label())
        ));
        xml.push_str(&format!(
            "      <vulnerable>{}</vulnerable>\n",
            vuln.vulnerable
        ));
        xml.push_str(&format!(
            "      <inconclusive>{}</inconclusive>\n",
            vuln.inconclusive
        ));
        xml.push_str(&format!("      <severity>{:?}</severity>\n", vuln.severity));
        if let Some(cve) = &vuln.cve {
            xml.push_str(&format!("      <cve>{}</cve>\n", escape_xml(cve)));
        }
        xml.push_str(&format!(
            "      <details>{}</details>\n",
            escape_xml(&vuln.details)
        ));
        xml.push_str("    </vulnerability>\n");
    }
    xml.push_str("  </vulnerabilities>\n");
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn option_status_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "supported",
        Some(false) => "not_supported",
        None => "inconclusive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use crate::rating::{Grade, RatingResult};
    use crate::scanner::RatingResults;
    use crate::scanner::ScanResults;
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

    #[test]
    fn test_generate_xml_report_escapes_and_includes_sections() {
        let results = ScanResults {
            target: "exa&<>'\"".to_string(),
            scan_time_ms: 123,
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 1,
                handshake_time_ms: Some(10),
                heartbeat_enabled: Some(false),
                session_resumption_caching: Some(true),
                session_resumption_tickets: Some(false),
                secure_renegotiation: Some(true),
            }],
            vulnerabilities: vec![VulnerabilityResult {
                vuln_type: VulnerabilityType::Heartbleed,
                vulnerable: false,
                inconclusive: false,
                details: "detail & <tag>".to_string(),
                cve: Some("CVE-2014-0160".to_string()),
                cwe: None,
                severity: Severity::High,
            }],
            ..Default::default()
        };

        let xml = generate_xml_report(&results).expect("test assertion should succeed");

        assert!(xml.contains("<target>exa&amp;&lt;&gt;&apos;&quot;</target>"));
        assert!(xml.contains("<scantime_ms>123</scantime_ms>"));
        assert!(xml.contains("<name>TLS 1.2</name>"));
        assert!(xml.contains("<secure_renegotiation>true</secure_renegotiation>"));
        assert!(xml.contains("<details>detail &amp; &lt;tag&gt;</details>"));
        assert!(xml.contains("<cve>CVE-2014-0160</cve>"));
        assert!(xml.contains("<status>Not Vulnerable</status>"));
        assert!(xml.contains("<inconclusive>false</inconclusive>"));
    }

    #[test]
    fn test_generate_xml_without_optional_sections() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            ..Default::default()
        };

        let xml = generate_xml_report(&results).expect("test assertion should succeed");
        assert!(xml.contains("<target>example.com:443</target>"));
        assert!(!xml.contains("<certificate>"));
        assert!(!xml.contains("<rating>"));
    }

    #[test]
    fn test_xml_escape_quotes() {
        let escaped = escape_xml("a\"b'c");
        assert!(escaped.contains("&quot;"));
        assert!(escaped.contains("&apos;"));
    }

    #[test]
    fn test_xml_includes_rating_section() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            rating: Some(RatingResults {
                ssl_rating: Some(RatingResult {
                    grade: Grade::A,
                    score: 90,
                    certificate_score: 90,
                    protocol_score: 90,
                    key_exchange_score: 90,
                    cipher_strength_score: 90,
                    warnings: Vec::new(),
                }),
            }),
            ..Default::default()
        };

        let xml = generate_xml_report(&results).expect("test assertion should succeed");
        assert!(xml.contains("<rating>"));
        assert!(xml.contains("<grade>A</grade>"));
        assert!(xml.contains("<score>90</score>"));
    }

    #[test]
    fn test_xml_escape_safe_string() {
        let escaped = escape_xml("plain-text");
        assert_eq!(escaped, "plain-text");
    }

    #[test]
    fn test_generate_xml_has_root_element() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            ..Default::default()
        };
        let xml = generate_xml_report(&results).expect("test assertion should succeed");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document"));
        assert!(xml.ends_with("</document>\n"));
    }
}
