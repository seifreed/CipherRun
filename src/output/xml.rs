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
            if let Some(ref aia_url) = leaf.aia_url {
                xml.push_str(&format!("    <aia_url>{}</aia_url>\n", escape_xml(aia_url)));
            }
            if let Some(ref ct) = leaf.certificate_transparency {
                xml.push_str(&format!(
                    "    <certificate_transparency>{}</certificate_transparency>\n",
                    escape_xml(ct)
                ));
            }
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
            "      <status>{}</status>\n",
            escape_xml(protocol.status_label())
        ));
        xml.push_str(&format!(
            "      <supported>{}</supported>\n",
            protocol.supported
        ));
        xml.push_str(&format!(
            "      <inconclusive>{}</inconclusive>\n",
            protocol.inconclusive
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
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 permits only tab, LF and CR among the C0 control characters.
            '\t' | '\n' | '\r' => out.push(c),
            // Drop other control characters: emitting them verbatim would produce
            // non-well-formed XML, and these fields carry server-controlled data
            // (certificate subjects, serials, vulnerability details).
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
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
            certificate_chain: Some(crate::scanner::CertificateAnalysisResult {
                chain: crate::certificates::parser::CertificateChain {
                    certificates: vec![crate::certificates::parser::CertificateInfo {
                        subject: "CN=example.com".to_string(),
                        issuer: "CN=Test CA".to_string(),
                        serial_number: "01AB".to_string(),
                        not_before: "2026-01-01".to_string(),
                        not_after: "2027-01-01".to_string(),
                        aia_url: Some("http://ca.example.com".to_string()),
                        certificate_transparency: Some("Yes (certificate)".to_string()),
                        extended_validation: false,
                        ..Default::default()
                    }],
                    chain_length: 1,
                    chain_size_bytes: 1,
                },
                validation: crate::certificates::validator::ValidationResult {
                    valid: true,
                    issues: Vec::new(),
                    trust_chain_valid: true,
                    hostname_match: true,
                    not_expired: true,
                    signature_valid: true,
                    trusted_ca: None,
                    platform_trust: None,
                },
                revocation: None,
            }),
            ..Default::default()
        };

        let xml = generate_xml_report(&results).expect("test assertion should succeed");

        assert!(xml.contains("<target>exa&amp;&lt;&gt;&apos;&quot;</target>"));
        assert!(xml.contains("<scantime_ms>123</scantime_ms>"));
        assert!(xml.contains("<name>TLS 1.2</name>"));
        assert!(xml.contains("<secure_renegotiation>true</secure_renegotiation>"));
        assert!(xml.contains("<aia_url>http://ca.example.com</aia_url>"));
        assert!(
            xml.contains("<certificate_transparency>Yes (certificate)</certificate_transparency>")
        );
        assert!(xml.contains("<details>detail &amp; &lt;tag&gt;</details>"));
        assert!(xml.contains("<cve>CVE-2014-0160</cve>"));
        assert!(xml.contains("<status>Not Vulnerable</status>"));
        assert!(xml.contains("<inconclusive>false</inconclusive>"));
    }

    #[test]
    fn test_xml_protocol_inconclusive_emits_status_and_flag() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1,
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS10,
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

        let xml = generate_xml_report(&results).expect("test assertion should succeed");
        assert!(xml.contains("<status>Inconclusive</status>"));
        assert!(xml.contains("<inconclusive>true</inconclusive>"));
        assert!(xml.contains("<supported>false</supported>"));
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
    fn test_xml_escape_drops_forbidden_control_chars_keeps_whitespace() {
        // C0 control chars (other than tab/LF/CR) are illegal in XML 1.0 and must
        // be dropped so server-controlled data cannot break well-formedness.
        let escaped = escape_xml("a\u{0}b\u{8}c\u{1f}d\tline\nbreak\r");
        assert_eq!(escaped, "abcd\tline\nbreak\r");
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
