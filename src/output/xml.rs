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
            if let Some(ref countdown) = leaf.expiry_countdown {
                xml.push_str(&format!(
                    "    <expires>{}</expires>\n",
                    escape_xml(countdown)
                ));
            }
            xml.push_str(&format!(
                "    <signature_algorithm>{}</signature_algorithm>\n",
                escape_xml(&leaf.signature_algorithm)
            ));
            xml.push_str(&format!("    <is_ca>{}</is_ca>\n", leaf.is_ca));
            xml.push_str(&format!(
                "    <public_key_algorithm>{}</public_key_algorithm>\n",
                escape_xml(&leaf.public_key_algorithm)
            ));
            if let Some(key_size) = leaf.public_key_size {
                xml.push_str(&format!(
                    "    <public_key_size>{}</public_key_size>\n",
                    key_size
                ));
            }
            if let Some(ref exponent) = leaf.rsa_exponent {
                xml.push_str(&format!(
                    "    <rsa_exponent>{}</rsa_exponent>\n",
                    escape_xml(exponent)
                ));
            }
            if !leaf.san.is_empty() {
                xml.push_str("    <sans>\n");
                for san in &leaf.san {
                    xml.push_str(&format!("      <san>{}</san>\n", escape_xml(san)));
                }
                xml.push_str("    </sans>\n");
            }
            if !leaf.key_usage.is_empty() {
                xml.push_str("    <key_usage>\n");
                for usage in &leaf.key_usage {
                    xml.push_str(&format!("      <usage>{}</usage>\n", escape_xml(usage)));
                }
                xml.push_str("    </key_usage>\n");
            }
            if !leaf.extended_key_usage.is_empty() {
                xml.push_str("    <extended_key_usage>\n");
                for usage in &leaf.extended_key_usage {
                    xml.push_str(&format!("      <usage>{}</usage>\n", escape_xml(usage)));
                }
                xml.push_str("    </extended_key_usage>\n");
            }
            if !leaf.ev_oids.is_empty() {
                xml.push_str("    <ev_oids>\n");
                for oid in &leaf.ev_oids {
                    xml.push_str(&format!("      <oid>{}</oid>\n", escape_xml(oid)));
                }
                xml.push_str("    </ev_oids>\n");
            }
            if let Some(ref fingerprint) = leaf.fingerprint_sha256 {
                xml.push_str(&format!(
                    "    <fingerprint_sha256>{}</fingerprint_sha256>\n",
                    escape_xml(fingerprint)
                ));
            }
            if let Some(ref pin) = leaf.pin_sha256 {
                xml.push_str(&format!(
                    "    <pin_sha256>{}</pin_sha256>\n",
                    escape_xml(pin)
                ));
            }
            xml.push_str(&format!(
                "    <extended_validation>{}</extended_validation>\n",
                leaf.extended_validation
            ));
            if let Some(debian_weak_key) = leaf.debian_weak_key {
                xml.push_str(&format!(
                    "    <debian_weak_key>{}</debian_weak_key>\n",
                    debian_weak_key
                ));
            }
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
        if let Some(revocation) = &cert_data.revocation {
            xml.push_str("    <revocation>\n");
            xml.push_str(&format!("      <status>{:?}</status>\n", revocation.status));
            xml.push_str(&format!("      <method>{:?}</method>\n", revocation.method));
            xml.push_str(&format!(
                "      <details>{}</details>\n",
                escape_xml(&revocation.details)
            ));
            xml.push_str(&format!(
                "      <ocsp_stapling>{}</ocsp_stapling>\n",
                revocation.ocsp_stapling
            ));
            xml.push_str(&format!(
                "      <must_staple>{}</must_staple>\n",
                revocation.must_staple
            ));
            if let Some(stapling) = &revocation.ocsp_stapling_details {
                xml.push_str("      <ocsp_stapling_details>\n");
                xml.push_str(&format!(
                    "        <stapling_supported>{}</stapling_supported>\n",
                    stapling.stapling_supported
                ));
                xml.push_str(&format!(
                    "        <stapled_response_present>{}</stapled_response_present>\n",
                    stapling.stapled_response_present
                ));
                if let Some(valid) = stapling.stapled_response_valid {
                    xml.push_str(&format!(
                        "        <stapled_response_valid>{}</stapled_response_valid>\n",
                        valid
                    ));
                }
                xml.push_str(&format!(
                    "        <details>{}</details>\n",
                    escape_xml(&stapling.details)
                ));
                xml.push_str("      </ocsp_stapling_details>\n");
            }
            xml.push_str("    </revocation>\n");
        }
        xml.push_str("  </certificate>\n");
    }

    // Rating
    if let Some(rating) = results.ssl_rating() {
        xml.push_str("  <rating>\n");
        xml.push_str(&format!("    <grade>{}</grade>\n", rating.grade));
        xml.push_str(&format!("    <score>{}</score>\n", rating.score));
        xml.push_str("  </rating>\n");
    }

    if let Some(cdn) = results.cdn_detection() {
        xml.push_str("  <cdn_detection>\n");
        xml.push_str(&format!("    <is_cdn>{}</is_cdn>\n", cdn.is_cdn));
        if let Some(provider) = &cdn.cdn_provider {
            xml.push_str(&format!(
                "    <provider>{}</provider>\n",
                escape_xml(provider)
            ));
        }
        xml.push_str(&format!(
            "    <confidence>{}</confidence>\n",
            cdn.confidence
        ));
        if !cdn.indicators.is_empty() {
            xml.push_str("    <indicators>\n");
            for indicator in &cdn.indicators {
                xml.push_str(&format!(
                    "      <indicator>{}</indicator>\n",
                    escape_xml(indicator)
                ));
            }
            xml.push_str("    </indicators>\n");
        }
        xml.push_str("  </cdn_detection>\n");
    }

    if let Some(load_balancer) = results.load_balancer_info() {
        xml.push_str("  <load_balancer_info>\n");
        xml.push_str(&format!(
            "    <detected>{}</detected>\n",
            load_balancer.detected
        ));
        if let Some(lb_type) = &load_balancer.lb_type {
            xml.push_str(&format!("    <type>{}</type>\n", escape_xml(lb_type)));
        }
        xml.push_str(&format!(
            "    <sticky_sessions>{}</sticky_sessions>\n",
            load_balancer.sticky_sessions
        ));
        if !load_balancer.indicators.is_empty() {
            xml.push_str("    <indicators>\n");
            for indicator in &load_balancer.indicators {
                xml.push_str(&format!(
                    "      <indicator>{}</indicator>\n",
                    escape_xml(indicator)
                ));
            }
            xml.push_str("    </indicators>\n");
        }
        xml.push_str("  </load_balancer_info>\n");
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
    use crate::fingerprint::{CdnDetection, LoadBalancerInfo};
    use crate::certificates::revocation::{RevocationMethod, RevocationResult, RevocationStatus};
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
                        expiry_countdown: Some("expires in 1 year".to_string()),
                        signature_algorithm: "sha256WithRSAEncryption".to_string(),
                        is_ca: false,
                        public_key_algorithm: "RSA".to_string(),
                        public_key_size: Some(2048),
                        rsa_exponent: Some("e 65537".to_string()),
                        san: vec!["example.com".to_string(), "www.example.com".to_string()],
                        key_usage: vec![
                            "Digital Signature".to_string(),
                            "Key Encipherment".to_string(),
                        ],
                        extended_key_usage: vec!["Server Authentication".to_string()],
                        ev_oids: vec!["1.2.3.4".to_string()],
                        fingerprint_sha256: Some("AA:BB".to_string()),
                        pin_sha256: Some("pin".to_string()),
                        debian_weak_key: Some(true),
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

        let xml = generate_xml_report(&results).expect("test assertion should succeed");

        assert!(xml.contains("<target>exa&amp;&lt;&gt;&apos;&quot;</target>"));
        assert!(xml.contains("<scantime_ms>123</scantime_ms>"));
        assert!(xml.contains("<name>TLS 1.2</name>"));
        assert!(xml.contains("<secure_renegotiation>true</secure_renegotiation>"));
        assert!(xml.contains("<expires>expires in 1 year</expires>"));
        assert!(xml.contains("<signature_algorithm>sha256WithRSAEncryption</signature_algorithm>"));
        assert!(xml.contains("<is_ca>false</is_ca>"));
        assert!(xml.contains("<public_key_algorithm>RSA</public_key_algorithm>"));
        assert!(xml.contains("<public_key_size>2048</public_key_size>"));
        assert!(xml.contains("<rsa_exponent>e 65537</rsa_exponent>"));
        assert!(xml.contains("<sans>"));
        assert!(xml.contains("<san>example.com</san>"));
        assert!(xml.contains("<key_usage>"));
        assert!(xml.contains("<usage>Digital Signature</usage>"));
        assert!(xml.contains("<extended_key_usage>"));
        assert!(xml.contains("<ev_oids>"));
        assert!(xml.contains("<fingerprint_sha256>AA:BB</fingerprint_sha256>"));
        assert!(xml.contains("<pin_sha256>pin</pin_sha256>"));
        assert!(xml.contains("<debian_weak_key>true</debian_weak_key>"));
        assert!(xml.contains("<aia_url>http://ca.example.com</aia_url>"));
        assert!(
            xml.contains("<certificate_transparency>Yes (certificate)</certificate_transparency>")
        );
        assert!(xml.contains("<revocation>"));
        assert!(xml.contains("<status>Good</status>"));
        assert!(xml.contains("<method>OCSP</method>"));
        assert!(xml.contains("<details>OCSP check via https://ocsp.example.com</details>"));
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
    fn test_xml_includes_cdn_and_load_balancer_sections() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            advanced: Some(crate::scanner::AdvancedResults {
                cdn_detection: Some(CdnDetection {
                    is_cdn: true,
                    cdn_provider: Some("Cloudflare".to_string()),
                    confidence: 0.95,
                    indicators: vec!["cdn".to_string()],
                }),
                load_balancer_info: Some(LoadBalancerInfo {
                    detected: true,
                    lb_type: Some("AWS ALB".to_string()),
                    sticky_sessions: true,
                    indicators: vec!["sticky sessions".to_string()],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let xml = generate_xml_report(&results).expect("test assertion should succeed");
        assert!(xml.contains("<cdn_detection>"));
        assert!(xml.contains("<provider>Cloudflare</provider>"));
        assert!(xml.contains("<load_balancer_info>"));
        assert!(xml.contains("<type>AWS ALB</type>"));
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
