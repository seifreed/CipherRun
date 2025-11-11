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
    xml.push_str("  <protocols>\n");
    for protocol in &results.protocols {
        xml.push_str("    <protocol>\n");
        xml.push_str(&format!(
            "      <name>{}</name>\n",
            escape_xml(&protocol.protocol.to_string())
        ));
        xml.push_str(&format!(
            "      <supported>{}</supported>\n",
            protocol.supported
        ));

        // Secure renegotiation
        if let Some(secure_reneg) = protocol.secure_renegotiation {
            xml.push_str(&format!(
                "      <secure_renegotiation>{}</secure_renegotiation>\n",
                secure_reneg
            ));
        }

        // Session resumption details
        if let Some(caching) = protocol.session_resumption_caching {
            xml.push_str(&format!(
                "      <session_resumption_caching>{}</session_resumption_caching>\n",
                caching
            ));
        }
        if let Some(tickets) = protocol.session_resumption_tickets {
            xml.push_str(&format!(
                "      <session_resumption_tickets>{}</session_resumption_tickets>\n",
                tickets
            ));
        }

        // Heartbeat extension
        if let Some(heartbeat) = protocol.heartbeat_enabled {
            xml.push_str(&format!(
                "      <heartbeat_enabled>{}</heartbeat_enabled>\n",
                heartbeat
            ));
        }

        xml.push_str("    </protocol>\n");
    }
    xml.push_str("  </protocols>\n");

    // Vulnerabilities
    xml.push_str("  <vulnerabilities>\n");
    for vuln in &results.vulnerabilities {
        xml.push_str("    <vulnerability>\n");
        xml.push_str(&format!("      <type>{:?}</type>\n", vuln.vuln_type));
        xml.push_str(&format!(
            "      <vulnerable>{}</vulnerable>\n",
            vuln.vulnerable
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
    if let Some(rating) = &results.rating {
        xml.push_str("  <rating>\n");
        xml.push_str(&format!("    <grade>{}</grade>\n", rating.grade));
        xml.push_str(&format!("    <score>{}</score>\n", rating.score));
        xml.push_str("  </rating>\n");
    }

    xml.push_str("</document>\n");

    Ok(xml)
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
