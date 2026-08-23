use crate::scanner::ScanResults;
use crate::vulnerabilities::FindingStatus;

pub fn generate_junit_report(results: &ScanResults) -> String {
    let failures = results
        .vulnerabilities
        .iter()
        .filter(|finding| finding.status() == FindingStatus::ConfirmedVulnerable)
        .count();
    let skipped = results
        .vulnerabilities
        .iter()
        .filter(|finding| {
            matches!(
                finding.status(),
                FindingStatus::PotentialExposure
                    | FindingStatus::Inconclusive
                    | FindingStatus::NotApplicable
                    | FindingStatus::NotExecuted
            )
        })
        .count();
    let escape = crate::output::xml::escape_xml;
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"CipherRun TLS scan\" tests=\"{}\" failures=\"{failures}\" skipped=\"{skipped}\" time=\"{:.3}\">\n",
        results.vulnerabilities.len(),
        results.scan_time_ms as f64 / 1000.0
    );

    for finding in &results.vulnerabilities {
        xml.push_str(&format!(
            "  <testcase classname=\"{}\" name=\"{}\">\n",
            escape(&results.target),
            finding.finding_id()
        ));
        match finding.status() {
            FindingStatus::ConfirmedVulnerable => xml.push_str(&format!(
                "    <failure type=\"security_vulnerability\" message=\"{}\">{}</failure>\n",
                escape(&format!("{:?}", finding.severity)),
                escape(&finding.details)
            )),
            FindingStatus::PotentialExposure
            | FindingStatus::Inconclusive
            | FindingStatus::NotApplicable
            | FindingStatus::NotExecuted => xml.push_str(&format!(
                "    <skipped message=\"{}\" />\n",
                escape(finding.status_label())
            )),
            FindingStatus::NotVulnerable => {}
        }
        xml.push_str("  </testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::{Severity, VulnerabilityResult, VulnerabilityType};

    #[test]
    fn junit_maps_confirmed_to_failures_and_uncertain_to_skipped() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            vulnerabilities: vec![
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::Heartbleed,
                    vulnerable: true,
                    inconclusive: false,
                    details: "bad & <unsafe>".to_string(),
                    cve: None,
                    cwe: None,
                    severity: Severity::Critical,
                },
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::BREACH,
                    vulnerable: true,
                    inconclusive: true,
                    details: "potential".to_string(),
                    cve: None,
                    cwe: None,
                    severity: Severity::Medium,
                },
            ],
            ..Default::default()
        };

        let xml = generate_junit_report(&results);
        assert!(xml.contains("tests=\"2\" failures=\"1\" skipped=\"1\""));
        assert!(xml.contains("bad &amp; &lt;unsafe&gt;"));
        assert!(xml.contains("<skipped message=\"Potential Exposure\" />"));
    }
}
