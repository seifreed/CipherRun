use crate::Result;
use crate::scanner::ScanResults;
use crate::vulnerabilities::{FindingStatus, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn generate_sarif_report(results: &ScanResults) -> Result<String> {
    let mut rules = BTreeMap::new();
    let findings = results
        .vulnerabilities
        .iter()
        .filter(|finding| {
            matches!(
                finding.status(),
                FindingStatus::ConfirmedVulnerable
                    | FindingStatus::PotentialExposure
                    | FindingStatus::Inconclusive
            )
        })
        .map(|finding| {
            rules.entry(finding.finding_id()).or_insert_with(|| {
                json!({
                    "id": finding.finding_id(),
                    "name": format!("{:?}", finding.vuln_type),
                    "shortDescription": { "text": format!("{:?} TLS finding", finding.vuln_type) },
                    "properties": { "severity": format!("{:?}", finding.severity).to_ascii_lowercase() }
                })
            });

            let evidence = finding.evidence();
            json!({
                "ruleId": finding.finding_id(),
                "level": sarif_level(finding.status(), finding.severity),
                "message": { "text": finding.details },
                "locations": [{
                    "logicalLocations": [{ "fullyQualifiedName": results.target }]
                }],
                "properties": {
                    "status": finding.status().as_str(),
                    "confidence": finding.confidence(),
                    "detectionMethod": finding.detection_method(),
                    "evidence": evidence
                }
            })
        })
        .collect::<Vec<_>>();

    let report = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "CipherRun",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": env!("CARGO_PKG_HOMEPAGE"),
                "rules": rules.into_values().collect::<Vec<Value>>()
            }},
            "results": findings
        }]
    });
    Ok(serde_json::to_string_pretty(&report)?)
}

fn sarif_level(status: FindingStatus, severity: Severity) -> &'static str {
    if status != FindingStatus::ConfirmedVulnerable {
        return "note";
    }
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::{VulnerabilityResult, VulnerabilityType};

    #[test]
    fn sarif_contains_only_actionable_or_uncertain_findings() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            vulnerabilities: vec![
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::Heartbleed,
                    vulnerable: true,
                    inconclusive: false,
                    details: "confirmed".to_string(),
                    cve: Some("CVE-2014-0160".to_string()),
                    cwe: None,
                    severity: Severity::Critical,
                },
                VulnerabilityResult {
                    vuln_type: VulnerabilityType::BEAST,
                    vulnerable: false,
                    inconclusive: false,
                    details: "clean".to_string(),
                    cve: None,
                    cwe: None,
                    severity: Severity::Medium,
                },
            ],
            ..Default::default()
        };

        let value: Value = serde_json::from_str(&generate_sarif_report(&results).unwrap()).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(value["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            value["runs"][0]["results"][0]["ruleId"],
            "CR-TLS-HEARTBLEED-001"
        );
    }
}
