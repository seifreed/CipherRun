use crate::api::routes::compliance::{
    ComplianceCheckResponse, ComplianceSummary, RequirementResult, ViolationDetail,
};
use crate::compliance::{
    ComplianceFramework, ComplianceReport, ComplianceStatus, RequirementStatus, Severity,
};

pub fn present_compliance_report(
    framework: &ComplianceFramework,
    target: &str,
    report: &ComplianceReport,
    detailed: bool,
) -> ComplianceCheckResponse {
    ComplianceCheckResponse {
        framework_id: framework.id.clone(),
        framework_name: framework.name.clone(),
        framework_version: framework.version.clone(),
        target: target.to_string(),
        status: compliance_status(report.overall_status).to_string(),
        summary: ComplianceSummary {
            total: report.summary.total,
            passed: report.summary.passed,
            failed: report.summary.failed,
            warnings: report.summary.warnings,
            compliance_percentage: compliance_percentage(report),
        },
        requirements: detailed.then(|| {
            report
                .requirements
                .iter()
                .map(|requirement| RequirementResult {
                    id: requirement.requirement_id.clone(),
                    name: requirement.name.clone(),
                    category: requirement.category.clone(),
                    status: requirement_status(requirement.status).to_string(),
                    severity: severity(requirement.severity).to_string(),
                    violation_count: requirement.violations.len(),
                    violations: (!requirement.violations.is_empty()).then(|| {
                        requirement
                            .violations
                            .iter()
                            .map(|violation| ViolationDetail {
                                rule_type: violation.violation_type.clone(),
                                message: violation.description.clone(),
                                evidence: Some(violation.evidence.clone()),
                            })
                            .collect()
                    }),
                    remediation: Some(requirement.remediation.clone()),
                })
                .collect()
        }),
        evaluated_at: report.scan_timestamp.to_rfc3339(),
    }
}

fn compliance_percentage(report: &ComplianceReport) -> f64 {
    if report.summary.total > 0 {
        (report.summary.passed as f64 / report.summary.total as f64) * 100.0
    } else {
        0.0
    }
}

fn compliance_status(status: ComplianceStatus) -> &'static str {
    match status {
        ComplianceStatus::Pass => "pass",
        ComplianceStatus::Fail => "fail",
        ComplianceStatus::Warning => "warning",
    }
}

fn requirement_status(status: RequirementStatus) -> &'static str {
    match status {
        RequirementStatus::Pass => "pass",
        RequirementStatus::Fail => "fail",
        RequirementStatus::Warning => "warning",
        RequirementStatus::NotApplicable => "not_applicable",
    }
}

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::{
        ComplianceReport, RequirementResult as ComplianceRequirementResult, Severity, Violation,
    };

    #[test]
    fn omits_requirements_when_not_detailed() {
        let framework = ComplianceFramework {
            id: "pci-dss-v4".to_string(),
            name: "PCI DSS".to_string(),
            version: "4.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let report = ComplianceReport::new(&framework, "example.com:443".to_string());

        let response = present_compliance_report(&framework, "example.com:443", &report, false);

        assert!(response.requirements.is_none());
        assert_eq!(response.status, "pass");
        assert_eq!(response.summary.compliance_percentage, 0.0);
    }

    #[test]
    fn includes_detailed_requirement_mapping() {
        let framework = ComplianceFramework {
            id: "pci-dss-v4".to_string(),
            name: "PCI DSS".to_string(),
            version: "4.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let mut report = ComplianceReport::new(&framework, "example.com:443".to_string());
        report.add_requirement_result(ComplianceRequirementResult {
            requirement_id: "REQ-1".to_string(),
            name: "Strong TLS".to_string(),
            description: String::new(),
            category: "protocols".to_string(),
            severity: Severity::High,
            status: RequirementStatus::Fail,
            violations: vec![Violation {
                violation_type: "protocol".to_string(),
                description: "TLS 1.0 enabled".to_string(),
                evidence: "tls1.0".to_string(),
                severity: Severity::High,
            }],
            remediation: "Disable TLS 1.0".to_string(),
        });
        report.finalize();

        let response = present_compliance_report(&framework, "example.com:443", &report, true);
        let requirements = response
            .requirements
            .expect("requirements should be present");

        assert_eq!(response.status, "fail");
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].status, "fail");
        assert_eq!(requirements[0].severity, "high");
        assert_eq!(requirements[0].violation_count, 1);
    }

    #[test]
    fn maps_warning_and_not_applicable_statuses() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let mut report = ComplianceReport::new(&framework, "example.com:443".to_string());
        report.add_requirement_result(ComplianceRequirementResult {
            requirement_id: "REQ-WARN".to_string(),
            name: "Warn".to_string(),
            description: String::new(),
            category: "protocols".to_string(),
            severity: Severity::Medium,
            status: RequirementStatus::Warning,
            violations: Vec::new(),
            remediation: "Review".to_string(),
        });
        report.add_requirement_result(ComplianceRequirementResult {
            requirement_id: "REQ-NA".to_string(),
            name: "N/A".to_string(),
            description: String::new(),
            category: "protocols".to_string(),
            severity: Severity::Low,
            status: RequirementStatus::NotApplicable,
            violations: Vec::new(),
            remediation: "Ignore".to_string(),
        });
        report.finalize();

        let response = present_compliance_report(&framework, "example.com:443", &report, true);
        let requirements = response
            .requirements
            .expect("requirements should be present");

        assert_eq!(response.status, "warning");
        assert_eq!(requirements[0].status, "warning");
        assert_eq!(requirements[1].status, "not_applicable");
    }

    #[test]
    fn percentage_is_zero_when_summary_total_is_zero_even_with_details() {
        let framework = ComplianceFramework {
            id: "zero".to_string(),
            name: "Zero".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let report = ComplianceReport::new(&framework, "example.com:443".to_string());

        let response = present_compliance_report(&framework, "example.com:443", &report, true);

        assert_eq!(response.summary.total, 0);
        assert_eq!(response.summary.compliance_percentage, 0.0);
        assert_eq!(
            response
                .requirements
                .expect("requirements should be present")
                .len(),
            0
        );
    }

    #[test]
    fn includes_null_evidence_and_remediation_for_empty_requirement_data() {
        let framework = ComplianceFramework {
            id: "detail".to_string(),
            name: "Detail".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            organization: String::new(),
            effective_date: None,
            requirements: Vec::new(),
        };
        let mut report = ComplianceReport::new(&framework, "example.com:443".to_string());
        report.add_requirement_result(ComplianceRequirementResult {
            requirement_id: "REQ-EMPTY".to_string(),
            name: "Empty".to_string(),
            description: String::new(),
            category: "certificates".to_string(),
            severity: Severity::Info,
            status: RequirementStatus::Pass,
            violations: Vec::new(),
            remediation: String::new(),
        });
        report.finalize();

        let response = present_compliance_report(&framework, "example.com:443", &report, true);
        let requirement = &response
            .requirements
            .expect("requirements should be present")[0];

        assert_eq!(requirement.severity, "info");
        assert_eq!(requirement.violation_count, 0);
        assert!(requirement.violations.is_none());
        assert_eq!(requirement.remediation.as_deref(), Some(""));
    }
}
