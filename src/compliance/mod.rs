// Compliance module - Framework-based compliance checking and reporting
//
// This module provides comprehensive compliance checking against industry standards
// including PCI-DSS, NIST SP 800-52r2, HIPAA, SOC 2, Mozilla Modern/Intermediate, and GDPR.

pub mod checker;
pub mod engine;
pub mod framework;
pub mod loader;
pub mod reporter;
pub mod rule;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use checker::ComplianceChecker;
pub use engine::ComplianceEngine;
pub use framework::{ComplianceFramework, Requirement};
pub use loader::FrameworkLoader;
pub use reporter::Reporter;
pub use rule::{Rule, RuleType};

/// Overall compliance status for a scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceStatus {
    /// All requirements passed
    Pass,
    /// One or more critical failures
    Fail,
    /// Minor issues detected
    Warning,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceStatus::Pass => write!(f, "PASS"),
            ComplianceStatus::Fail => write!(f, "FAIL"),
            ComplianceStatus::Warning => write!(f, "WARNING"),
        }
    }
}

/// Status of an individual requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequirementStatus {
    /// Requirement met
    Pass,
    /// Requirement not met (critical)
    Fail,
    /// Requirement partially met or minor issue
    Warning,
    /// Requirement not applicable to this scan
    NotApplicable,
}

impl std::fmt::Display for RequirementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementStatus::Pass => write!(f, "PASS"),
            RequirementStatus::Fail => write!(f, "FAIL"),
            RequirementStatus::Warning => write!(f, "WARNING"),
            RequirementStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// Severity level for violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A compliance violation detected during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Type of violation (e.g., "Weak Protocol", "Insecure Cipher")
    pub violation_type: String,
    /// Human-readable description
    pub description: String,
    /// Evidence supporting the violation (e.g., "TLS 1.0 enabled")
    pub evidence: String,
    /// Severity of this violation
    pub severity: Severity,
}

/// Result of evaluating a single compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementResult {
    /// Requirement identifier (e.g., "PCI-4.2.1")
    pub requirement_id: String,
    /// Short name of the requirement
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Category (e.g., "Protocol Security", "Cipher Security")
    pub category: String,
    /// Severity level of this requirement
    pub severity: Severity,
    /// Status of this requirement
    pub status: RequirementStatus,
    /// List of violations found
    pub violations: Vec<Violation>,
    /// Remediation advice
    pub remediation: String,
}

/// Summary statistics for a compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Total number of requirements evaluated
    pub total: usize,
    /// Number of requirements passed
    pub passed: usize,
    /// Number of requirements failed
    pub failed: usize,
    /// Number of requirements with warnings
    pub warnings: usize,
    /// Number of requirements not applicable
    pub not_applicable: usize,
}

/// Complete compliance report for a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Framework used for evaluation
    pub framework: ComplianceFramework,
    /// Target that was scanned (hostname:port)
    pub target: String,
    /// When the scan was performed
    pub scan_timestamp: DateTime<Utc>,
    /// Overall compliance status
    pub overall_status: ComplianceStatus,
    /// Individual requirement results
    pub requirements: Vec<RequirementResult>,
    /// Summary statistics
    pub summary: ComplianceSummary,
}

impl ComplianceReport {
    /// Create a new compliance report
    pub fn new(framework: &ComplianceFramework, target: String) -> Self {
        Self {
            framework: framework.clone(),
            target,
            scan_timestamp: Utc::now(),
            overall_status: ComplianceStatus::Pass,
            requirements: Vec::new(),
            summary: ComplianceSummary {
                total: 0,
                passed: 0,
                failed: 0,
                warnings: 0,
                not_applicable: 0,
            },
        }
    }

    /// Add a requirement result to the report
    pub fn add_requirement_result(&mut self, result: RequirementResult) {
        match result.status {
            RequirementStatus::Pass => self.summary.passed += 1,
            RequirementStatus::Fail => self.summary.failed += 1,
            RequirementStatus::Warning => self.summary.warnings += 1,
            RequirementStatus::NotApplicable => self.summary.not_applicable += 1,
        }
        self.requirements.push(result);
    }

    /// Finalize the report by calculating overall status
    pub fn finalize(&mut self) {
        self.summary.total = self.requirements.len();

        self.overall_status = if self.summary.failed > 0 {
            ComplianceStatus::Fail
        } else if self.summary.warnings > 0 {
            ComplianceStatus::Warning
        } else {
            ComplianceStatus::Pass
        };
    }

    /// Get all failed requirements
    pub fn failed_requirements(&self) -> Vec<&RequirementResult> {
        self.requirements
            .iter()
            .filter(|r| r.status == RequirementStatus::Fail)
            .collect()
    }

    /// Get all requirements with warnings
    pub fn warning_requirements(&self) -> Vec<&RequirementResult> {
        self.requirements
            .iter()
            .filter(|r| r.status == RequirementStatus::Warning)
            .collect()
    }

    /// Get requirements by severity
    pub fn requirements_by_severity(&self, severity: Severity) -> Vec<&RequirementResult> {
        self.requirements
            .iter()
            .filter(|r| r.severity == severity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Pass.to_string(), "PASS");
        assert_eq!(ComplianceStatus::Fail.to_string(), "FAIL");
        assert_eq!(ComplianceStatus::Warning.to_string(), "WARNING");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_compliance_report_summary() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![],
        };

        let mut report = ComplianceReport::new(&framework, "test.com:443".to_string());

        report.add_requirement_result(RequirementResult {
            requirement_id: "TEST-1".to_string(),
            name: "Test Req".to_string(),
            description: "".to_string(),
            category: "Test".to_string(),
            severity: Severity::High,
            status: RequirementStatus::Pass,
            violations: vec![],
            remediation: "".to_string(),
        });

        report.add_requirement_result(RequirementResult {
            requirement_id: "TEST-2".to_string(),
            name: "Test Req 2".to_string(),
            description: "".to_string(),
            category: "Test".to_string(),
            severity: Severity::Critical,
            status: RequirementStatus::Fail,
            violations: vec![],
            remediation: "".to_string(),
        });

        report.finalize();

        assert_eq!(report.summary.total, 2);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.overall_status, ComplianceStatus::Fail);
    }
}
