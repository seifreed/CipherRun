// Policy-as-Code Engine - Core module
//
// This module provides a complete policy-as-code implementation for
// enforcing TLS/SSL security policies in CI/CD pipelines and automated scans.

pub mod evaluator;
pub mod exceptions;
pub mod parser;
pub mod rules;
pub mod violation;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy action to take when a rule is violated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "INFO")]
    Info,
}

impl PolicyAction {
    pub fn is_failure(&self) -> bool {
        matches!(self, PolicyAction::Fail)
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, PolicyAction::Warn)
    }
}

/// Complete policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<ProtocolPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<CipherPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<CertificatePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<VulnerabilityPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating: Option<RatingPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<CompliancePolicy>,

    #[serde(default)]
    pub exceptions: Vec<PolicyException>,
}

/// Protocol policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Cipher suite policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_strength: Option<String>, // LOW, MEDIUM, HIGH
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_forward_secrecy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_aead: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_patterns: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Certificate policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_signature_algorithms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_valid_trust_chain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_san: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_hostname_match: Option<bool>,
    pub action: PolicyAction,
}

/// Vulnerability policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_critical: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_high: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_medium: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Rating policy requirements (SSL Labs style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_grade: Option<String>, // A+, A, A-, B, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score: Option<u32>,
    pub action: PolicyAction,
}

/// Compliance framework policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub require_all: bool,
    pub action: PolicyAction,
}

/// Policy exception for specific targets or rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>, // Supports wildcards: *.example.com
    pub rules: Vec<String>,      // Rule paths: "protocols.prohibited"
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>, // YYYY-MM-DD format
    pub approved_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

/// Result of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub policy_name: String,
    pub policy_version: String,
    pub target: String,
    pub evaluation_time: DateTime<Utc>,
    pub violations: Vec<violation::PolicyViolation>,
    pub exceptions_applied: Vec<String>,
    pub summary: PolicySummary,
}

/// Summary statistics of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub total_checks: u32,
    pub passed: u32,
    pub failed: u32,
    pub warnings: u32,
    pub info: u32,
    pub overall_result: PolicyOverallResult,
}

/// Overall policy evaluation result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyOverallResult {
    Pass,
    Fail,
    Warning,
}

impl PolicyResult {
    pub fn new(policy: Policy, violations: Vec<violation::PolicyViolation>) -> Self {
        let mut failed = 0;
        let mut warnings = 0;
        let mut info = 0;

        for violation in &violations {
            match violation.action {
                PolicyAction::Fail => failed += 1,
                PolicyAction::Warn => warnings += 1,
                PolicyAction::Info => info += 1,
            }
        }

        let overall_result = if failed > 0 {
            PolicyOverallResult::Fail
        } else if warnings > 0 {
            PolicyOverallResult::Warning
        } else {
            PolicyOverallResult::Pass
        };

        let total_checks = violations.len() as u32;
        let passed = total_checks - failed - warnings - info;

        Self {
            policy_name: policy.name,
            policy_version: policy.version,
            target: String::new(), // Set by evaluator
            evaluation_time: Utc::now(),
            violations,
            exceptions_applied: Vec::new(), // Set by evaluator
            summary: PolicySummary {
                total_checks,
                passed,
                failed,
                warnings,
                info,
                overall_result,
            },
        }
    }

    /// Check if there are any violations that should fail the check
    pub fn has_violations(&self) -> bool {
        self.summary.overall_result == PolicyOverallResult::Fail
    }

    /// Format the result for display
    pub fn format(&self, format: &str) -> crate::Result<String> {
        match format {
            "json" => Ok(serde_json::to_string_pretty(self)?),
            "csv" => self.to_csv(),
            "terminal" | _ => self.to_terminal(),
        }
    }

    /// Format as terminal output
    fn to_terminal(&self) -> crate::Result<String> {
        use colored::*;
        let mut output = String::new();

        output.push_str(&format!(
            "{}\n",
            "=".repeat(60).cyan().to_string()
        ));
        output.push_str(&format!(
            "Policy Evaluation: {} v{}\n",
            self.policy_name.bold(),
            self.policy_version
        ));
        output.push_str(&format!(
            "{}\n",
            "=".repeat(60).cyan().to_string()
        ));
        output.push_str(&format!("Target: {}\n", self.target.green()));
        output.push_str(&format!(
            "Evaluation Time: {}\n",
            self.evaluation_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        let result_str = match self.summary.overall_result {
            PolicyOverallResult::Pass => format!(
                "Result: {} ({} violations)",
                "PASS".green().bold(),
                self.violations.len()
            ),
            PolicyOverallResult::Fail => format!(
                "Result: {} ({} violations)",
                "FAIL".red().bold(),
                self.violations.len()
            ),
            PolicyOverallResult::Warning => format!(
                "Result: {} ({} violations)",
                "WARNING".yellow().bold(),
                self.violations.len()
            ),
        };
        output.push_str(&format!("{}\n", result_str));

        if !self.violations.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "Violations:".yellow().bold().to_string()
            ));
            output.push_str(&format!("{}\n", "-".repeat(60)));

            for violation in &self.violations {
                let action_str = match violation.action {
                    PolicyAction::Fail => "[FAIL]".red().bold(),
                    PolicyAction::Warn => "[WARN]".yellow(),
                    PolicyAction::Info => "[INFO]".cyan(),
                };

                output.push_str(&format!("\n{} {}\n", action_str, violation.rule_path.bold()));
                output.push_str(&format!("  Rule: {}\n", violation.rule_name));
                output.push_str(&format!("  Description: {}\n", violation.description));
                if let Some(ref evidence) = violation.evidence {
                    output.push_str(&format!("  Evidence: {}\n", evidence.dimmed()));
                }
                if let Some(ref remediation) = violation.remediation {
                    output.push_str(&format!("  Remediation: {}\n", remediation.green()));
                }
            }
        }

        if !self.exceptions_applied.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "Exceptions Applied:".cyan().to_string()
            ));
            output.push_str(&format!("{}\n", "-".repeat(60)));
            for exception in &self.exceptions_applied {
                output.push_str(&format!("  {}\n", exception));
            }
        } else {
            output.push_str(&format!(
                "\n{}\n",
                "Exceptions Applied:".cyan().to_string()
            ));
            output.push_str(&format!("{}\n", "-".repeat(60)));
            output.push_str("None\n");
        }

        output.push_str(&format!("\n{}\n", "Summary:".cyan().to_string()));
        output.push_str(&format!("  Total Checks: {}\n", self.summary.total_checks));
        output.push_str(&format!(
            "  {} Passed: {}\n",
            "✓".green(),
            self.summary.passed.to_string().green()
        ));
        output.push_str(&format!(
            "  {} Failed: {}\n",
            "✗".red(),
            self.summary.failed.to_string().red()
        ));
        output.push_str(&format!(
            "  {} Warnings: {}\n",
            "⚠".yellow(),
            self.summary.warnings.to_string().yellow()
        ));

        let exit_code_msg = if self.has_violations() {
            "Exit Code: 1 (FAIL)".red().bold()
        } else {
            "Exit Code: 0 (PASS)".green().bold()
        };
        output.push_str(&format!("\n{}\n", exit_code_msg));

        Ok(output)
    }

    /// Format as CSV
    fn to_csv(&self) -> crate::Result<String> {
        let mut output = String::new();
        output.push_str("Rule Path,Rule Name,Action,Description,Evidence,Remediation\n");

        for violation in &self.violations {
            output.push_str(&format!(
                "\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",\"{}\"\n",
                violation.rule_path,
                violation.rule_name,
                violation.action,
                violation.description.replace('"', "\"\""),
                violation
                    .evidence
                    .as_ref()
                    .unwrap_or(&String::new())
                    .replace('"', "\"\""),
                violation
                    .remediation
                    .as_ref()
                    .unwrap_or(&String::new())
                    .replace('"', "\"\"")
            ));
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_action_is_failure() {
        assert!(PolicyAction::Fail.is_failure());
        assert!(!PolicyAction::Warn.is_failure());
        assert!(!PolicyAction::Info.is_failure());
    }

    #[test]
    fn test_policy_result_has_violations() {
        let policy = Policy {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: None,
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: None,
            compliance: None,
            exceptions: Vec::new(),
        };

        let result = PolicyResult::new(policy, Vec::new());
        assert!(!result.has_violations());
    }
}
