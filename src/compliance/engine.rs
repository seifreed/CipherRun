// Compliance engine - Orchestrates compliance evaluation

use crate::compliance::{
    ComplianceChecker, ComplianceFramework, ComplianceReport, Requirement, RequirementResult,
    RequirementStatus, Severity, Violation,
};
use crate::scanner::ScanResults;
use anyhow::Result;

/// Compliance engine that evaluates scan results against a framework
pub struct ComplianceEngine {
    framework: ComplianceFramework,
}

impl ComplianceEngine {
    /// Create a new compliance engine for a specific framework
    pub fn new(framework: ComplianceFramework) -> Self {
        Self { framework }
    }

    /// Evaluate scan results against the framework
    pub fn evaluate(&self, results: &ScanResults) -> Result<ComplianceReport> {
        let mut report = ComplianceReport::new(&self.framework, results.target.clone());

        for requirement in &self.framework.requirements {
            let violations = self.evaluate_requirement(requirement, results)?;

            let status = if violations.is_empty() {
                RequirementStatus::Pass
            } else {
                // Check if any violation is critical
                let has_critical = violations
                    .iter()
                    .any(|v| matches!(v.severity, Severity::Critical));

                if has_critical {
                    RequirementStatus::Fail
                } else {
                    RequirementStatus::Warning
                }
            };

            report.add_requirement_result(RequirementResult {
                requirement_id: requirement.id.clone(),
                name: requirement.name.clone(),
                description: requirement.description.clone(),
                category: requirement.category.clone(),
                severity: requirement.severity,
                status,
                violations,
                remediation: requirement.remediation.clone(),
            });
        }

        report.finalize();
        Ok(report)
    }

    /// Evaluate a single requirement
    fn evaluate_requirement(
        &self,
        requirement: &Requirement,
        results: &ScanResults,
    ) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();

        for rule in &requirement.rules {
            let rule_violations = match rule.rule_type.as_str() {
                "ProtocolVersion" => ComplianceChecker::check_protocols(rule, results)?,
                "CipherSuite" => ComplianceChecker::check_ciphers(rule, results)?,
                "CertificateKeySize" => ComplianceChecker::check_key_size(rule, results)?,
                "SignatureAlgorithm" => ComplianceChecker::check_signature(rule, results)?,
                "ForwardSecrecy" => ComplianceChecker::check_forward_secrecy(rule, results)?,
                "CertificateValidation" => ComplianceChecker::check_cert_validation(rule, results)?,
                "CertificateExpiration" => ComplianceChecker::check_cert_expiration(rule, results)?,
                "Vulnerability" => ComplianceChecker::check_vulnerabilities(rule, results)?,
                _ => {
                    // Unknown rule type - log warning and skip
                    eprintln!("Warning: Unknown rule type: {}", rule.rule_type);
                    vec![]
                }
            };

            violations.extend(rule_violations);
        }

        Ok(violations)
    }

    /// Get the framework being used
    pub fn framework(&self) -> &ComplianceFramework {
        &self.framework
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::{ComplianceFramework, Requirement, Rule};
    use crate::protocols::{Protocol, ProtocolTestResult};
    use std::collections::HashMap;

    #[test]
    fn test_compliance_engine_evaluation() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![Requirement {
                id: "TEST-1".to_string(),
                name: "No SSLv2".to_string(),
                description: "SSLv2 must not be enabled".to_string(),
                category: "Protocol Security".to_string(),
                severity: Severity::Critical,
                remediation: "Disable SSLv2".to_string(),
                rules: vec![Rule {
                    rule_type: "ProtocolVersion".to_string(),
                    allowed: vec![],
                    denied: vec!["SSLv2".to_string()],
                    allowed_patterns: vec![],
                    denied_patterns: vec![],
                    preferred_patterns: vec![],
                    min_rsa_bits: None,
                    min_ecc_bits: None,
                    required: None,
                    require_valid_chain: None,
                    require_unexpired: None,
                    require_hostname_match: None,
                    max_days_until_expiration: None,
                    custom_params: HashMap::new(),
                }],
            }],
        };

        let engine = ComplianceEngine::new(framework);

        let mut results = ScanResults::default();
        results.target = "test.com:443".to_string();
        results.protocols = vec![
            ProtocolTestResult {
                protocol: Protocol::SSLv2,
                supported: true,
                heartbeat_enabled: None,
                handshake_time_ms: None,
            },
            ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                heartbeat_enabled: None,
                handshake_time_ms: None,
            },
        ];

        let report = engine.evaluate(&results).unwrap();

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.overall_status, crate::compliance::ComplianceStatus::Fail);
    }

    #[test]
    fn test_compliance_engine_pass() {
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![Requirement {
                id: "TEST-1".to_string(),
                name: "No SSLv2".to_string(),
                description: "SSLv2 must not be enabled".to_string(),
                category: "Protocol Security".to_string(),
                severity: Severity::Critical,
                remediation: "Disable SSLv2".to_string(),
                rules: vec![Rule {
                    rule_type: "ProtocolVersion".to_string(),
                    allowed: vec![],
                    denied: vec!["SSLv2".to_string()],
                    allowed_patterns: vec![],
                    denied_patterns: vec![],
                    preferred_patterns: vec![],
                    min_rsa_bits: None,
                    min_ecc_bits: None,
                    required: None,
                    require_valid_chain: None,
                    require_unexpired: None,
                    require_hostname_match: None,
                    max_days_until_expiration: None,
                    custom_params: HashMap::new(),
                }],
            }],
        };

        let engine = ComplianceEngine::new(framework);

        let mut results = ScanResults::default();
        results.target = "test.com:443".to_string();
        results.protocols = vec![ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported: true,
            heartbeat_enabled: None,
            handshake_time_ms: None,
        }];

        let report = engine.evaluate(&results).unwrap();

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.overall_status, crate::compliance::ComplianceStatus::Pass);
    }
}
