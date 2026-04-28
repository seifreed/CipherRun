// Compliance engine - Orchestrates compliance evaluation

use crate::Result;
use crate::application::ScanAssessment;
use crate::compliance::{
    ComplianceChecker, ComplianceFramework, ComplianceReport, Requirement, RequirementResult,
    RequirementStatus, Severity, Violation,
};

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
    pub fn evaluate(&self, results: &ScanAssessment) -> Result<ComplianceReport> {
        let mut report = ComplianceReport::new(&self.framework, results.target.clone());

        for requirement in &self.framework.requirements {
            let violations = self.evaluate_requirement(requirement, results)?;

            let status = if violations.is_empty() {
                RequirementStatus::Pass
            } else {
                let has_fail = violations
                    .iter()
                    .any(|v| matches!(v.severity, Severity::Critical | Severity::High));

                if has_fail {
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
        results: &ScanAssessment,
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
                    // I7 fix: previously returning Err aborted the ENTIRE compliance
                    // report for a single unknown rule_type, discarding results from
                    // every valid rule in the framework. Now we log a warning and
                    // treat the unknown rule as producing zero violations so the
                    // rest of the evaluation continues.
                    tracing::warn!(
                        "Unknown compliance rule type '{}' in requirement '{}' — skipping rule",
                        rule.rule_type,
                        requirement.id
                    );
                    Vec::new()
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

/// Default implementation of ComplianceEvaluatorPort using ComplianceEngine.
pub struct DefaultComplianceEvaluator;

impl crate::application::ComplianceEvaluatorPort for DefaultComplianceEvaluator {
    fn evaluate(
        &self,
        framework: &ComplianceFramework,
        assessment: &ScanAssessment,
    ) -> crate::Result<ComplianceReport> {
        let engine = ComplianceEngine::new(framework.clone());
        engine.evaluate(assessment)
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

        let results = ScanAssessment {
            target: "test.com:443".to_string(),
            protocols: vec![
                ProtocolTestResult {
                    protocol: Protocol::SSLv2,
                    supported: true,
                    inconclusive: false,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
                ProtocolTestResult {
                    protocol: Protocol::TLS12,
                    supported: true,
                    inconclusive: false,
                    preferred: false,
                    ciphers_count: 0,
                    heartbeat_enabled: None,
                    handshake_time_ms: None,
                    session_resumption_caching: None,
                    session_resumption_tickets: None,
                    secure_renegotiation: None,
                },
            ],
            ..Default::default()
        };

        let report = engine
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(
            report.overall_status,
            crate::compliance::ComplianceStatus::Fail
        );
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

        let results = ScanAssessment {
            target: "test.com:443".to_string(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ..Default::default()
        };

        let report = engine
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(
            report.overall_status,
            crate::compliance::ComplianceStatus::Pass
        );
    }

    #[test]
    fn test_unknown_rule_type_does_not_abort_report() {
        // I7 regression: a framework with one unknown rule_type and one valid
        // rule must still produce a complete report — the unknown rule is
        // skipped (with a warning) and the valid rule evaluates normally.
        let framework = ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![Requirement {
                id: "MIXED-1".to_string(),
                name: "Mixed rule types".to_string(),
                description: "One unknown, one valid".to_string(),
                category: "Test".to_string(),
                severity: Severity::Medium,
                remediation: "n/a".to_string(),
                rules: vec![
                    Rule {
                        rule_type: "TotallyBogusRuleType".to_string(),
                        allowed: vec![],
                        denied: vec![],
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
                    },
                    Rule {
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
                    },
                ],
            }],
        };

        let engine = ComplianceEngine::new(framework);
        let results = ScanAssessment {
            target: "test.com:443".to_string(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                inconclusive: false,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ..Default::default()
        };

        let report = engine
            .evaluate(&results)
            .expect("unknown rule type must not abort the report");
        assert_eq!(report.summary.total, 1);
        // The valid rule evaluates cleanly; overall passes despite the bogus rule.
        assert_eq!(report.summary.passed, 1);
    }
}
