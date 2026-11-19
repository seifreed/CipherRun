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
                    return Err(crate::TlsError::ConfigError {
                        message: format!(
                            "Unknown compliance rule type '{}' in requirement '{}'",
                            rule.rule_type, requirement.id
                        ),
                    });
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
    use crate::ciphers::{CipherSuite, ProtocolCipherSummary, tester::CipherCounts};
    use crate::compliance::test_support::base_rule;
    use crate::compliance::{ComplianceFramework, Requirement, Rule};
    use crate::protocols::test_support::supported_protocol_result as protocol_result;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use std::collections::HashMap;

    fn test_framework(requirement_id: &str, rules: Vec<Rule>) -> ComplianceFramework {
        ComplianceFramework {
            id: "test".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            organization: "Test Org".to_string(),
            effective_date: None,
            requirements: vec![Requirement {
                id: requirement_id.to_string(),
                name: "No SSLv2".to_string(),
                description: "SSLv2 must not be enabled".to_string(),
                category: "Protocol Security".to_string(),
                severity: Severity::Critical,
                remediation: "Disable SSLv2".to_string(),
                rules,
            }],
        }
    }

    fn deny_sslv2_rule() -> Rule {
        Rule {
            denied: vec!["SSLv2".to_string()],
            ..base_rule("ProtocolVersion")
        }
    }

    fn assessment(protocols: Vec<ProtocolTestResult>) -> ScanAssessment {
        ScanAssessment {
            target: "test.com:443".to_string(),
            protocols,
            ..Default::default()
        }
    }

    #[test]
    fn test_compliance_engine_evaluation() {
        let framework = test_framework("TEST-1", vec![deny_sslv2_rule()]);

        let engine = ComplianceEngine::new(framework);

        let results = assessment(vec![
            protocol_result(Protocol::SSLv2),
            protocol_result(Protocol::TLS12),
        ]);

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
        let framework = test_framework("TEST-1", vec![deny_sslv2_rule()]);

        let engine = ComplianceEngine::new(framework);

        let results = assessment(vec![protocol_result(Protocol::TLS12)]);

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
    fn test_unknown_rule_type_fails_evaluation() {
        let framework = test_framework(
            "MIXED-1",
            vec![base_rule("TotallyBogusRuleType"), deny_sslv2_rule()],
        );

        let engine = ComplianceEngine::new(framework);
        let results = assessment(vec![protocol_result(Protocol::TLS12)]);

        let err = engine
            .evaluate(&results)
            .expect_err("unknown rule type should fail compliance evaluation");
        assert!(err.to_string().contains("Unknown compliance rule type"));
    }

    #[test]
    fn test_engine_dispatches_every_supported_rule_type() {
        let rule_types = [
            "ProtocolVersion",
            "CipherSuite",
            "CertificateKeySize",
            "SignatureAlgorithm",
            "ForwardSecrecy",
            "CertificateValidation",
            "CertificateExpiration",
            "Vulnerability",
        ];
        let framework =
            test_framework("ALL-RULES", rule_types.into_iter().map(base_rule).collect());
        let engine = ComplianceEngine::new(framework);

        assert_eq!(engine.framework().id, "test");
        let report = engine
            .evaluate(&assessment(Vec::new()))
            .expect("all known rule types should dispatch");
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.passed, 1);
    }

    #[test]
    fn test_medium_compliance_violations_are_warnings() {
        let rule = Rule {
            preferred_patterns: vec!["GCM".to_string()],
            ..base_rule("CipherSuite")
        };
        let framework = test_framework("PREFERRED-CIPHER", vec![rule]);
        let engine = ComplianceEngine::new(framework);
        let protocol = Protocol::TLS12;
        let cipher = CipherSuite {
            hexcode: "0x002f".to_string(),
            openssl_name: "ECDHE-RSA-AES128-SHA".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES".to_string(),
            mac: "SHA".to_string(),
            bits: 128,
            export: false,
        };
        let results = ScanAssessment {
            ciphers: HashMap::from([(
                protocol,
                ProtocolCipherSummary {
                    protocol,
                    supported_ciphers: vec![cipher],
                    server_ordered: false,
                    server_preference: Vec::new(),
                    preferred_cipher: None,
                    counts: CipherCounts::default(),
                    avg_handshake_time_ms: None,
                },
            )]),
            ..assessment(Vec::new())
        };

        let report = engine
            .evaluate(&results)
            .expect("warning should be reported");
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.requirements[0].status, RequirementStatus::Warning);
    }
}
