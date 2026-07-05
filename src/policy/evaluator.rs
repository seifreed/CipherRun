// Policy evaluator - Main policy enforcement engine

use crate::Result;
use crate::application::ScanAssessment;
use crate::policy::exceptions::ExceptionMatcher;
use crate::policy::rules::{certificate::*, cipher::*, protocol::*, vulnerability::*};
use crate::policy::violation::PolicyViolation;
use crate::policy::{Policy, PolicyResult};
use crate::rating::Grade;
use chrono::Utc;

/// Policy evaluator
pub struct PolicyEvaluator {
    policy: Policy,
    exception_matcher: ExceptionMatcher,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new(policy: Policy) -> Self {
        let exception_matcher = ExceptionMatcher::new(policy.exceptions.clone());
        Self {
            policy,
            exception_matcher,
        }
    }

    /// Evaluate scan results against the policy
    pub fn evaluate(&self, results: &ScanAssessment) -> Result<PolicyResult> {
        let mut violations = Vec::new();
        let mut exceptions_applied = Vec::new();
        let target = &results.target;

        // Check protocols
        if let Some(ref protocol_policy) = self.policy.protocols {
            let proto_violations = self.check_protocols(protocol_policy, results, target)?;
            violations.extend(self.apply_exceptions(
                proto_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Check ciphers
        if let Some(ref cipher_policy) = self.policy.ciphers {
            let cipher_violations = self.check_ciphers(cipher_policy, results, target)?;
            violations.extend(self.apply_exceptions(
                cipher_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Check certificates
        if let Some(ref cert_policy) = self.policy.certificates {
            let cert_violations = self.check_certificates(cert_policy, results, target)?;
            violations.extend(self.apply_exceptions(
                cert_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Check vulnerabilities
        if let Some(ref vuln_policy) = self.policy.vulnerabilities {
            let vuln_violations = self.check_vulnerabilities(vuln_policy, results, target)?;
            violations.extend(self.apply_exceptions(
                vuln_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Check rating
        if let Some(ref rating_policy) = self.policy.rating {
            let rating_violations = self.check_rating(rating_policy, results, target)?;
            violations.extend(self.apply_exceptions(
                rating_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Check compliance frameworks
        if let Some(ref compliance_policy) = self.policy.compliance {
            let compliance_violations = self.check_compliance(compliance_policy, results)?;
            violations.extend(self.apply_exceptions(
                compliance_violations,
                target,
                &mut exceptions_applied,
            ));
        }

        // Build result
        let mut result = PolicyResult::new(self.policy.clone(), violations);
        result.target = target.clone();
        result.evaluation_time = Utc::now();
        result.exceptions_applied = exceptions_applied;

        Ok(result)
    }

    /// Check protocol policy
    fn check_protocols(
        &self,
        policy: &crate::policy::ProtocolPolicy,
        results: &ScanAssessment,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = ProtocolRule::new(policy, &results.protocols, &results.any_supported_protocols);
        rule.evaluate(&results.target)
    }

    /// Check cipher policy
    fn check_ciphers(
        &self,
        policy: &crate::policy::CipherPolicy,
        results: &ScanAssessment,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = CipherRule::new(policy, &results.ciphers);
        rule.evaluate(&results.target)
    }

    /// Check certificate policy
    fn check_certificates(
        &self,
        policy: &crate::policy::CertificatePolicy,
        results: &ScanAssessment,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = CertificateRule::new(policy, results.certificate_chain.as_ref());
        rule.evaluate(&results.target)
    }

    /// Check vulnerability policy
    fn check_vulnerabilities(
        &self,
        policy: &crate::policy::VulnerabilityPolicy,
        results: &ScanAssessment,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = VulnerabilityRule::new(policy, &results.vulnerabilities);
        rule.evaluate(&results.target)
    }

    /// Check rating policy
    fn check_rating(
        &self,
        policy: &crate::policy::RatingPolicy,
        results: &ScanAssessment,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        if let Some(rating) = results.ssl_rating() {
            // Check minimum grade
            if let Some(ref min_grade_str) = policy.min_grade {
                let min_grade =
                    self.parse_grade(min_grade_str)
                        .map_err(|_| crate::TlsError::ConfigError {
                            message: format!(
                                "Invalid min_grade '{}' in policy rating configuration",
                                min_grade_str
                            ),
                        })?;
                if rating.grade < min_grade {
                    violations.push(
                        PolicyViolation::new(
                            "rating.min_grade",
                            "Minimum SSL Labs Grade",
                            policy.action,
                            format!(
                                "SSL Labs grade {} is below minimum {}",
                                rating.grade, min_grade_str
                            ),
                        )
                        .with_evidence(format!(
                            "Current grade: {} (score: {})",
                            rating.grade, rating.score
                        ))
                        .with_remediation(format!(
                            "Improve TLS configuration to achieve grade {}",
                            min_grade_str
                        )),
                    );
                }
            }

            // Check minimum score
            if let Some(min_score) = policy.min_score
                && u32::from(rating.score) < min_score
            {
                violations.push(
                    PolicyViolation::new(
                        "rating.min_score",
                        "Minimum SSL Labs Score",
                        policy.action,
                        format!(
                            "SSL Labs score {} is below minimum {}",
                            rating.score, min_score
                        ),
                    )
                    .with_evidence(format!(
                        "Current score: {} (grade: {})",
                        rating.score, rating.grade
                    ))
                    .with_remediation(format!(
                        "Improve TLS configuration to achieve score {}",
                        min_score
                    )),
                );
            }
        } else {
            if let Some(ref min_grade_str) = policy.min_grade {
                violations.push(
                    PolicyViolation::new(
                        "rating.min_grade",
                        "Minimum SSL Labs Grade",
                        policy.action,
                        format!(
                            "SSL Labs grade is required but no rating result is available (minimum: {})",
                            min_grade_str
                        ),
                    )
                    .with_evidence("No SSL Labs rating result available")
                    .with_remediation("Run a scan mode that calculates SSL Labs rating"),
                );
            }

            if let Some(min_score) = policy.min_score {
                violations.push(
                    PolicyViolation::new(
                        "rating.min_score",
                        "Minimum SSL Labs Score",
                        policy.action,
                        format!(
                            "SSL Labs score is required but no rating result is available (minimum: {})",
                            min_score
                        ),
                    )
                    .with_evidence("No SSL Labs rating result available")
                    .with_remediation("Run a scan mode that calculates SSL Labs rating"),
                );
            }
        }

        Ok(violations)
    }

    /// Check compliance-framework policy.
    ///
    /// Each named framework is evaluated against the scan assessment via the
    /// compliance engine. Semantics:
    /// - `require_all` = true: every listed framework must be compliant; each
    ///   framework that hard-fails (overall status Fail) yields one violation.
    /// - `require_all` = false: the target passes as long as at least one
    ///   framework is compliant; a single aggregated violation is emitted only
    ///   when every listed framework hard-fails.
    ///
    /// A Warning status (only advisory requirements unmet) satisfies the gate.
    /// An unknown framework id is a configuration error (fail-closed).
    fn check_compliance(
        &self,
        policy: &crate::policy::CompliancePolicy,
        results: &ScanAssessment,
    ) -> Result<Vec<PolicyViolation>> {
        use crate::application::ComplianceFrameworkSource;
        use crate::compliance::{BuiltinFrameworkSource, ComplianceEngine};

        let source = BuiltinFrameworkSource;
        let mut evaluated = Vec::with_capacity(policy.frameworks.len());

        for framework_id in &policy.frameworks {
            let framework =
                source
                    .load_framework(framework_id)
                    .map_err(|e| crate::TlsError::ConfigError {
                        message: format!(
                            "Policy compliance framework '{}' could not be loaded: {}",
                            framework_id, e
                        ),
                    })?;
            let report = ComplianceEngine::new(framework).evaluate(results)?;
            evaluated.push((framework_id.as_str(), report));
        }

        let mut violations = Vec::new();

        if policy.require_all {
            for (framework_id, report) in &evaluated {
                if Self::compliance_report_hard_fails(report) {
                    violations.push(Self::compliance_violation(
                        framework_id,
                        report,
                        policy.action,
                    ));
                }
            }
        } else if !evaluated.is_empty()
            && evaluated
                .iter()
                .all(|(_, report)| Self::compliance_report_hard_fails(report))
        {
            let names = evaluated
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
                .join(", ");
            violations.push(
                PolicyViolation::new(
                    "compliance.frameworks",
                    "Compliance frameworks",
                    policy.action,
                    format!(
                        "Target does not comply with any of the required frameworks: {}",
                        names
                    ),
                )
                .with_remediation(
                    "Bring the TLS configuration into compliance with at least one required framework",
                ),
            );
        }

        Ok(violations)
    }

    fn compliance_report_hard_fails(report: &crate::compliance::ComplianceReport) -> bool {
        report.overall_status == crate::compliance::ComplianceStatus::Fail
    }

    fn compliance_violation(
        framework_id: &str,
        report: &crate::compliance::ComplianceReport,
        action: crate::policy::PolicyAction,
    ) -> PolicyViolation {
        PolicyViolation::new(
            format!("compliance.{}", framework_id),
            format!("Compliance: {}", report.framework.name),
            action,
            format!(
                "Target is not compliant with framework '{}' ({} of {} requirements failed)",
                framework_id, report.summary.failed, report.summary.total
            ),
        )
        .with_evidence(format!(
            "{} passed, {} failed, {} warnings, {} not applicable",
            report.summary.passed,
            report.summary.failed,
            report.summary.warnings,
            report.summary.not_applicable
        ))
        .with_remediation(format!(
            "Remediate the {} failed requirement(s) to achieve {} compliance",
            report.summary.failed, report.framework.name
        ))
    }

    /// Parse grade string to Grade enum
    fn parse_grade(&self, grade_str: &str) -> Result<Grade> {
        match grade_str {
            "A+" => Ok(Grade::APlus),
            "A" => Ok(Grade::A),
            "A-" => Ok(Grade::AMinus),
            "B" => Ok(Grade::B),
            "C" => Ok(Grade::C),
            "D" => Ok(Grade::D),
            "E" => Ok(Grade::E),
            "F" => Ok(Grade::F),
            "T" => Ok(Grade::T),
            "M" => Ok(Grade::M),
            _ => Err(crate::TlsError::ConfigError {
                message: format!("Invalid grade: {}", grade_str),
            }),
        }
    }

    /// Apply exceptions to violations
    fn apply_exceptions(
        &self,
        violations: Vec<PolicyViolation>,
        target: &str,
        exceptions_applied: &mut Vec<String>,
    ) -> Vec<PolicyViolation> {
        violations
            .into_iter()
            .filter(|violation| {
                if let Some(exception) = self
                    .exception_matcher
                    .is_exception(target, &violation.rule_path)
                {
                    // Exception applies - filter out this violation
                    let exception_msg = ExceptionMatcher::format_exception(exception);
                    exceptions_applied.push(format!("{}: {}", violation.rule_path, exception_msg));
                    false
                } else {
                    // No exception - keep the violation
                    true
                }
            })
            .collect()
    }
}

/// Default implementation of PolicyEvaluatorPort using PolicyEvaluator.
pub struct DefaultPolicyEvaluator;

impl crate::application::PolicyEvaluatorPort for DefaultPolicyEvaluator {
    fn evaluate(
        &self,
        policy: &Policy,
        assessment: &ScanAssessment,
    ) -> crate::Result<PolicyResult> {
        let evaluator = PolicyEvaluator::new(policy.clone());
        evaluator.evaluate(assessment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::*;
    use crate::protocols::{Protocol, ProtocolTestResult};

    #[test]
    fn test_evaluator_with_violations() {
        let policy = Policy {
            name: "Test Policy".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: Some(ProtocolPolicy {
                required: Some(vec!["TLSv1.3".to_string()]),
                prohibited: None,
                action: PolicyAction::Fail,
            }),
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: None,
            compliance: None,
            exceptions: Vec::new(),
        };

        let mut results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        results.protocols = vec![ProtocolTestResult {
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
        }];

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert!(result.has_violations());
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_evaluator_summary_counts_passing_configured_checks() {
        let policy = Policy {
            name: "Test Policy".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: Some(ProtocolPolicy {
                required: Some(vec!["TLSv1.2".to_string()]),
                prohibited: None,
                action: PolicyAction::Fail,
            }),
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: None,
            compliance: None,
            exceptions: Vec::new(),
        };

        let mut results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        results.protocols = vec![ProtocolTestResult {
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
        }];

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert!(!result.has_violations());
        assert!(result.violations.is_empty());
        assert_eq!(result.summary.total_checks, 1);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 0);
    }

    #[test]
    fn test_evaluator_with_exceptions() {
        let policy = Policy {
            name: "Test Policy".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: Some(ProtocolPolicy {
                required: Some(vec!["TLSv1.3".to_string()]),
                prohibited: None,
                action: PolicyAction::Fail,
            }),
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: None,
            compliance: None,
            exceptions: vec![PolicyException {
                domain: Some("example.com".to_string()),
                rules: vec!["protocols.required".to_string()],
                reason: "Test exception".to_string(),
                expires: None,
                approved_by: "Admin".to_string(),
                ticket: None,
            }],
        };

        let mut results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        results.protocols = vec![ProtocolTestResult {
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
        }];

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator
            .evaluate(&results)
            .expect("test assertion should succeed");

        // Violation should be filtered out by exception
        assert!(!result.has_violations());
        assert!(!result.exceptions_applied.is_empty());
    }

    #[test]
    fn test_parse_grade_invalid() {
        let policy = Policy {
            name: "Test Policy".to_string(),
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

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator.parse_grade("Z");
        assert!(result.is_err());
    }

    #[test]
    fn test_rating_min_score_violation() {
        let policy = Policy {
            name: "Test Policy".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: None,
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: Some(crate::policy::RatingPolicy {
                min_grade: None,
                min_score: Some(90),
                action: PolicyAction::Fail,
            }),
            compliance: None,
            exceptions: Vec::new(),
        };

        let mut results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        results.rating = Some(crate::rating::scoring::RatingResult {
            grade: Grade::B,
            score: 70,
            certificate_score: 80,
            protocol_score: 70,
            key_exchange_score: 70,
            cipher_strength_score: 70,
            warnings: vec![],
        });

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert!(result.has_violations());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_path == "rating.min_score")
        );
    }

    #[test]
    fn test_missing_rating_fails_configured_rating_checks() {
        let policy = Policy {
            name: "Test Policy".to_string(),
            version: "1.0".to_string(),
            description: None,
            organization: None,
            effective_date: None,
            extends: None,
            protocols: None,
            ciphers: None,
            certificates: None,
            vulnerabilities: None,
            rating: Some(crate::policy::RatingPolicy {
                min_grade: Some("A".to_string()),
                min_score: Some(90),
                action: PolicyAction::Fail,
            }),
            compliance: None,
            exceptions: Vec::new(),
        };
        let results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator
            .evaluate(&results)
            .expect("test assertion should succeed");

        assert!(result.has_violations());
        assert_eq!(result.summary.total_checks, 2);
        assert_eq!(result.summary.failed, 2);
        assert_eq!(result.summary.passed, 0);
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_path == "rating.min_grade")
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_path == "rating.min_score")
        );
    }

    fn assessment_with_sslv2() -> ScanAssessment {
        let mut results = ScanAssessment {
            target: "example.com:443".to_string(),
            ..Default::default()
        };
        results.protocols = vec![ProtocolTestResult {
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
        }];
        results
    }

    fn policy_with_compliance(frameworks: Vec<String>, require_all: bool) -> Policy {
        Policy {
            name: "Test Policy".to_string(),
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
            compliance: Some(CompliancePolicy {
                frameworks,
                require_all,
                action: PolicyAction::Fail,
            }),
            exceptions: Vec::new(),
        }
    }

    #[test]
    fn test_compliance_policy_flags_noncompliant_target() {
        let policy = policy_with_compliance(vec!["pci-dss-v4".to_string()], true);
        let evaluator = PolicyEvaluator::new(policy);

        let result = evaluator
            .evaluate(&assessment_with_sslv2())
            .expect("evaluation should succeed");

        assert!(result.has_violations());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_path == "compliance.pci-dss-v4"),
            "expected a compliance violation for the non-compliant framework"
        );
    }

    #[test]
    fn test_compliance_policy_unknown_framework_is_config_error() {
        let policy = policy_with_compliance(vec!["does-not-exist".to_string()], true);
        let evaluator = PolicyEvaluator::new(policy);

        let err = evaluator
            .evaluate(&assessment_with_sslv2())
            .expect_err("unknown framework should be a configuration error");
        assert!(err.to_string().contains("does-not-exist"));
    }

    #[test]
    fn test_compliance_require_all_false_aggregates_when_all_fail() {
        let policy = policy_with_compliance(
            vec!["pci-dss-v4".to_string(), "nist-sp800-52r2".to_string()],
            false,
        );
        let evaluator = PolicyEvaluator::new(policy);

        let result = evaluator
            .evaluate(&assessment_with_sslv2())
            .expect("evaluation should succeed");

        assert!(result.has_violations());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule_path == "compliance.frameworks"),
            "expected a single aggregated violation when no framework passes"
        );
    }

    #[test]
    fn test_parse_grade_valid() {
        let policy = Policy {
            name: "Test Policy".to_string(),
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

        let evaluator = PolicyEvaluator::new(policy);
        let grade = evaluator.parse_grade("A+").expect("grade should parse");
        assert_eq!(grade, Grade::APlus);
    }
}
