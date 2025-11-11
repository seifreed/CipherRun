// Policy evaluator - Main policy enforcement engine

use crate::Result;
use crate::policy::exceptions::ExceptionMatcher;
use crate::policy::rules::{certificate::*, cipher::*, protocol::*, vulnerability::*};
use crate::policy::violation::PolicyViolation;
use crate::policy::{Policy, PolicyResult};
use crate::rating::Grade;
use crate::scanner::ScanResults;
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
    pub fn evaluate(&self, results: &ScanResults) -> Result<PolicyResult> {
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
        results: &ScanResults,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = ProtocolRule::new(policy, &results.protocols);
        rule.evaluate(&results.target)
    }

    /// Check cipher policy
    fn check_ciphers(
        &self,
        policy: &crate::policy::CipherPolicy,
        results: &ScanResults,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = CipherRule::new(policy, &results.ciphers);
        rule.evaluate(&results.target)
    }

    /// Check certificate policy
    fn check_certificates(
        &self,
        policy: &crate::policy::CertificatePolicy,
        results: &ScanResults,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = CertificateRule::new(policy, results.certificate_chain.as_ref());
        rule.evaluate(&results.target)
    }

    /// Check vulnerability policy
    fn check_vulnerabilities(
        &self,
        policy: &crate::policy::VulnerabilityPolicy,
        results: &ScanResults,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let rule = VulnerabilityRule::new(policy, &results.vulnerabilities);
        rule.evaluate(&results.target)
    }

    /// Check rating policy
    fn check_rating(
        &self,
        policy: &crate::policy::RatingPolicy,
        results: &ScanResults,
        _target: &str,
    ) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        if let Some(ref rating) = results.rating {
            // Check minimum grade
            if let Some(ref min_grade_str) = policy.min_grade {
                let min_grade = self.parse_grade(min_grade_str)?;
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
        }

        Ok(violations)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::*;
    use crate::protocols::{Protocol, ProtocolTestResult};
    use std::collections::HashMap;

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

        let results = ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ciphers: HashMap::new(),
            certificate_chain: None,
            http_headers: None,
            vulnerabilities: Vec::new(),
            client_simulations: None,
            rating: None,
            scan_time_ms: 1000,
            signature_algorithms: None,
            key_exchange_groups: None,
            client_cas: None,
            intolerance: None,
            ja3_fingerprint: None,
            ja3_match: None,
            ct_log_source: None,
            ct_log_index: None,
            client_hello_raw: None,
            ja3s_fingerprint: None,
            ja3s_match: None,
            cdn_detection: None,
            load_balancer_info: None,
            server_hello_raw: None,
            pre_handshake_used: false,
            scanned_ips: Vec::new(),
            jarm_fingerprint: None,
            sni_used: None,
            sni_generation_method: None,
            probe_status: crate::output::probe_status::ProbeStatus::default(),
            alpn_result: None,
        };

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator.evaluate(&results).unwrap();

        assert!(result.has_violations());
        assert!(!result.violations.is_empty());
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

        let results = ScanResults {
            target: "example.com:443".to_string(),
            protocols: vec![ProtocolTestResult {
                protocol: Protocol::TLS12,
                supported: true,
                preferred: false,
                ciphers_count: 0,
                heartbeat_enabled: None,
                handshake_time_ms: None,
                session_resumption_caching: None,
                session_resumption_tickets: None,
                secure_renegotiation: None,
            }],
            ciphers: HashMap::new(),
            certificate_chain: None,
            http_headers: None,
            vulnerabilities: Vec::new(),
            client_simulations: None,
            rating: None,
            scan_time_ms: 1000,
            signature_algorithms: None,
            key_exchange_groups: None,
            client_cas: None,
            intolerance: None,
            ja3_fingerprint: None,
            ja3_match: None,
            ct_log_source: None,
            ct_log_index: None,
            client_hello_raw: None,
            ja3s_fingerprint: None,
            ja3s_match: None,
            cdn_detection: None,
            load_balancer_info: None,
            server_hello_raw: None,
            pre_handshake_used: false,
            scanned_ips: Vec::new(),
            jarm_fingerprint: None,
            sni_used: None,
            sni_generation_method: None,
            probe_status: crate::output::probe_status::ProbeStatus::default(),
            alpn_result: None,
        };

        let evaluator = PolicyEvaluator::new(policy);
        let result = evaluator.evaluate(&results).unwrap();

        // Violation should be filtered out by exception
        assert!(!result.has_violations());
        assert!(!result.exceptions_applied.is_empty());
    }
}
