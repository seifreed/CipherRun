use crate::api::models::response::{PolicyCheckResult, PolicyEvaluationResponse};
use crate::policy::PolicyResult;
use chrono::Utc;
use uuid::Uuid;

pub fn present_policy_evaluation(
    policy_id: String,
    policy_name: String,
    target: String,
    policy_result: &PolicyResult,
) -> PolicyEvaluationResponse {
    PolicyEvaluationResponse {
        policy_id,
        policy_name,
        target,
        compliant: !policy_result.has_violations(),
        checks: policy_result
            .violations
            .iter()
            .map(|violation| PolicyCheckResult {
                check: violation.rule_name.clone(),
                passed: false,
                severity: format!("{:?}", violation.action).to_lowercase(),
                message: Some(violation.description.clone()),
                expected: violation.remediation.clone(),
                actual: violation.evidence.clone(),
            })
            .collect(),
        evaluated_at: Utc::now(),
        scan_id: Uuid::new_v4().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::violation::PolicyViolation;
    use crate::policy::{Policy, PolicyAction, PolicyResult};

    #[test]
    fn maps_policy_violations_to_response_checks() {
        let policy = Policy {
            name: "Baseline".to_string(),
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
        let result = PolicyResult::new(
            policy,
            vec![PolicyViolation {
                rule_path: "protocols.required".to_string(),
                rule_name: "protocols.required".to_string(),
                description: "TLS 1.2 missing".to_string(),
                action: PolicyAction::Fail,
                evidence: Some("tls1.0".to_string()),
                remediation: Some("Enable TLS 1.2+".to_string()),
            }],
        );

        let response = present_policy_evaluation(
            "baseline".to_string(),
            "Baseline".to_string(),
            "example.com:443".to_string(),
            &result,
        );

        assert!(!response.compliant);
        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].check, "protocols.required");
        assert_eq!(response.checks[0].severity, "fail");
    }
}
