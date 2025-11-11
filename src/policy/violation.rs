// Policy violation reporting

use crate::policy::PolicyAction;
use serde::{Deserialize, Serialize};

/// Represents a policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule_path: String, // e.g., "protocols.prohibited"
    pub rule_name: String, // e.g., "Prohibited Protocol Check"
    pub action: PolicyAction,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
}

impl PolicyViolation {
    pub fn new(
        rule_path: impl Into<String>,
        rule_name: impl Into<String>,
        action: PolicyAction,
        description: impl Into<String>,
    ) -> Self {
        Self {
            rule_path: rule_path.into(),
            rule_name: rule_name.into(),
            action,
            description: description.into(),
            evidence: None,
            remediation: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_violation_builder() {
        let violation = PolicyViolation::new(
            "protocols.prohibited",
            "Prohibited Protocol",
            PolicyAction::Fail,
            "TLS 1.0 is prohibited",
        )
        .with_evidence("Server accepts TLS 1.0")
        .with_remediation("Disable TLS 1.0 in server configuration");

        assert_eq!(violation.rule_path, "protocols.prohibited");
        assert_eq!(violation.rule_name, "Prohibited Protocol");
        assert!(violation.evidence.is_some());
        assert!(violation.remediation.is_some());
    }
}
