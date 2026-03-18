// Policy rules module

pub mod certificate;
pub mod cipher;
pub mod protocol;
pub mod vulnerability;

use crate::Result;
use crate::policy::violation::PolicyViolation;

/// Trait for policy rules
pub trait PolicyRule {
    /// Evaluate the rule against scan results
    fn evaluate(&self, target: &str) -> Result<Vec<PolicyViolation>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyAction;

    struct DummyRule;

    impl PolicyRule for DummyRule {
        fn evaluate(&self, target: &str) -> Result<Vec<PolicyViolation>> {
            Ok(vec![PolicyViolation::new(
                "rules.dummy",
                "Dummy Rule",
                PolicyAction::Warn,
                format!("Triggered for {}", target),
            )])
        }
    }

    #[test]
    fn test_policy_rule_evaluate_returns_violation() {
        let rule = DummyRule;
        let results = rule
            .evaluate("example.com")
            .expect("test assertion should succeed");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_path, "rules.dummy");
        assert!(results[0].description.contains("example.com"));
    }

    struct EmptyRule;

    impl PolicyRule for EmptyRule {
        fn evaluate(&self, _target: &str) -> Result<Vec<PolicyViolation>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn test_policy_rule_empty_results() {
        let rule = EmptyRule;
        let results = rule
            .evaluate("example.com")
            .expect("test assertion should succeed");
        assert!(results.is_empty());
    }
}
