use super::{ComplianceFramework, Rule};
use std::collections::HashMap;

pub(crate) fn base_rule(rule_type: &str) -> Rule {
    Rule {
        rule_type: rule_type.to_string(),
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
        require_revocation_check: None,
        max_days_until_expiration: None,
        custom_params: HashMap::new(),
    }
}

pub(crate) fn test_framework() -> ComplianceFramework {
    ComplianceFramework {
        id: "test".to_string(),
        name: "Test Framework".to_string(),
        version: "1.0".to_string(),
        description: "Test".to_string(),
        organization: "Test Org".to_string(),
        effective_date: None,
        requirements: vec![],
    }
}
