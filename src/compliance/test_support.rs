use super::Rule;
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
