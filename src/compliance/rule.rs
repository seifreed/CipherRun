// Rule definitions and types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of compliance rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleType {
    /// Check protocol versions (allowed/denied lists)
    ProtocolVersion,
    /// Check cipher suites (pattern matching)
    CipherSuite,
    /// Check certificate key sizes
    CertificateKeySize,
    /// Check signature algorithms
    SignatureAlgorithm,
    /// Check forward secrecy support
    ForwardSecrecy,
    /// Check certificate validation
    CertificateValidation,
    /// Check certificate expiration
    CertificateExpiration,
    /// Check for vulnerabilities
    Vulnerability,
}

/// A rule that defines how to check compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Type of rule
    #[serde(rename = "type")]
    pub rule_type: String,

    /// Allowed values (for allow-list rules)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,

    /// Denied values (for deny-list rules)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,

    /// Patterns to match (regex patterns for cipher names, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_patterns: Vec<String>,

    /// Patterns to deny (regex patterns for weak ciphers, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_patterns: Vec<String>,

    /// Preferred patterns (not required, but recommended)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferred_patterns: Vec<String>,

    /// Minimum RSA key size in bits
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rsa_bits: Option<u32>,

    /// Minimum ECC key size in bits
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ecc_bits: Option<u32>,

    /// Whether forward secrecy is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Require valid certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_valid_chain: Option<bool>,

    /// Require unexpired certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_unexpired: Option<bool>,

    /// Require hostname match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_hostname_match: Option<bool>,

    /// Maximum days until expiration (for early warning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_days_until_expiration: Option<i64>,

    /// Additional custom parameters
    #[serde(flatten)]
    pub custom_params: HashMap<String, serde_yaml::Value>,
}

impl Rule {
    /// Check if a value is allowed by this rule
    pub fn is_allowed(&self, value: &str) -> bool {
        if !self.allowed.is_empty() {
            self.allowed.contains(&value.to_string())
        } else {
            true // If no allow list, everything is allowed by default
        }
    }

    /// Check if a value is denied by this rule
    pub fn is_denied(&self, value: &str) -> bool {
        if !self.denied.is_empty() {
            self.denied.contains(&value.to_string())
        } else {
            false
        }
    }

    /// Check if a value matches allowed patterns
    pub fn matches_allowed_pattern(&self, value: &str) -> bool {
        if self.allowed_patterns.is_empty() {
            return true;
        }

        for pattern in &self.allowed_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(value) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a value matches denied patterns
    pub fn matches_denied_pattern(&self, value: &str) -> bool {
        for pattern in &self.denied_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(value) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a value matches preferred patterns
    pub fn matches_preferred_pattern(&self, value: &str) -> bool {
        for pattern in &self.preferred_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(value) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_allowed_list() {
        let rule = Rule {
            rule_type: "ProtocolVersion".to_string(),
            allowed: vec!["TLS 1.2".to_string(), "TLS 1.3".to_string()],
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
        };

        assert!(rule.is_allowed("TLS 1.2"));
        assert!(rule.is_allowed("TLS 1.3"));
        assert!(!rule.is_allowed("TLS 1.0"));
    }

    #[test]
    fn test_rule_denied_list() {
        let rule = Rule {
            rule_type: "ProtocolVersion".to_string(),
            allowed: vec![],
            denied: vec!["SSLv2".to_string(), "SSLv3".to_string()],
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
        };

        assert!(rule.is_denied("SSLv2"));
        assert!(rule.is_denied("SSLv3"));
        assert!(!rule.is_denied("TLS 1.2"));
    }

    #[test]
    fn test_rule_pattern_matching() {
        let rule = Rule {
            rule_type: "CipherSuite".to_string(),
            allowed: vec![],
            denied: vec![],
            allowed_patterns: vec![],
            denied_patterns: vec![".*_NULL_.*".to_string(), ".*_EXPORT_.*".to_string()],
            preferred_patterns: vec![],
            min_rsa_bits: None,
            min_ecc_bits: None,
            required: None,
            require_valid_chain: None,
            require_unexpired: None,
            require_hostname_match: None,
            max_days_until_expiration: None,
            custom_params: HashMap::new(),
        };

        assert!(rule.matches_denied_pattern("TLS_RSA_WITH_NULL_SHA"));
        assert!(rule.matches_denied_pattern("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"));
        assert!(!rule.matches_denied_pattern("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    }
}
