// YAML policy parser and validator

use crate::Result;
use crate::policy::Policy;
use crate::protocols::Protocol;
use regex::Regex;
use serde_yaml;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub trait PolicyDocumentSource: Send + Sync {
    fn read_to_string(&self, path: &Path) -> Result<String>;
}

struct NoopPolicyDocumentSource;

impl PolicyDocumentSource for NoopPolicyDocumentSource {
    fn read_to_string(&self, _path: &Path) -> Result<String> {
        Err(crate::TlsError::ConfigError {
            message: "No policy document source configured for this loader".to_string(),
        })
    }
}

/// Policy loader with support for inheritance
pub struct PolicyLoader<'a> {
    base_path: PathBuf,
    source: &'a dyn PolicyDocumentSource,
}

impl<'a> PolicyLoader<'a> {
    /// Create a new policy loader with a base path and document source.
    pub fn from_source(
        base_path: impl Into<PathBuf>,
        source: &'a dyn PolicyDocumentSource,
    ) -> Self {
        Self {
            base_path: base_path.into(),
            source,
        }
    }

    /// Load a policy from a file path
    pub fn load(&self, policy_path: &Path) -> Result<Policy> {
        let content = self.source.read_to_string(policy_path)?;
        let mut policy = self.parse_policy_document(&content)?;

        // Handle inheritance (extends)
        if let Some(ref extends_path) = policy.extends.clone() {
            let parent_path = self.resolve_path(policy_path, extends_path);
            let base_policy = self.load(&parent_path)?;
            policy = self.merge_policies(base_policy, policy)?;
        }

        self.normalize_policy_values(&mut policy);

        // Validate the policy
        self.validate(&policy)?;

        Ok(policy)
    }

    /// Load policy from YAML string
    pub fn load_from_string(yaml_content: &str) -> Result<Policy> {
        let loader = PolicyLoader::from_source(".", &NoopPolicyDocumentSource);
        let mut policy = loader.parse_policy_document(yaml_content)?;
        loader.normalize_policy_values(&mut policy);
        loader.validate(&policy)?;

        Ok(policy)
    }

    fn parse_policy_document(&self, content: &str) -> Result<Policy> {
        // Parse the YAML into a generic value first
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(content).map_err(|e| crate::TlsError::ParseError {
                message: format!("Failed to parse YAML: {}", e),
            })?;

        // Check if the policy is wrapped under a "policy" key
        let policy_value = if let Some(policy_obj) = yaml_value.get("policy") {
            policy_obj.clone()
        } else {
            // If no "policy" key, assume the entire content is the policy
            yaml_value
        };

        // Deserialize the policy
        serde_yaml::from_value(policy_value).map_err(|e| crate::TlsError::ParseError {
            message: format!("Failed to parse policy YAML: {}", e),
        })
    }

    /// Resolve a path relative to the current policy file
    fn resolve_path(&self, current_file: &Path, relative_path: &str) -> PathBuf {
        if let Some(parent) = current_file.parent() {
            parent.join(relative_path)
        } else {
            self.base_path.join(relative_path)
        }
    }

    /// Merge two policies (child overrides parent)
    fn merge_policies(&self, mut base: Policy, override_policy: Policy) -> Result<Policy> {
        // Override policy takes precedence for most fields
        let merged = Policy {
            name: override_policy.name,
            version: override_policy.version,
            description: override_policy.description.or(base.description),
            organization: override_policy.organization.or(base.organization),
            effective_date: override_policy.effective_date.or(base.effective_date),
            extends: None, // Don't keep extends chain

            // Override policy rules take precedence
            protocols: override_policy.protocols.or(base.protocols),
            ciphers: override_policy.ciphers.or(base.ciphers),
            certificates: override_policy.certificates.or(base.certificates),
            vulnerabilities: override_policy.vulnerabilities.or(base.vulnerabilities),
            rating: override_policy.rating.or(base.rating),
            compliance: override_policy.compliance.or(base.compliance),

            // Merge exceptions (both apply)
            exceptions: {
                base.exceptions.extend(override_policy.exceptions);
                base.exceptions
            },
        };

        Ok(merged)
    }

    fn normalize_policy_values(&self, policy: &mut Policy) {
        if let Some(ref mut cipher_policy) = policy.ciphers
            && let Some(ref mut min_strength) = cipher_policy.min_strength
        {
            *min_strength = min_strength.trim().to_ascii_uppercase();
        }

        if let Some(ref mut rating_policy) = policy.rating
            && let Some(ref mut min_grade) = rating_policy.min_grade
        {
            *min_grade = min_grade.trim().to_ascii_uppercase();
        }
    }

    /// Validate policy structure and values
    fn validate(&self, policy: &Policy) -> Result<()> {
        // Validate name and version are not empty
        if policy.name.trim().is_empty() {
            return Err(crate::TlsError::ConfigError {
                message: "Policy name cannot be empty".to_string(),
            });
        }

        if policy.version.trim().is_empty() {
            return Err(crate::TlsError::ConfigError {
                message: "Policy version cannot be empty".to_string(),
            });
        }

        // Validate protocol policy
        if let Some(ref protocol_policy) = policy.protocols {
            if let Some(ref required) = protocol_policy.required {
                Self::validate_protocol_names("required", required)?;
            }

            if let Some(ref prohibited) = protocol_policy.prohibited {
                Self::validate_protocol_names("prohibited", prohibited)?;
            }
        }

        // Validate cipher policy
        if let Some(ref cipher_policy) = policy.ciphers {
            if let Some(ref min_strength) = cipher_policy.min_strength
                && !["LOW", "MEDIUM", "HIGH"].contains(&min_strength.as_str())
            {
                return Err(crate::TlsError::ConfigError {
                    message: format!(
                        "Invalid min_strength: {}. Must be LOW, MEDIUM, or HIGH",
                        min_strength
                    ),
                });
            }

            // Validate regex patterns
            if let Some(ref patterns) = cipher_policy.prohibited_patterns {
                Self::validate_cipher_patterns("prohibited", patterns)?;
            }

            if let Some(ref patterns) = cipher_policy.required_patterns {
                Self::validate_cipher_patterns("required", patterns)?;
            }
        }

        // Validate certificate policy
        if let Some(ref cert_policy) = policy.certificates {
            if let Some(min_key_size) = cert_policy.min_key_size
                && min_key_size < 1024
            {
                return Err(crate::TlsError::ConfigError {
                    message: "min_key_size must be at least 1024".to_string(),
                });
            }

            if let Some(ref algorithms) = cert_policy.prohibited_signature_algorithms {
                Self::validate_non_empty_entries("prohibited signature algorithm", algorithms)?;
            }
        }

        // Validate vulnerability policy
        if let Some(ref vulnerability_policy) = policy.vulnerabilities
            && let Some(ref prohibited) = vulnerability_policy.prohibited
        {
            Self::validate_non_empty_entries("prohibited vulnerability", prohibited)?;
        }

        // Validate rating policy
        if let Some(ref rating_policy) = policy.rating {
            if let Some(ref min_grade) = rating_policy.min_grade {
                let valid_grades = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"];
                if !valid_grades.contains(&min_grade.as_str()) {
                    return Err(crate::TlsError::ConfigError {
                        message: format!(
                            "Invalid min_grade: {}. Must be one of: {}",
                            min_grade,
                            valid_grades.join(", ")
                        ),
                    });
                }
            }

            if let Some(min_score) = rating_policy.min_score
                && min_score > 100
            {
                return Err(crate::TlsError::ConfigError {
                    message: "min_score must be between 0 and 100".to_string(),
                });
            }
        }

        // Validate exceptions
        for exception in &policy.exceptions {
            if exception.rules.is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception rules cannot be empty".to_string(),
                });
            }

            if exception.rules.iter().any(|rule| rule.trim().is_empty()) {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception rules cannot contain empty rule paths".to_string(),
                });
            }

            if exception.reason.trim().is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception reason cannot be empty".to_string(),
                });
            }

            if exception.approved_by.trim().is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception approved_by cannot be empty".to_string(),
                });
            }

            // Validate date format if expires is set
            if let Some(ref expires) = exception.expires {
                use chrono::NaiveDate;
                NaiveDate::parse_from_str(expires, "%Y-%m-%d").map_err(|e| {
                    crate::TlsError::ConfigError {
                        message: format!(
                            "Invalid exception expiry date '{}': {} (expected YYYY-MM-DD)",
                            expires, e
                        ),
                    }
                })?;
            }
        }

        Ok(())
    }

    fn validate_protocol_names(field: &str, protocols: &[String]) -> Result<()> {
        for protocol in protocols {
            if protocol.trim().is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: format!("Protocol {} entries cannot be empty", field),
                });
            }

            Protocol::from_str(protocol).map_err(|e| crate::TlsError::ConfigError {
                message: format!("Invalid protocol in {} list: {}", field, e),
            })?;
        }

        Ok(())
    }

    fn validate_cipher_patterns(field: &str, patterns: &[String]) -> Result<()> {
        for pattern in patterns {
            if pattern.trim().is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: format!("Cipher {} patterns cannot be empty", field),
                });
            }

            Regex::new(pattern).map_err(|e| crate::TlsError::ConfigError {
                message: format!("Invalid {} cipher pattern '{}': {}", field, pattern, e),
            })?;
        }

        Ok(())
    }

    fn validate_non_empty_entries(field: &str, entries: &[String]) -> Result<()> {
        for entry in entries {
            if entry.trim().is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: format!("Policy {} entries cannot be empty", field),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_policy() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  description: "Test policy"
  protocols:
    required: ["TLSv1.2", "TLSv1.3"]
    prohibited: ["SSLv2", "SSLv3"]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_ok());

        let policy = result.expect("test assertion should succeed");
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.version, "1.0");
        assert!(policy.protocols.is_some());
    }

    #[test]
    fn test_validate_min_strength() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  ciphers:
    min_strength: "INVALID"
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_required_protocol_name_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  protocols:
    required: ["TLSv1.4"]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_prohibited_protocol_name_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  protocols:
    prohibited: ["not-a-protocol"]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_protocol_name_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  protocols:
    prohibited: ["   "]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_strength_is_normalized_before_evaluation() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  ciphers:
    min_strength: " high "
    action: FAIL
"#;

        let policy = PolicyLoader::load_from_string(yaml).expect("policy should parse");
        assert_eq!(
            policy
                .ciphers
                .expect("cipher policy")
                .min_strength
                .expect("min strength"),
            "HIGH"
        );
    }

    #[test]
    fn test_validate_regex_patterns() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  ciphers:
    prohibited_patterns:
      - ".*_RC4_.*"
      - "[invalid regex"
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_required_cipher_pattern_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  ciphers:
    required_patterns: [""]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_prohibited_cipher_pattern_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  ciphers:
    prohibited_patterns: ["   "]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_prohibited_signature_algorithm_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  certificates:
    prohibited_signature_algorithms: [""]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_prohibited_vulnerability_is_rejected() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  vulnerabilities:
    prohibited: ["   "]
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_exception_dates() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  exceptions:
    - domain: "example.com"
      rules: ["protocols.prohibited"]
      reason: "Test"
      expires: "invalid-date"
      approved_by: "Admin"
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_name_validation() {
        let yaml = r#"
policy:
  name: ""
  version: "1.0"
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_policy_name_is_invalid() {
        let yaml = r#"
policy:
  name: "   "
  version: "1.0"
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_policy_version_is_invalid() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "   "
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_exception_audit_fields_are_invalid() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  exceptions:
    - domain: "example.com"
      rules: ["protocols.prohibited"]
      reason: "   "
      approved_by: "   "
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_exception_rules_are_invalid() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  exceptions:
    - domain: "example.com"
      rules: []
      reason: "Test"
      approved_by: "Admin"
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_exception_rules_are_invalid() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  exceptions:
    - domain: "example.com"
      rules: ["   "]
      reason: "Test"
      approved_by: "Admin"
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_without_policy_wrapper() {
        // Test that parsing without the "policy:" wrapper also works
        let yaml = r#"
name: "Test Policy"
version: "1.0"
description: "Test policy without wrapper"
protocols:
  required: ["TLSv1.2", "TLSv1.3"]
  prohibited: ["SSLv2", "SSLv3"]
  action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_ok());

        let policy = result.expect("test assertion should succeed");
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.version, "1.0");
        assert!(policy.protocols.is_some());
    }

    #[test]
    fn test_validate_rating_min_score_too_high() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  rating:
    min_score: 101
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rating_min_grade_valid() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  rating:
    min_grade: "A-"
    action: FAIL
"#;

        let result = PolicyLoader::load_from_string(yaml);
        assert!(result.is_ok());
        let policy = result.expect("test assertion should succeed");
        assert!(policy.rating.is_some());
    }

    #[test]
    fn test_rating_min_grade_is_normalized() {
        let yaml = r#"
policy:
  name: "Test Policy"
  version: "1.0"
  rating:
    min_grade: " a- "
    action: FAIL
"#;

        let policy = PolicyLoader::load_from_string(yaml).expect("policy should parse");
        assert_eq!(
            policy
                .rating
                .expect("rating policy")
                .min_grade
                .expect("min grade"),
            "A-"
        );
    }

    #[test]
    fn test_load_example_policy_file() {
        // Test loading an actual example policy file
        use std::path::PathBuf;

        let policy_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/policies/base-security.yaml");

        if policy_path.exists() {
            let source = crate::policy::source::FilesystemPolicySource;
            let loader = PolicyLoader::from_source(".", &source);
            let result = loader.load(&policy_path);

            match &result {
                Ok(policy) => {
                    assert_eq!(policy.name, "Base Security Policy");
                    assert_eq!(policy.version, "1.0");
                    assert!(policy.protocols.is_some());
                    assert!(policy.ciphers.is_some());
                    assert!(policy.certificates.is_some());
                }
                Err(e) => panic!("Failed to load example policy: {:?}", e),
            }
        }
    }
}
