// YAML policy parser and validator

use crate::Result;
use crate::policy::Policy;
use regex::Regex;
use serde_yaml;
use std::fs;
use std::path::{Path, PathBuf};

/// Policy loader with support for inheritance
pub struct PolicyLoader {
    base_path: PathBuf,
}

impl PolicyLoader {
    /// Create a new policy loader with a base path for resolving relative imports
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Load a policy from a file path
    pub fn load(&self, policy_path: &Path) -> Result<Policy> {
        let mut policy = self.load_yaml(policy_path)?;

        // Handle inheritance (extends)
        if let Some(ref extends_path) = policy.extends.clone() {
            let parent_path = self.resolve_path(policy_path, extends_path);
            let base_policy = self.load(&parent_path)?;
            policy = self.merge_policies(base_policy, policy)?;
        }

        // Validate the policy
        self.validate(&policy)?;

        Ok(policy)
    }

    /// Load policy from YAML string
    pub fn load_from_string(yaml_content: &str) -> Result<Policy> {
        // Parse the YAML into a generic value first
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(yaml_content).map_err(|e| crate::TlsError::ParseError {
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
        let policy: Policy =
            serde_yaml::from_value(policy_value).map_err(|e| crate::TlsError::ParseError {
                message: format!("Failed to parse policy YAML: {}", e),
            })?;

        // Basic validation
        let loader = PolicyLoader::new(".");
        loader.validate(&policy)?;

        Ok(policy)
    }

    /// Load YAML file
    fn load_yaml(&self, path: &Path) -> Result<Policy> {
        let content =
            fs::read_to_string(path).map_err(|e| crate::TlsError::IoError { source: e })?;

        // Parse the YAML into a generic value first
        let yaml_value: serde_yaml::Value =
            serde_yaml::from_str(&content).map_err(|e| crate::TlsError::ParseError {
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

    /// Validate policy structure and values
    fn validate(&self, policy: &Policy) -> Result<()> {
        // Validate name and version are not empty
        if policy.name.is_empty() {
            return Err(crate::TlsError::ConfigError {
                message: "Policy name cannot be empty".to_string(),
            });
        }

        if policy.version.is_empty() {
            return Err(crate::TlsError::ConfigError {
                message: "Policy version cannot be empty".to_string(),
            });
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
                for pattern in patterns {
                    Regex::new(pattern).map_err(|e| crate::TlsError::ConfigError {
                        message: format!("Invalid prohibited cipher pattern '{}': {}", pattern, e),
                    })?;
                }
            }

            if let Some(ref patterns) = cipher_policy.required_patterns {
                for pattern in patterns {
                    Regex::new(pattern).map_err(|e| crate::TlsError::ConfigError {
                        message: format!("Invalid required cipher pattern '{}': {}", pattern, e),
                    })?;
                }
            }
        }

        // Validate certificate policy
        if let Some(ref cert_policy) = policy.certificates
            && let Some(min_key_size) = cert_policy.min_key_size
            && min_key_size < 1024
        {
            return Err(crate::TlsError::ConfigError {
                message: "min_key_size must be at least 1024".to_string(),
            });
        }

        // Validate rating policy
        if let Some(ref rating_policy) = policy.rating {
            if let Some(ref min_grade) = rating_policy.min_grade {
                let valid_grades = [
                    "A+", "A", "A-", "B", "B+", "B-", "C", "C+", "C-", "D", "E", "F", "T", "M",
                ];
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
            if exception.reason.is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception reason cannot be empty".to_string(),
                });
            }

            if exception.approved_by.is_empty() {
                return Err(crate::TlsError::ConfigError {
                    message: "Exception approved_by cannot be empty".to_string(),
                });
            }

            // Validate date format if expires is set
            if let Some(ref expires) = exception.expires {
                use chrono::NaiveDate;
                NaiveDate::parse_from_str(expires, "%Y-%m-%d").map_err(|_| {
                    crate::TlsError::ConfigError {
                        message: format!(
                            "Invalid exception expiry date '{}'. Must be in YYYY-MM-DD format",
                            expires
                        ),
                    }
                })?;
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
    fn test_load_example_policy_file() {
        // Test loading an actual example policy file
        use std::path::PathBuf;

        let policy_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/policies/base-security.yaml");

        if policy_path.exists() {
            let loader = PolicyLoader::new(".");
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
