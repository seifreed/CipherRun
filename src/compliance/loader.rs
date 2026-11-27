// Framework loader - Parses compliance frameworks from YAML content

use crate::compliance::ComplianceFramework;
use crate::error::TlsError;

/// Framework loader for loading compliance frameworks from YAML files
pub struct FrameworkLoader;

impl FrameworkLoader {
    pub fn load_from_string(yaml_content: &str) -> crate::Result<ComplianceFramework> {
        let framework: ComplianceFramework =
            serde_saphyr::from_str(yaml_content).map_err(|e| TlsError::ParseError {
                message: format!("Failed to deserialize compliance framework YAML: {}", e),
            })?;
        Self::validate_regex_patterns(&framework)?;
        Ok(framework)
    }

    fn validate_regex_patterns(framework: &ComplianceFramework) -> crate::Result<()> {
        for requirement in &framework.requirements {
            for rule in &requirement.rules {
                for pattern in &rule.denied_patterns {
                    regex::Regex::new(pattern).map_err(|_| TlsError::ParseError {
                        message: format!(
                            "Invalid regex in denied_patterns of requirement '{}': {:?}",
                            requirement.id, pattern
                        ),
                    })?;
                }
                for pattern in &rule.allowed_patterns {
                    regex::Regex::new(pattern).map_err(|_| TlsError::ParseError {
                        message: format!(
                            "Invalid regex in allowed_patterns of requirement '{}': {:?}",
                            requirement.id, pattern
                        ),
                    })?;
                }
                for pattern in &rule.preferred_patterns {
                    regex::Regex::new(pattern).map_err(|_| TlsError::ParseError {
                        message: format!(
                            "Invalid regex in preferred_patterns of requirement '{}': {:?}",
                            requirement.id, pattern
                        ),
                    })?;
                }
            }
        }
        Ok(())
    }

    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> crate::Result<ComplianceFramework> {
        crate::compliance::source::BuiltinFrameworkSource::load_from_file(path)
    }

    pub fn load_builtin(framework_id: &str) -> crate::Result<ComplianceFramework> {
        use crate::application::ComplianceFrameworkSource;
        crate::compliance::source::BuiltinFrameworkSource.load_framework(framework_id)
    }

    pub fn list_builtin_frameworks() -> Vec<(&'static str, &'static str)> {
        crate::compliance::source::BuiltinFrameworkSource::list_frameworks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framework_yaml_with_pattern_field(field: &str) -> String {
        format!(
            "id: test\nname: Test framework\nversion: '1'\ndescription: Test framework\norganization: Test\nrequirements:\n  - id: test-1\n    name: Test\n    description: Test\n    category: Test\n    severity: low\n    rules:\n      - type: CipherSuite\n        {field}: ['[']\n"
        )
    }

    #[test]
    fn test_list_builtin_frameworks() {
        let frameworks = FrameworkLoader::list_builtin_frameworks();
        assert_eq!(frameworks.len(), 9);
        assert!(frameworks.iter().any(|(id, _)| *id == "pci-dss-v4"));
        assert!(frameworks.iter().any(|(id, _)| *id == "nist-sp800-52r2"));
        assert!(frameworks.iter().any(|(id, _)| *id == "nist-sp800-131a"));
        assert!(frameworks.iter().any(|(id, _)| *id == "nist-fips-pqc"));
    }

    #[test]
    fn test_every_listed_framework_is_loadable() {
        // Guards against a framework being advertised by `list_frameworks`
        // without a corresponding, parseable data file behind it.
        for (id, _) in FrameworkLoader::list_builtin_frameworks() {
            FrameworkLoader::load_builtin(id).expect("listed framework should load successfully");
        }
    }

    #[test]
    fn test_unknown_framework() {
        let result = FrameworkLoader::load_builtin("unknown-framework");
        assert!(result.is_err());
    }

    #[test]
    fn parses_json_compatible_custom_rule_values() {
        let yaml = r#"
id: test
name: Test
version: "1"
description: Test framework
organization: Test
requirements:
  - id: test-1
    name: Test
    description: Test
    category: Test
    severity: low
    rules:
      - type: Custom
        custom:
          enabled: true
          labels: [one, two]
          settings:
            retries: 3
"#;

        let framework = FrameworkLoader::load_from_string(yaml).unwrap();
        let custom = &framework.requirements[0].rules[0].custom_params["custom"];

        assert_eq!(custom["enabled"], serde_json::json!(true));
        assert_eq!(custom["labels"], serde_json::json!(["one", "two"]));
        assert_eq!(custom["settings"]["retries"], serde_json::json!(3));
    }

    #[test]
    fn malformed_yaml_returns_a_parse_error() {
        let error = FrameworkLoader::load_from_string("requirements: [")
            .expect_err("malformed YAML should fail to deserialize");

        assert!(
            error
                .to_string()
                .contains("Failed to deserialize compliance framework YAML")
        );
    }

    #[test]
    fn invalid_regexes_in_all_pattern_fields_are_rejected() {
        for field in ["denied_patterns", "allowed_patterns", "preferred_patterns"] {
            let yaml = framework_yaml_with_pattern_field(field);
            let error = FrameworkLoader::load_from_string(&yaml)
                .expect_err("invalid pattern should fail framework validation");

            let message = error.to_string();
            assert!(message.contains("Invalid regex"), "{message}");
            assert!(message.contains(field), "{message}");
            assert!(message.contains("test-1"), "{message}");
        }
    }

    #[test]
    fn load_from_file_reads_a_framework_and_reports_missing_files() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("custom.yaml");
        let yaml =
            framework_yaml_with_pattern_field("allowed_patterns").replace("['[']", "['TLS_.*']");
        std::fs::write(&path, yaml).expect("write framework YAML");

        let loaded = FrameworkLoader::load_from_file(&path).expect("load custom framework");
        assert_eq!(loaded.id, "test");
        assert_eq!(loaded.requirements.len(), 1);

        let missing = directory.path().join("missing.yaml");
        assert!(FrameworkLoader::load_from_file(missing).is_err());
    }
}
