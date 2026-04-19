// Framework loader - Parses compliance frameworks from YAML content

use crate::compliance::ComplianceFramework;
use crate::error::TlsError;

/// Framework loader for loading compliance frameworks from YAML files
pub struct FrameworkLoader;

impl FrameworkLoader {
    pub fn load_from_string(yaml_content: &str) -> crate::Result<ComplianceFramework> {
        let framework: ComplianceFramework = serde_yaml::from_str(yaml_content).map_err(|e| {
            TlsError::ParseError {
                message: format!("Failed to deserialize compliance framework YAML: {}", e),
            }
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

    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> crate::Result<ComplianceFramework> {
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

    #[test]
    fn test_list_builtin_frameworks() {
        let frameworks = FrameworkLoader::list_builtin_frameworks();
        assert_eq!(frameworks.len(), 7);
        assert!(frameworks.iter().any(|(id, _)| *id == "pci-dss-v4"));
        assert!(frameworks.iter().any(|(id, _)| *id == "nist-sp800-52r2"));
    }

    #[test]
    fn test_unknown_framework() {
        let result = FrameworkLoader::load_builtin("unknown-framework");
        assert!(result.is_err());
    }
}
