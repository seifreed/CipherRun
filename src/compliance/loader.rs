// Framework loader - Parses compliance frameworks from YAML content

use crate::compliance::ComplianceFramework;
use anyhow::{Context, Result};

/// Framework loader for loading compliance frameworks from YAML files
pub struct FrameworkLoader;

impl FrameworkLoader {
    pub fn load_from_string(yaml_content: &str) -> Result<ComplianceFramework> {
        let framework: ComplianceFramework = serde_yaml::from_str(yaml_content)
            .context("Failed to deserialize compliance framework YAML")?;
        Ok(framework)
    }

    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<ComplianceFramework> {
        crate::compliance::source::BuiltinFrameworkSource::load_from_file(path)
    }

    pub fn load_builtin(framework_id: &str) -> Result<ComplianceFramework> {
        use crate::application::ComplianceFrameworkSource;
        crate::compliance::source::BuiltinFrameworkSource
            .load_framework(framework_id)
            .map_err(Into::into)
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
