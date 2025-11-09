// Framework loader - Loads compliance frameworks from YAML files

use crate::compliance::ComplianceFramework;
use anyhow::{Context, Result};
use std::path::Path;

/// Framework loader for loading compliance frameworks from YAML files
pub struct FrameworkLoader;

impl FrameworkLoader {
    /// Load a framework from a YAML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<ComplianceFramework> {
        let content = std::fs::read_to_string(&path).context(format!(
            "Failed to read framework file: {}",
            path.as_ref().display()
        ))?;

        let framework: ComplianceFramework = serde_yaml::from_str(&content).context(format!(
            "Failed to parse framework YAML: {}",
            path.as_ref().display()
        ))?;

        Ok(framework)
    }

    /// Load a built-in framework by ID
    ///
    /// Supported IDs:
    /// - pci-dss-v4
    /// - nist-sp800-52r2
    /// - hipaa
    /// - soc2
    /// - mozilla-modern
    /// - mozilla-intermediate
    /// - gdpr
    pub fn load_builtin(framework_id: &str) -> Result<ComplianceFramework> {
        let filename = match framework_id {
            "pci-dss-v4" | "pci-dss" | "pci" => "pci_dss_v4.yaml",
            "nist-sp800-52r2" | "nist" => "nist_sp800_52r2.yaml",
            "hipaa" => "hipaa.yaml",
            "soc2" | "soc-2" => "soc2.yaml",
            "mozilla-modern" | "modern" => "mozilla_modern.yaml",
            "mozilla-intermediate" | "intermediate" => "mozilla_intermediate.yaml",
            "gdpr" => "gdpr.yaml",
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown framework ID: {}. Supported: pci-dss-v4, nist-sp800-52r2, hipaa, soc2, mozilla-modern, mozilla-intermediate, gdpr",
                    framework_id
                ));
            }
        };

        // Try to load from data/compliance directory
        let data_path = format!("data/compliance/{}", filename);
        if Path::new(&data_path).exists() {
            return Self::load_from_file(&data_path);
        }

        // Try embedded data (if compiled in)
        // This would use include_str! macro in production
        Err(anyhow::anyhow!(
            "Framework file not found: {}. Please ensure data/compliance/{} exists.",
            framework_id,
            filename
        ))
    }

    /// List all available built-in frameworks
    pub fn list_builtin_frameworks() -> Vec<(&'static str, &'static str)> {
        vec![
            ("pci-dss-v4", "PCI-DSS v4.0.1 - Payment Card Industry Data Security Standard"),
            ("nist-sp800-52r2", "NIST SP 800-52 Revision 2 - Guidelines for TLS"),
            ("hipaa", "HIPAA - Health Insurance Portability and Accountability Act"),
            ("soc2", "SOC 2 - Service Organization Control 2"),
            ("mozilla-modern", "Mozilla Modern TLS Configuration"),
            ("mozilla-intermediate", "Mozilla Intermediate TLS Configuration"),
            ("gdpr", "GDPR - General Data Protection Regulation (encryption requirements)"),
        ]
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
