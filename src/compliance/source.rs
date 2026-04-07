use crate::application::ComplianceFrameworkSource;
use crate::compliance::framework::ComplianceFramework;
use crate::compliance::loader::FrameworkLoader;
use anyhow::{Context, Result};
use std::path::Path;

pub struct BuiltinFrameworkSource;

impl BuiltinFrameworkSource {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<ComplianceFramework> {
        let content = std::fs::read_to_string(&path).context(format!(
            "Failed to read framework file: {}",
            path.as_ref().display()
        ))?;

        FrameworkLoader::load_from_string(&content).context(format!(
            "Failed to parse framework YAML: {}",
            path.as_ref().display()
        ))
    }

    pub fn list_frameworks() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "pci-dss-v4",
                "PCI-DSS v4.0.1 - Payment Card Industry Data Security Standard",
            ),
            (
                "nist-sp800-52r2",
                "NIST SP 800-52 Revision 2 - Guidelines for TLS",
            ),
            (
                "hipaa",
                "HIPAA - Health Insurance Portability and Accountability Act",
            ),
            ("soc2", "SOC 2 - Service Organization Control 2"),
            ("mozilla-modern", "Mozilla Modern TLS Configuration"),
            (
                "mozilla-intermediate",
                "Mozilla Intermediate TLS Configuration",
            ),
            (
                "gdpr",
                "GDPR - General Data Protection Regulation (encryption requirements)",
            ),
        ]
    }

    fn builtin_filename(framework_id: &str) -> crate::Result<&'static str> {
        match framework_id {
            "pci-dss-v4" | "pci-dss" | "pci" => Ok("pci_dss_v4.yaml"),
            "nist-sp800-52r2" | "nist" => Ok("nist_sp800_52r2.yaml"),
            "hipaa" => Ok("hipaa.yaml"),
            "soc2" | "soc-2" => Ok("soc2.yaml"),
            "mozilla-modern" | "modern" => Ok("mozilla_modern.yaml"),
            "mozilla-intermediate" | "intermediate" => Ok("mozilla_intermediate.yaml"),
            "gdpr" => Ok("gdpr.yaml"),
            _ => Err(crate::error::TlsError::ConfigError {
                message: format!(
                    "Unknown framework ID: {}. Supported: pci-dss-v4, nist-sp800-52r2, hipaa, soc2, mozilla-modern, mozilla-intermediate, gdpr",
                    framework_id
                ),
            }),
        }
    }
}

impl ComplianceFrameworkSource for BuiltinFrameworkSource {
    fn load_framework(&self, framework_id: &str) -> crate::Result<ComplianceFramework> {
        let filename = Self::builtin_filename(framework_id)?;
        let data_path = format!("data/compliance/{}", filename);
        if Path::new(&data_path).exists() {
            return Self::load_from_file(&data_path)
                .context(format!("loading compliance framework '{}'", framework_id))
                .map_err(Into::into);
        }

        Err(crate::error::TlsError::ConfigError {
            message: format!(
                "Framework file not found: {}. Please ensure data/compliance/{} exists.",
                framework_id, filename
            ),
        })
    }
}
