use crate::application::ComplianceFrameworkSource;
use crate::compliance::framework::ComplianceFramework;
use crate::compliance::loader::FrameworkLoader;
use std::path::Path;

pub struct BuiltinFrameworkSource;

impl BuiltinFrameworkSource {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> crate::Result<ComplianceFramework> {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            crate::error::TlsError::Other(format!(
                "Failed to read framework file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;
        FrameworkLoader::load_from_string(&content).map_err(|e| {
            crate::error::TlsError::Other(format!(
                "Failed to parse framework YAML '{}': {}",
                path.as_ref().display(),
                e
            ))
        })
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
            (
                "nist-sp800-131a",
                "NIST SP 800-131A Rev 3 - Cryptographic Algorithm Transitions",
            ),
            (
                "nist-fips-pqc",
                "NIST FIPS 203/204 - Post-Quantum Readiness",
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
            "nist-sp800-131a" | "sp800-131a" | "nist-131a" => Ok("nist_sp800_131a_r3.yaml"),
            "nist-fips-pqc" | "fips-pqc" | "pqc" => Ok("nist_fips_pqc.yaml"),
            _ => Err(crate::error::TlsError::ConfigError {
                message: format!(
                    "Unknown framework ID: {}. Supported: pci-dss-v4, nist-sp800-52r2, hipaa, soc2, mozilla-modern, mozilla-intermediate, gdpr, nist-sp800-131a, nist-fips-pqc",
                    framework_id
                ),
            }),
        }
    }

    /// Embedded copy of each builtin framework YAML, bundled into the binary so
    /// compliance scanning works when running outside the source tree — matching
    /// how every other data file (cert stores, cipher mapping, fingerprints) is
    /// embedded via `include_str!`. Keyed by the canonical filename returned by
    /// [`Self::builtin_filename`], so the set is always exhaustive.
    fn builtin_embedded(filename: &str) -> Option<&'static str> {
        let content = match filename {
            "pci_dss_v4.yaml" => include_str!("../../data/compliance/pci_dss_v4.yaml"),
            "nist_sp800_52r2.yaml" => include_str!("../../data/compliance/nist_sp800_52r2.yaml"),
            "hipaa.yaml" => include_str!("../../data/compliance/hipaa.yaml"),
            "soc2.yaml" => include_str!("../../data/compliance/soc2.yaml"),
            "mozilla_modern.yaml" => include_str!("../../data/compliance/mozilla_modern.yaml"),
            "mozilla_intermediate.yaml" => {
                include_str!("../../data/compliance/mozilla_intermediate.yaml")
            }
            "gdpr.yaml" => include_str!("../../data/compliance/gdpr.yaml"),
            "nist_sp800_131a_r3.yaml" => {
                include_str!("../../data/compliance/nist_sp800_131a_r3.yaml")
            }
            "nist_fips_pqc.yaml" => include_str!("../../data/compliance/nist_fips_pqc.yaml"),
            _ => return None,
        };
        Some(content)
    }
}

impl ComplianceFrameworkSource for BuiltinFrameworkSource {
    fn load_framework(&self, framework_id: &str) -> crate::Result<ComplianceFramework> {
        let filename = Self::builtin_filename(framework_id)?;
        // Prefer an on-disk copy when present so operators can override a bundled
        // framework, but fall back to the embedded copy so the binary works when
        // run outside the source tree.
        let data_path = format!("data/compliance/{}", filename);
        if Path::new(&data_path).exists() {
            return Self::load_from_file(&data_path);
        }

        let embedded = Self::builtin_embedded(filename).ok_or_else(|| {
            crate::error::TlsError::ConfigError {
                message: format!("No embedded framework available for: {}", framework_id),
            }
        })?;
        FrameworkLoader::load_from_string(embedded).map_err(|e| {
            crate::error::TlsError::Other(format!(
                "Failed to parse embedded framework '{}': {}",
                filename, e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_listed_framework_has_a_parseable_embedded_copy() {
        for (framework_id, _) in BuiltinFrameworkSource::list_frameworks() {
            let filename = BuiltinFrameworkSource::builtin_filename(framework_id)
                .expect("listed framework must map to a filename");
            let embedded =
                BuiltinFrameworkSource::builtin_embedded(filename).unwrap_or_else(|| {
                    panic!("framework '{framework_id}' ({filename}) has no embedded copy")
                });
            FrameworkLoader::load_from_string(embedded).unwrap_or_else(|e| {
                panic!("embedded framework '{framework_id}' failed to parse: {e}")
            });
        }
    }
}
