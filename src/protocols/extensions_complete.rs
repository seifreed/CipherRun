// Complete TLS Extensions Testing - All 20+ TLS Extensions
// Comprehensive extension detection and analysis

mod catalog;
mod model;

pub use model::{SecurityImpact, TlsExtensionInfo, TlsExtensionResult, TlsExtensionsComplete};

use catalog::{all_extensions, parse_extension_data};

/// Complete TLS extensions reference (RFC numbers included)
pub struct TlsExtensions;

impl TlsExtensions {
    /// Get all known TLS extensions
    pub fn all_extensions() -> Vec<TlsExtensionInfo> {
        all_extensions()
    }

    /// Get extension info by ID
    pub fn get_extension_info(extension_id: u16) -> Option<TlsExtensionInfo> {
        Self::all_extensions()
            .into_iter()
            .find(|ext| ext.id == extension_id)
    }

    /// Get critical extensions that should be supported
    pub fn critical_extensions() -> Vec<u16> {
        Self::all_extensions()
            .into_iter()
            .filter(|ext| ext.security_impact == SecurityImpact::Critical)
            .map(|ext| ext.id)
            .collect()
    }

    /// Get deprecated extensions
    pub fn deprecated_extensions() -> Vec<u16> {
        Self::all_extensions()
            .into_iter()
            .filter(|ext| ext.deprecated)
            .map(|ext| ext.id)
            .collect()
    }

    /// Analyze extensions from server
    pub fn analyze_extensions(extensions: &[(u16, Vec<u8>)]) -> TlsExtensionsComplete {
        let mut results = Vec::new();
        let supported_ids: Vec<u16> = extensions.iter().map(|(id, _)| *id).collect();

        for ext_info in Self::all_extensions() {
            let supported = supported_ids.contains(&ext_info.id);

            let (data_length, parsed_data) = if supported {
                if let Some((_, data)) = extensions.iter().find(|(id, _)| *id == ext_info.id) {
                    (
                        Some(data.len()),
                        Some(parse_extension_data(ext_info.id, data)),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            results.push(TlsExtensionResult {
                extension_id: ext_info.id,
                extension_name: ext_info.name,
                supported,
                required: ext_info.required,
                deprecated: ext_info.deprecated,
                data_length,
                parsed_data,
                security_impact: ext_info.security_impact,
                description: ext_info.description,
            });
        }

        let total_supported = results.iter().filter(|result| result.supported).count();

        let critical_missing: Vec<String> = results
            .iter()
            .filter(|result| {
                result.security_impact == SecurityImpact::Critical && !result.supported
            })
            .map(|result| result.extension_name.clone())
            .collect();

        let deprecated_present: Vec<String> = results
            .iter()
            .filter(|result| result.deprecated && result.supported)
            .map(|result| result.extension_name.clone())
            .collect();

        TlsExtensionsComplete {
            extensions: results,
            total_supported,
            critical_missing,
            deprecated_present,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_extensions_loaded() {
        let extensions = TlsExtensions::all_extensions();
        assert!(
            extensions.len() >= 30,
            "Should have at least 30 TLS extensions"
        );
    }

    #[test]
    fn test_critical_extensions() {
        let critical = TlsExtensions::critical_extensions();
        assert!(critical.contains(&0x0000));
        assert!(critical.contains(&0xff01));
        assert!(critical.contains(&0x0017));
    }

    #[test]
    fn test_deprecated_extensions() {
        let deprecated = TlsExtensions::deprecated_extensions();
        assert!(deprecated.contains(&0x3374));
    }

    #[test]
    fn test_get_extension_info() {
        let sni = TlsExtensions::get_extension_info(0x0000).expect("test assertion should succeed");
        assert_eq!(sni.name, "server_name (SNI)");
        assert_eq!(sni.security_impact, SecurityImpact::Critical);
    }

    #[test]
    fn test_get_extension_info_unknown() {
        let info = TlsExtensions::get_extension_info(0xdead);
        assert!(info.is_none());
    }
}
