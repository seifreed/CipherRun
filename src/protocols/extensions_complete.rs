// Complete TLS Extensions Testing - All 20+ TLS Extensions
// Comprehensive extension detection and analysis

use serde::{Deserialize, Serialize};

/// All TLS extensions comprehensive results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtensionsComplete {
    pub extensions: Vec<TlsExtensionResult>,
    pub total_supported: usize,
    pub critical_missing: Vec<String>,
    pub deprecated_present: Vec<String>,
}

/// Individual TLS extension result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtensionResult {
    pub extension_id: u16,
    pub extension_name: String,
    pub supported: bool,
    pub required: bool,
    pub deprecated: bool,
    pub data_length: Option<usize>,
    pub parsed_data: Option<String>,
    pub security_impact: SecurityImpact,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityImpact {
    Critical,   // Extension critical for security
    High,       // Important security extension
    Medium,     // Useful security feature
    Low,        // Optional or informational
    Deprecated, // Should not be used
}

/// Complete TLS extensions reference (RFC numbers included)
pub struct TlsExtensions;

impl TlsExtensions {
    /// Get all known TLS extensions
    pub fn all_extensions() -> Vec<TlsExtensionInfo> {
        vec![
            // ===== CRITICAL SECURITY EXTENSIONS =====
            TlsExtensionInfo {
                id: 0x0000,
                name: "server_name (SNI)".to_string(),
                required: true,
                deprecated: false,
                security_impact: SecurityImpact::Critical,
                description: "Server Name Indication (RFC 6066) - Enables virtual hosting for TLS"
                    .to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0xff01,
                name: "renegotiation_info".to_string(),
                required: true,
                deprecated: false,
                security_impact: SecurityImpact::Critical,
                description: "Secure renegotiation (RFC 5746) - Prevents renegotiation attacks"
                    .to_string(),
                rfc: "RFC 5746".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0017,
                name: "extended_master_secret".to_string(),
                required: true,
                deprecated: false,
                security_impact: SecurityImpact::Critical,
                description:
                    "Extended Master Secret (RFC 7627) - Prevents session resumption attacks"
                        .to_string(),
                rfc: "RFC 7627".to_string(),
            },
            TlsExtensionInfo {
                id: 0x002b,
                name: "supported_versions".to_string(),
                required: true,
                deprecated: false,
                security_impact: SecurityImpact::Critical,
                description: "Supported TLS versions (RFC 8446) - TLS 1.3 version negotiation"
                    .to_string(),
                rfc: "RFC 8446".to_string(),
            },
            // ===== HIGH SECURITY EXTENSIONS =====
            TlsExtensionInfo {
                id: 0x0005,
                name: "status_request (OCSP Stapling)".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::High,
                description: "OCSP stapling (RFC 6066) - Certificate revocation checking"
                    .to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0x000d,
                name: "signature_algorithms".to_string(),
                required: true,
                deprecated: false,
                security_impact: SecurityImpact::High,
                description: "Signature algorithms (RFC 5246) - Supported signature schemes"
                    .to_string(),
                rfc: "RFC 5246, RFC 8446".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0033,
                name: "key_share".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::High,
                description: "Key share (RFC 8446) - TLS 1.3 key exchange".to_string(),
                rfc: "RFC 8446".to_string(),
            },
            TlsExtensionInfo {
                id: 0x002d,
                name: "psk_key_exchange_modes".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::High,
                description: "PSK key exchange modes (RFC 8446) - TLS 1.3 PSK".to_string(),
                rfc: "RFC 8446".to_string(),
            },
            // ===== MEDIUM SECURITY EXTENSIONS =====
            TlsExtensionInfo {
                id: 0x000a,
                name: "supported_groups (ECC)".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description:
                    "Supported elliptic curves (RFC 4492, RFC 8422) - ECC curve negotiation"
                        .to_string(),
                rfc: "RFC 4492, RFC 8422".to_string(),
            },
            TlsExtensionInfo {
                id: 0x000b,
                name: "ec_point_formats".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "EC point formats (RFC 4492) - Uncompressed point format".to_string(),
                rfc: "RFC 4492".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0010,
                name: "application_layer_protocol_negotiation (ALPN)".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "ALPN (RFC 7301) - Application protocol negotiation (HTTP/2, HTTP/3)"
                    .to_string(),
                rfc: "RFC 7301".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0023,
                name: "session_ticket".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "Session tickets (RFC 5077) - Stateless session resumption"
                    .to_string(),
                rfc: "RFC 5077".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0012,
                name: "signed_certificate_timestamp (CT)".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "Certificate Transparency (RFC 6962) - SCT for CT logs".to_string(),
                rfc: "RFC 6962".to_string(),
            },
            // ===== LOW PRIORITY EXTENSIONS =====
            TlsExtensionInfo {
                id: 0x0001,
                name: "max_fragment_length".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Maximum fragment length (RFC 6066) - Negotiate smaller TLS records"
                    .to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0003,
                name: "trusted_ca_keys".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Trusted CA keys (RFC 6066) - Client indicates trusted CAs"
                    .to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0004,
                name: "truncated_hmac".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Truncated HMAC (RFC 6066) - Reduce HMAC to 80 bits".to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0x000f,
                name: "heartbeat".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Heartbeat (RFC 6520) - Keep-alive mechanism (Heartbleed vector!)"
                    .to_string(),
                rfc: "RFC 6520".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0015,
                name: "padding".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Padding (RFC 7685) - Pad ClientHello to avoid fragmentation"
                    .to_string(),
                rfc: "RFC 7685".to_string(),
            },
            TlsExtensionInfo {
                id: 0x001b,
                name: "compress_certificate".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Certificate compression (RFC 8879) - Compress certificate messages"
                    .to_string(),
                rfc: "RFC 8879".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0029,
                name: "pre_shared_key".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "Pre-shared key (RFC 8446) - TLS 1.3 PSK identity".to_string(),
                rfc: "RFC 8446".to_string(),
            },
            TlsExtensionInfo {
                id: 0x002a,
                name: "early_data".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "Early data / 0-RTT (RFC 8446) - TLS 1.3 zero round-trip".to_string(),
                rfc: "RFC 8446".to_string(),
            },
            TlsExtensionInfo {
                id: 0x002c,
                name: "cookie".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "Cookie (RFC 8446) - TLS 1.3 HelloRetryRequest statelessness"
                    .to_string(),
                rfc: "RFC 8446".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0032,
                name: "supported_groups (FFDHE)".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Medium,
                description: "Finite field Diffie-Hellman groups (RFC 7919)".to_string(),
                rfc: "RFC 7919".to_string(),
            },
            // ===== DEPRECATED / LEGACY EXTENSIONS =====
            TlsExtensionInfo {
                id: 0x3374,
                name: "next_protocol_negotiation (NPN)".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "NPN (Deprecated) - Replaced by ALPN. Used in SPDY".to_string(),
                rfc: "Draft (never standardized)".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0002,
                name: "client_certificate_url".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "Client certificate URL (RFC 6066) - Rarely used".to_string(),
                rfc: "RFC 6066".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0006,
                name: "user_mapping".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "User mapping (RFC 4681) - Obsolete".to_string(),
                rfc: "RFC 4681".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0007,
                name: "client_authz".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "Client authorization (RFC 5878) - Obsolete".to_string(),
                rfc: "RFC 5878".to_string(),
            },
            TlsExtensionInfo {
                id: 0x0008,
                name: "server_authz".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "Server authorization (RFC 5878) - Obsolete".to_string(),
                rfc: "RFC 5878".to_string(),
            },
            TlsExtensionInfo {
                id: 0x000c,
                name: "srp".to_string(),
                required: false,
                deprecated: true,
                security_impact: SecurityImpact::Deprecated,
                description: "SRP (RFC 5054) - Secure Remote Password, rarely used".to_string(),
                rfc: "RFC 5054".to_string(),
            },
            TlsExtensionInfo {
                id: 0x000e,
                name: "use_srtp".to_string(),
                required: false,
                deprecated: false,
                security_impact: SecurityImpact::Low,
                description: "SRTP (RFC 5764) - For DTLS-SRTP (WebRTC)".to_string(),
                rfc: "RFC 5764".to_string(),
            },
        ]
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

        // Check all known extensions
        for ext_info in Self::all_extensions() {
            let supported = supported_ids.contains(&ext_info.id);

            let (data_length, parsed_data) = if supported {
                if let Some((_, data)) = extensions.iter().find(|(id, _)| *id == ext_info.id) {
                    (
                        Some(data.len()),
                        Some(Self::parse_extension_data(ext_info.id, data)),
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

        let total_supported = results.iter().filter(|r| r.supported).count();

        let critical_missing: Vec<String> = results
            .iter()
            .filter(|r| r.security_impact == SecurityImpact::Critical && !r.supported)
            .map(|r| r.extension_name.clone())
            .collect();

        let deprecated_present: Vec<String> = results
            .iter()
            .filter(|r| r.deprecated && r.supported)
            .map(|r| r.extension_name.clone())
            .collect();

        TlsExtensionsComplete {
            extensions: results,
            total_supported,
            critical_missing,
            deprecated_present,
        }
    }

    fn parse_extension_data(extension_id: u16, data: &[u8]) -> String {
        match extension_id {
            0x0000 => format!("SNI data ({} bytes)", data.len()),
            0x0005 => format!("OCSP request ({} bytes)", data.len()),
            0x000a => format!("Supported groups ({} bytes)", data.len()),
            0x000d => format!("Signature algorithms ({} bytes)", data.len()),
            0x0010 => format!("ALPN protocols ({} bytes)", data.len()),
            0x0023 => format!("Session ticket ({} bytes)", data.len()),
            0x002b => format!("Supported versions ({} bytes)", data.len()),
            0x0033 => format!("Key share ({} bytes)", data.len()),
            _ => format!("{} bytes", data.len()),
        }
    }
}

/// TLS extension information
#[derive(Debug, Clone)]
pub struct TlsExtensionInfo {
    pub id: u16,
    pub name: String,
    pub required: bool,
    pub deprecated: bool,
    pub security_impact: SecurityImpact,
    pub description: String,
    pub rfc: String,
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
        assert!(critical.contains(&0x0000)); // SNI
        assert!(critical.contains(&0xff01)); // Renegotiation info
        assert!(critical.contains(&0x0017)); // Extended master secret
    }

    #[test]
    fn test_deprecated_extensions() {
        let deprecated = TlsExtensions::deprecated_extensions();
        assert!(deprecated.contains(&0x3374)); // NPN
    }

    #[test]
    fn test_get_extension_info() {
        let sni = TlsExtensions::get_extension_info(0x0000).unwrap();
        assert_eq!(sni.name, "server_name (SNI)");
        assert_eq!(sni.security_impact, SecurityImpact::Critical);
    }
}
