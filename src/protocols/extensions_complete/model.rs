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
    Critical,
    High,
    Medium,
    Low,
    Deprecated,
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
