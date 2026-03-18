use serde::{Deserialize, Serialize};

/// Server cipher order preference result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderPreference {
    pub server_preferred: bool,
    pub client_order_respected: bool,
    pub inconclusive: bool,
    pub test_results: Vec<CipherOrderTest>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherOrderTest {
    pub client_preference: Vec<String>,
    pub server_selected: String,
    pub matched_client_first: bool,
}

/// DH parameter strength analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhParameterAnalysis {
    pub dh_supported: bool,
    pub dh_size_bits: Option<u16>,
    pub dh_prime: Option<String>,
    pub generator: Option<u8>,
    pub strength: DhStrength,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhStrength {
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

/// ECDH curves preference order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdhCurvesAnalysis {
    pub ecdh_supported: bool,
    pub preferred_curve: Option<String>,
    pub supported_curves: Vec<String>,
    pub server_enforces_preference: bool,
    pub preference_measured: bool,
    pub details: String,
}

/// Server key exchange detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeAnalysis {
    pub algorithm: String,
    pub ephemeral: bool,
    pub key_size: Option<u16>,
    pub parameters: KeyExchangeParams,
    pub reuse_detected: bool,
    pub reuse_detection_measured: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyExchangeParams {
    Rsa { modulus_size: u16 },
    Dhe { prime_size: u16, generator: u8 },
    Ecdhe { curve: String, point_size: u16 },
    Unknown,
}
