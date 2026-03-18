use serde::{Deserialize, Serialize};

/// Legacy compatibility test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCompatResult {
    pub sslv2_support: Sslv2Test,
    pub weak_ciphers: WeakCipherTest,
    pub export_ciphers: ExportCipherTest,
    pub null_ciphers: NullCipherTest,
    pub anonymous_dh: AnonymousDhTest,
    pub legacy_handshakes: LegacyHandshakeTest,
    pub compatibility_level: CompatibilityLevel,
    pub details: String,
}

/// SSLv2 support test (pre-1996 protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sslv2Test {
    pub supported: bool,
    pub cipher_count: usize,
    pub ciphers: Vec<String>,
    pub security_concern: SecurityConcern,
}

/// Weak cipher support (DES, RC2, MD5, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakCipherTest {
    pub des_support: bool,
    pub rc2_support: bool,
    pub md5_mac_support: bool,
    pub weak_ciphers_found: Vec<String>,
    pub security_concern: SecurityConcern,
}

/// Export-grade cipher support (40-bit, 56-bit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportCipherTest {
    pub export_40bit: bool,
    pub export_56bit: bool,
    pub export_ciphers_found: Vec<String>,
    pub freak_vulnerable: bool,
    pub security_concern: SecurityConcern,
}

/// Null cipher support (no encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullCipherTest {
    pub null_encryption: bool,
    pub null_ciphers_found: Vec<String>,
    pub security_concern: SecurityConcern,
}

/// Anonymous Diffie-Hellman support (no authentication)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousDhTest {
    pub adh_support: bool,
    pub aecdh_support: bool,
    pub anonymous_ciphers_found: Vec<String>,
    pub security_concern: SecurityConcern,
}

/// Legacy handshake quirks and compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyHandshakeTest {
    pub sslv2_compatible_hello: bool,
    pub fragmented_handshake: bool,
    pub old_signature_algorithms: bool,
    pub quirks: Vec<String>,
}

/// Security concern level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityConcern {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl SecurityConcern {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityConcern::Critical => "CRITICAL",
            SecurityConcern::High => "HIGH",
            SecurityConcern::Medium => "MEDIUM",
            SecurityConcern::Low => "LOW",
            SecurityConcern::None => "NONE",
        }
    }
}

/// Compatibility level with ancient systems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatibilityLevel {
    Modern,
    Compatible,
    Legacy,
    Ancient,
}

impl CompatibilityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompatibilityLevel::Modern => "Modern (TLS 1.2+)",
            CompatibilityLevel::Compatible => "Compatible (TLS 1.0+)",
            CompatibilityLevel::Legacy => "Legacy (SSLv3+)",
            CompatibilityLevel::Ancient => "Ancient (SSLv2)",
        }
    }
}

/// Cipher information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    pub name: String,
    pub security_level: SecurityConcern,
    pub description: String,
}
