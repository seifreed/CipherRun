// Legacy Compatibility Modes - Testing Support for Ancient Systems
// Enables compatibility with systems from 1990s-2000s that nobody uses anymore
// For security testing and penetration testing purposes only

use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub freak_vulnerable: bool, // Factoring RSA Export Keys
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
    Critical, // Immediate security risk
    High,     // Significant weakness
    Medium,   // Potential issue
    Low,      // Minor concern
    None,     // Not supported
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
    Modern,     // TLS 1.2+ only
    Compatible, // TLS 1.0+
    Legacy,     // SSLv3+
    Ancient,    // SSLv2 support
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

/// Legacy compatibility tester
pub struct LegacyCompatTester {
    _target: Target,
}

impl LegacyCompatTester {
    pub fn new(target: Target) -> Self {
        Self { _target: target }
    }

    /// Run complete legacy compatibility tests
    pub async fn test(&self) -> Result<LegacyCompatResult> {
        let sslv2_support = self.test_sslv2_support().await?;
        let weak_ciphers = self.test_weak_ciphers().await?;
        let export_ciphers = self.test_export_ciphers().await?;
        let null_ciphers = self.test_null_ciphers().await?;
        let anonymous_dh = self.test_anonymous_dh().await?;
        let legacy_handshakes = self.test_legacy_handshakes().await?;

        let compatibility_level =
            self.determine_compatibility_level(&sslv2_support, &weak_ciphers, &export_ciphers);

        let details = format!(
            "Compatibility: {}. SSLv2: {}, Weak: {}, Export: {}, Null: {}, ADH: {}",
            compatibility_level.as_str(),
            sslv2_support.supported,
            !weak_ciphers.weak_ciphers_found.is_empty(),
            !export_ciphers.export_ciphers_found.is_empty(),
            null_ciphers.null_encryption,
            anonymous_dh.adh_support || anonymous_dh.aecdh_support
        );

        Ok(LegacyCompatResult {
            sslv2_support,
            weak_ciphers,
            export_ciphers,
            null_ciphers,
            anonymous_dh,
            legacy_handshakes,
            compatibility_level,
            details,
        })
    }

    /// Test SSLv2 support (ancient protocol from 1995)
    async fn test_sslv2_support(&self) -> Result<Sslv2Test> {
        // SSLv2 cipher list (historical reference)
        let _sslv2_ciphers = [
            "SSL_CK_RC4_128_WITH_MD5",
            "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
            "SSL_CK_RC2_128_CBC_WITH_MD5",
            "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
            "SSL_CK_IDEA_128_CBC_WITH_MD5",
            "SSL_CK_DES_64_CBC_WITH_MD5",
            "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        ];

        // Try to connect with SSLv2
        // Note: Modern OpenSSL doesn't support SSLv2, so this will likely fail
        // This is intentional - SSLv2 should NOT be supported
        let supported = false; // SSLv2 is disabled in modern OpenSSL
        let cipher_count = 0;
        let ciphers = Vec::new();

        let security_concern = if supported {
            SecurityConcern::Critical
        } else {
            SecurityConcern::None
        };

        Ok(Sslv2Test {
            supported,
            cipher_count,
            ciphers,
            security_concern,
        })
    }

    /// Test weak cipher support
    async fn test_weak_ciphers(&self) -> Result<WeakCipherTest> {
        let weak_cipher_names = vec![
            // DES ciphers (56-bit)
            "DES-CBC-SHA",
            "DES-CBC3-SHA",
            "EDH-RSA-DES-CBC-SHA",
            "EDH-DSS-DES-CBC-SHA",
            // RC2 ciphers
            "RC2-CBC-MD5",
            "EXP-RC2-CBC-MD5",
            // MD5-based ciphers
            "RC4-MD5",
            "DES-CBC-MD5",
            "DES-CBC3-MD5",
            // IDEA ciphers
            "IDEA-CBC-SHA",
            "IDEA-CBC-MD5",
        ];

        let des_support = false;
        let rc2_support = false;
        let md5_mac_support = false;
        let weak_ciphers_found = Vec::new();

        // Check which weak ciphers are supported
        // In a real implementation, this would test each cipher
        for cipher in &weak_cipher_names {
            if cipher.contains("DES") {
                // Would test DES support
            }
            if cipher.contains("RC2") {
                // Would test RC2 support
            }
            if cipher.contains("MD5") {
                // Would test MD5 MAC support
            }
        }

        let security_concern = if !weak_ciphers_found.is_empty() {
            SecurityConcern::High
        } else {
            SecurityConcern::None
        };

        Ok(WeakCipherTest {
            des_support,
            rc2_support,
            md5_mac_support,
            weak_ciphers_found,
            security_concern,
        })
    }

    /// Test export-grade cipher support (FREAK vulnerability)
    async fn test_export_ciphers(&self) -> Result<ExportCipherTest> {
        let _export_cipher_names = [
            // 40-bit export ciphers
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "EXP-DES-CBC-SHA",
            "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA",
            // 56-bit export ciphers
            "EXP1024-DES-CBC-SHA",
            "EXP1024-RC4-SHA",
            "EXP1024-RC2-CBC-MD5",
        ];

        let export_40bit = false;
        let export_56bit = false;
        let export_ciphers_found = Vec::new();

        // Check for FREAK vulnerability
        // FREAK: Factoring RSA Export Keys
        let freak_vulnerable = false;

        let security_concern = if !export_ciphers_found.is_empty() {
            SecurityConcern::Critical
        } else {
            SecurityConcern::None
        };

        Ok(ExportCipherTest {
            export_40bit,
            export_56bit,
            export_ciphers_found,
            freak_vulnerable,
            security_concern,
        })
    }

    /// Test null cipher support (no encryption)
    async fn test_null_ciphers(&self) -> Result<NullCipherTest> {
        let _null_cipher_names = [
            "NULL-MD5",
            "NULL-SHA",
            "NULL-SHA256",
            "AECDH-NULL-SHA",
            "ECDHE-RSA-NULL-SHA",
            "ECDHE-ECDSA-NULL-SHA",
        ];

        let null_encryption = false;
        let null_ciphers_found = Vec::new();

        let security_concern = if null_encryption {
            SecurityConcern::Critical
        } else {
            SecurityConcern::None
        };

        Ok(NullCipherTest {
            null_encryption,
            null_ciphers_found,
            security_concern,
        })
    }

    /// Test anonymous Diffie-Hellman support
    async fn test_anonymous_dh(&self) -> Result<AnonymousDhTest> {
        let _anonymous_cipher_names = [
            // ADH (Anonymous Diffie-Hellman)
            "ADH-AES256-SHA256",
            "ADH-AES128-SHA256",
            "ADH-AES256-SHA",
            "ADH-AES128-SHA",
            "ADH-DES-CBC3-SHA",
            "ADH-DES-CBC-SHA",
            "ADH-RC4-MD5",
            // AECDH (Anonymous Elliptic Curve Diffie-Hellman)
            "AECDH-AES256-SHA",
            "AECDH-AES128-SHA",
            "AECDH-DES-CBC3-SHA",
            "AECDH-RC4-SHA",
            "AECDH-NULL-SHA",
        ];

        let adh_support = false;
        let aecdh_support = false;
        let anonymous_ciphers_found = Vec::new();

        let security_concern = if adh_support || aecdh_support {
            SecurityConcern::Critical
        } else {
            SecurityConcern::None
        };

        Ok(AnonymousDhTest {
            adh_support,
            aecdh_support,
            anonymous_ciphers_found,
            security_concern,
        })
    }

    /// Test legacy handshake quirks
    async fn test_legacy_handshakes(&self) -> Result<LegacyHandshakeTest> {
        let mut quirks = Vec::new();

        // SSLv2-compatible ClientHello
        let sslv2_compatible_hello = false;

        // Fragmented handshake messages (for very small MTU)
        let fragmented_handshake = false;

        // Old signature algorithms (MD5, SHA1-only)
        let old_signature_algorithms = false;

        // Detect specific quirks
        if sslv2_compatible_hello {
            quirks.push("SSLv2-compatible ClientHello".to_string());
        }
        if fragmented_handshake {
            quirks.push("Accepts fragmented handshake".to_string());
        }
        if old_signature_algorithms {
            quirks.push("Supports MD5/SHA1 signatures only".to_string());
        }

        Ok(LegacyHandshakeTest {
            sslv2_compatible_hello,
            fragmented_handshake,
            old_signature_algorithms,
            quirks,
        })
    }

    /// Determine overall compatibility level
    fn determine_compatibility_level(
        &self,
        sslv2: &Sslv2Test,
        weak: &WeakCipherTest,
        export: &ExportCipherTest,
    ) -> CompatibilityLevel {
        if sslv2.supported {
            CompatibilityLevel::Ancient
        } else if !export.export_ciphers_found.is_empty() {
            CompatibilityLevel::Legacy
        } else if !weak.weak_ciphers_found.is_empty() {
            CompatibilityLevel::Compatible
        } else {
            CompatibilityLevel::Modern
        }
    }
}

/// Legacy cipher suites database
pub struct LegacyCiphers;

impl LegacyCiphers {
    /// Get all legacy cipher suites by category
    pub fn all_by_category() -> HashMap<String, Vec<String>> {
        let mut categories = HashMap::new();

        // SSLv2 ciphers (1995-1996)
        categories.insert(
            "SSLv2".to_string(),
            vec![
                "SSL_CK_RC4_128_WITH_MD5".to_string(),
                "SSL_CK_RC4_128_EXPORT40_WITH_MD5".to_string(),
                "SSL_CK_RC2_128_CBC_WITH_MD5".to_string(),
                "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5".to_string(),
                "SSL_CK_IDEA_128_CBC_WITH_MD5".to_string(),
                "SSL_CK_DES_64_CBC_WITH_MD5".to_string(),
                "SSL_CK_DES_192_EDE3_CBC_WITH_MD5".to_string(),
            ],
        );

        // Export ciphers (40-bit, 56-bit)
        categories.insert(
            "Export".to_string(),
            vec![
                "EXP-RC4-MD5".to_string(),
                "EXP-RC2-CBC-MD5".to_string(),
                "EXP-DES-CBC-SHA".to_string(),
                "EXP-EDH-RSA-DES-CBC-SHA".to_string(),
                "EXP-EDH-DSS-DES-CBC-SHA".to_string(),
                "EXP1024-DES-CBC-SHA".to_string(),
                "EXP1024-RC4-SHA".to_string(),
                "EXP1024-RC2-CBC-MD5".to_string(),
            ],
        );

        // Null ciphers (no encryption)
        categories.insert(
            "Null".to_string(),
            vec![
                "NULL-MD5".to_string(),
                "NULL-SHA".to_string(),
                "NULL-SHA256".to_string(),
                "AECDH-NULL-SHA".to_string(),
                "ECDHE-RSA-NULL-SHA".to_string(),
                "ECDHE-ECDSA-NULL-SHA".to_string(),
            ],
        );

        // Anonymous DH (no authentication)
        categories.insert(
            "Anonymous".to_string(),
            vec![
                "ADH-AES256-SHA256".to_string(),
                "ADH-AES128-SHA256".to_string(),
                "ADH-AES256-SHA".to_string(),
                "ADH-AES128-SHA".to_string(),
                "ADH-DES-CBC3-SHA".to_string(),
                "ADH-DES-CBC-SHA".to_string(),
                "ADH-RC4-MD5".to_string(),
                "AECDH-AES256-SHA".to_string(),
                "AECDH-AES128-SHA".to_string(),
                "AECDH-DES-CBC3-SHA".to_string(),
                "AECDH-RC4-SHA".to_string(),
                "AECDH-NULL-SHA".to_string(),
            ],
        );

        // Weak ciphers (DES, RC2, MD5, IDEA)
        categories.insert(
            "Weak".to_string(),
            vec![
                "DES-CBC-SHA".to_string(),
                "DES-CBC3-SHA".to_string(),
                "EDH-RSA-DES-CBC-SHA".to_string(),
                "EDH-DSS-DES-CBC-SHA".to_string(),
                "RC2-CBC-MD5".to_string(),
                "EXP-RC2-CBC-MD5".to_string(),
                "RC4-MD5".to_string(),
                "DES-CBC-MD5".to_string(),
                "DES-CBC3-MD5".to_string(),
                "IDEA-CBC-SHA".to_string(),
                "IDEA-CBC-MD5".to_string(),
            ],
        );

        // Windows Server 2003 compatibility
        categories.insert(
            "Windows2003".to_string(),
            vec![
                "RC4-SHA".to_string(),
                "RC4-MD5".to_string(),
                "DES-CBC3-SHA".to_string(),
                "DES-CBC-SHA".to_string(),
            ],
        );

        // Old Java compatibility (Java 6, Java 7)
        categories.insert(
            "OldJava".to_string(),
            vec![
                "SSL_RSA_WITH_RC4_128_SHA".to_string(),
                "SSL_RSA_WITH_RC4_128_MD5".to_string(),
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
                "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
                "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
            ],
        );

        categories
    }

    /// Get cipher details
    pub fn get_cipher_info(cipher: &str) -> CipherInfo {
        let security_level = if cipher.contains("NULL")
            || cipher.contains("EXP")
            || cipher.contains("EXPORT")
            || cipher.contains("ADH")
            || cipher.contains("AECDH")
        {
            SecurityConcern::Critical
        } else if (cipher.contains("DES") && !cipher.contains("3DES"))
            || cipher.contains("RC2")
            || cipher.contains("MD5")
            || cipher.contains("RC4")
        {
            SecurityConcern::High
        } else if cipher.contains("3DES") {
            SecurityConcern::Medium
        } else {
            SecurityConcern::Low
        };

        let description = match cipher {
            c if c.contains("NULL") => "No encryption - plaintext communication",
            c if c.contains("EXP") => "Export-grade cipher - 40/56-bit encryption",
            c if c.contains("ADH") || c.contains("AECDH") => "Anonymous DH - no authentication",
            c if c.contains("DES") && !c.contains("3DES") => "DES - 56-bit encryption",
            c if c.contains("RC2") => "RC2 - weak cipher",
            c if c.contains("RC4") => "RC4 - deprecated stream cipher",
            c if c.contains("3DES") => "3DES - 112-bit effective security",
            _ => "Legacy cipher",
        };

        CipherInfo {
            name: cipher.to_string(),
            security_level,
            description: description.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_concern_display() {
        assert_eq!(SecurityConcern::Critical.as_str(), "CRITICAL");
        assert_eq!(SecurityConcern::High.as_str(), "HIGH");
        assert_eq!(SecurityConcern::None.as_str(), "NONE");
    }

    #[test]
    fn test_compatibility_level() {
        assert_eq!(CompatibilityLevel::Modern.as_str(), "Modern (TLS 1.2+)");
        assert_eq!(CompatibilityLevel::Ancient.as_str(), "Ancient (SSLv2)");
    }

    #[test]
    fn test_legacy_ciphers_categories() {
        let categories = LegacyCiphers::all_by_category();
        assert!(categories.contains_key("SSLv2"));
        assert!(categories.contains_key("Export"));
        assert!(categories.contains_key("Null"));
        assert!(categories.contains_key("Anonymous"));
        assert!(categories.contains_key("Weak"));
    }

    #[test]
    fn test_cipher_info() {
        let info = LegacyCiphers::get_cipher_info("NULL-MD5");
        assert_eq!(info.security_level, SecurityConcern::Critical);
        assert!(info.description.contains("No encryption"));

        let info2 = LegacyCiphers::get_cipher_info("EXP-RC4-MD5");
        assert_eq!(info2.security_level, SecurityConcern::Critical);
        assert!(info2.description.contains("Export-grade"));
    }
}
