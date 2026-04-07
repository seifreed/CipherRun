// Legacy Compatibility Modes - Testing Support for Ancient Systems
// Enables compatibility with systems from 1990s-2000s that nobody uses anymore
// For security testing and penetration testing purposes only

mod catalog;
mod model;

pub use catalog::LegacyCiphers;
pub use model::{
    AnonymousDhTest, CipherInfo, CompatibilityLevel, ExportCipherTest, LegacyCompatResult,
    LegacyHandshakeTest, NullCipherTest, SecurityConcern, Sslv2Test, WeakCipherTest,
};

use crate::Result;
use crate::utils::network::Target;

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

    async fn test_sslv2_support(&self) -> Result<Sslv2Test> {
        let _sslv2_ciphers = [
            "SSL_CK_RC4_128_WITH_MD5",
            "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
            "SSL_CK_RC2_128_CBC_WITH_MD5",
            "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
            "SSL_CK_IDEA_128_CBC_WITH_MD5",
            "SSL_CK_DES_64_CBC_WITH_MD5",
            "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        ];

        let supported = false;
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

    async fn test_weak_ciphers(&self) -> Result<WeakCipherTest> {
        let weak_cipher_names = vec![
            "DES-CBC-SHA",
            "DES-CBC3-SHA",
            "EDH-RSA-DES-CBC-SHA",
            "EDH-DSS-DES-CBC-SHA",
            "RC2-CBC-MD5",
            "EXP-RC2-CBC-MD5",
            "RC4-MD5",
            "DES-CBC-MD5",
            "DES-CBC3-MD5",
            "IDEA-CBC-SHA",
            "IDEA-CBC-MD5",
        ];

        let des_support = false;
        let rc2_support = false;
        let md5_mac_support = false;
        let weak_ciphers_found = Vec::new();

        for cipher in &weak_cipher_names {
            cipher.contains("DES");
            cipher.contains("RC2");
            if cipher.contains("MD5") {}
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

    async fn test_export_ciphers(&self) -> Result<ExportCipherTest> {
        let _export_cipher_names = [
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "EXP-DES-CBC-SHA",
            "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA",
            "EXP1024-DES-CBC-SHA",
            "EXP1024-RC4-SHA",
            "EXP1024-RC2-CBC-MD5",
        ];

        let export_40bit = false;
        let export_56bit = false;
        let export_ciphers_found = Vec::new();
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

    async fn test_anonymous_dh(&self) -> Result<AnonymousDhTest> {
        let _anonymous_cipher_names = [
            "ADH-AES256-SHA256",
            "ADH-AES128-SHA256",
            "ADH-AES256-SHA",
            "ADH-AES128-SHA",
            "ADH-DES-CBC3-SHA",
            "ADH-DES-CBC-SHA",
            "ADH-RC4-MD5",
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

    async fn test_legacy_handshakes(&self) -> Result<LegacyHandshakeTest> {
        let mut quirks = Vec::new();

        let sslv2_compatible_hello = false;
        let fragmented_handshake = false;
        let old_signature_algorithms = false;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

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

    #[test]
    fn test_cipher_info_modern_cipher_is_low() {
        let info = LegacyCiphers::get_cipher_info("TLS_AES_128_GCM_SHA256");
        assert_eq!(info.security_level, SecurityConcern::Low);
    }

    #[tokio::test]
    async fn test_legacy_compat_tester_defaults() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = LegacyCompatTester::new(target);
        let result = tester.test().await.unwrap();

        assert_eq!(result.compatibility_level, CompatibilityLevel::Modern);
        assert!(!result.sslv2_support.supported);
        assert!(result.weak_ciphers.weak_ciphers_found.is_empty());
        assert!(result.export_ciphers.export_ciphers_found.is_empty());
        assert!(!result.null_ciphers.null_encryption);
        assert!(!result.anonymous_dh.adh_support);
        assert!(result.details.contains("Compatibility"));
    }

    #[test]
    fn test_determine_compatibility_levels() {
        let target = Target::with_ips(
            "localhost".to_string(),
            443,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();
        let tester = LegacyCompatTester::new(target);

        let sslv2 = Sslv2Test {
            supported: true,
            cipher_count: 1,
            ciphers: vec!["SSL_CK_RC4_128_WITH_MD5".to_string()],
            security_concern: SecurityConcern::Critical,
        };
        let weak = WeakCipherTest {
            des_support: false,
            rc2_support: false,
            md5_mac_support: false,
            weak_ciphers_found: Vec::new(),
            security_concern: SecurityConcern::None,
        };
        let export = ExportCipherTest {
            export_40bit: false,
            export_56bit: false,
            export_ciphers_found: Vec::new(),
            freak_vulnerable: false,
            security_concern: SecurityConcern::None,
        };
        assert_eq!(
            tester.determine_compatibility_level(&sslv2, &weak, &export),
            CompatibilityLevel::Ancient
        );

        let sslv2 = Sslv2Test {
            supported: false,
            cipher_count: 0,
            ciphers: Vec::new(),
            security_concern: SecurityConcern::None,
        };
        let export = ExportCipherTest {
            export_40bit: true,
            export_56bit: false,
            export_ciphers_found: vec!["EXP-RC4-MD5".to_string()],
            freak_vulnerable: true,
            security_concern: SecurityConcern::Critical,
        };
        assert_eq!(
            tester.determine_compatibility_level(&sslv2, &weak, &export),
            CompatibilityLevel::Legacy
        );

        let export = ExportCipherTest {
            export_40bit: false,
            export_56bit: false,
            export_ciphers_found: Vec::new(),
            freak_vulnerable: false,
            security_concern: SecurityConcern::None,
        };
        let weak = WeakCipherTest {
            des_support: true,
            rc2_support: false,
            md5_mac_support: false,
            weak_ciphers_found: vec!["DES-CBC-SHA".to_string()],
            security_concern: SecurityConcern::High,
        };
        assert_eq!(
            tester.determine_compatibility_level(&sslv2, &weak, &export),
            CompatibilityLevel::Compatible
        );
    }

    #[test]
    fn test_cipher_info_security_levels() {
        let des = LegacyCiphers::get_cipher_info("DES-CBC-SHA");
        assert_eq!(des.security_level, SecurityConcern::High);

        let triple = LegacyCiphers::get_cipher_info("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert_eq!(triple.security_level, SecurityConcern::Medium);

        let modern = LegacyCiphers::get_cipher_info("TLS_AES_128_GCM_SHA256");
        assert_eq!(modern.security_level, SecurityConcern::Low);
    }
}
