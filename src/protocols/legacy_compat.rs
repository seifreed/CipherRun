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
use std::time::Duration;

const CIPHER_TIMEOUT: Duration = Duration::from_secs(3);

/// Legacy compatibility tester
pub struct LegacyCompatTester {
    target: Target,
}

impl LegacyCompatTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test if a specific cipher suite is supported by the server.
    /// Returns Ok(false) on any connection or negotiation failure.
    async fn test_cipher_support(&self, cipher: &str) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVersion};

        let addr = match self.target.socket_addrs().first().copied() {
            Some(a) => a,
            None => return Ok(false),
        };
        let hostname = self.target.hostname.clone();
        let cipher = cipher.to_string();

        let stream =
            match crate::utils::network::connect_with_timeout(addr, CIPHER_TIMEOUT, None).await {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        let result = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;

            if cipher.starts_with("EXP") || cipher.starts_with("SSL_CK") {
                let _ = builder.set_min_proto_version(Some(SslVersion::SSL3));
            }

            match builder.set_cipher_list(&cipher) {
                Ok(_) => {
                    let connector = builder.build();
                    Ok(connector.connect(&hostname, std_stream).is_ok())
                }
                Err(_) => Ok(false),
            }
        })
        .await
        .map_err(|e| crate::error::TlsError::Other(format!("spawn_blocking failed: {e}")))??;

        Ok(result)
    }

    async fn test_baseline_tls_connectivity(&self) -> Result<bool> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let addr = match self.target.socket_addrs().first().copied() {
            Some(a) => a,
            None => return Ok(false),
        };
        let hostname = self.target.hostname.clone();

        let stream =
            match crate::utils::network::connect_with_timeout(addr, CIPHER_TIMEOUT, None).await {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();
            Ok(connector.connect(&hostname, std_stream).is_ok())
        })
        .await
        .map_err(|e| crate::error::TlsError::Other(format!("spawn_blocking failed: {e}")))?
    }

    /// Run complete legacy compatibility tests
    pub async fn test(&self) -> Result<LegacyCompatResult> {
        let sslv2_support = self.test_sslv2_support().await?;
        let weak_ciphers = self.test_weak_ciphers().await?;
        let export_ciphers = self.test_export_ciphers().await?;
        let null_ciphers = self.test_null_ciphers().await?;
        let anonymous_dh = self.test_anonymous_dh().await?;
        let legacy_handshakes = self.test_legacy_handshakes().await?;

        let baseline_tls_ok = self.test_baseline_tls_connectivity().await?;
        let has_legacy_evidence = Self::has_legacy_evidence(
            &sslv2_support,
            &weak_ciphers,
            &export_ciphers,
            &null_ciphers,
            &anonymous_dh,
            &legacy_handshakes,
        );
        let inconclusive = !has_legacy_evidence && !baseline_tls_ok;
        let compatibility_level = if inconclusive {
            CompatibilityLevel::Unknown
        } else {
            self.determine_compatibility_level(&sslv2_support, &weak_ciphers, &export_ciphers)
        };

        let details = if inconclusive {
            "Compatibility: Unknown (test inconclusive). No baseline TLS handshake succeeded; legacy cipher support could not be determined".to_string()
        } else {
            format!(
                "Compatibility: {}. SSLv2: {}, Weak: {}, Export: {}, Null: {}, ADH: {}",
                compatibility_level.as_str(),
                sslv2_support.supported,
                !weak_ciphers.weak_ciphers_found.is_empty(),
                !export_ciphers.export_ciphers_found.is_empty(),
                null_ciphers.null_encryption,
                anonymous_dh.adh_support || anonymous_dh.aecdh_support
            )
        };

        Ok(LegacyCompatResult {
            sslv2_support,
            weak_ciphers,
            export_ciphers,
            null_ciphers,
            anonymous_dh,
            legacy_handshakes,
            compatibility_level,
            inconclusive,
            details,
        })
    }

    fn has_legacy_evidence(
        sslv2: &Sslv2Test,
        weak: &WeakCipherTest,
        export: &ExportCipherTest,
        null_ciphers: &NullCipherTest,
        anonymous_dh: &AnonymousDhTest,
        legacy_handshakes: &LegacyHandshakeTest,
    ) -> bool {
        sslv2.supported
            || !weak.weak_ciphers_found.is_empty()
            || !export.export_ciphers_found.is_empty()
            || null_ciphers.null_encryption
            || anonymous_dh.adh_support
            || anonymous_dh.aecdh_support
            || legacy_handshakes.sslv2_compatible_hello
            || legacy_handshakes.fragmented_handshake
            || legacy_handshakes.old_signature_algorithms
            || !legacy_handshakes.quirks.is_empty()
    }

    async fn test_sslv2_support(&self) -> Result<Sslv2Test> {
        // SSLv2 cannot be negotiated via modern OpenSSL (removed at compile time).
        // We attempt using the OpenSSL 2-cipher name format; any connection success
        // indicates SSLv2 support.  In practice this always returns false on modern
        // systems, and the DROWN tester (raw-socket SSLv2 ClientHello) is the
        // authoritative SSLv2 detection path.
        let sslv2_openssl_ciphers = [
            "RC4-MD5",
            "EXP-RC4-MD5",
            "RC2-CBC-MD5",
            "EXP-RC2-CBC-MD5",
            "IDEA-CBC-MD5",
            "DES-CBC-MD5",
            "DES-CBC3-MD5",
        ];

        let mut ciphers = Vec::new();
        for cipher in &sslv2_openssl_ciphers {
            if self.test_cipher_support(cipher).await? {
                ciphers.push(cipher.to_string());
            }
        }

        let supported = !ciphers.is_empty();
        let cipher_count = ciphers.len();
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
        let weak_cipher_names = [
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

        let mut des_support = false;
        let mut rc2_support = false;
        let mut md5_mac_support = false;
        let mut weak_ciphers_found = Vec::new();

        for cipher in &weak_cipher_names {
            if self.test_cipher_support(cipher).await? {
                weak_ciphers_found.push(cipher.to_string());
                if cipher.contains("DES") {
                    des_support = true;
                }
                if cipher.contains("RC2") {
                    rc2_support = true;
                }
                if cipher.contains("MD5") {
                    md5_mac_support = true;
                }
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

    async fn test_export_ciphers(&self) -> Result<ExportCipherTest> {
        // 40-bit export ciphers (EXP prefix, no 1024 suffix)
        let export_40bit_names = [
            "EXP-RC4-MD5",
            "EXP-RC2-CBC-MD5",
            "EXP-DES-CBC-SHA",
            "EXP-EDH-RSA-DES-CBC-SHA",
            "EXP-EDH-DSS-DES-CBC-SHA",
        ];
        // 56-bit export ciphers (EXP1024 prefix)
        let export_56bit_names = [
            "EXP1024-DES-CBC-SHA",
            "EXP1024-RC4-SHA",
            "EXP1024-RC2-CBC-MD5",
        ];

        let mut export_40bit = false;
        let mut export_56bit = false;
        let mut export_ciphers_found = Vec::new();

        for cipher in &export_40bit_names {
            if self.test_cipher_support(cipher).await? {
                export_ciphers_found.push(cipher.to_string());
                export_40bit = true;
            }
        }
        for cipher in &export_56bit_names {
            if self.test_cipher_support(cipher).await? {
                export_ciphers_found.push(cipher.to_string());
                export_56bit = true;
            }
        }

        let freak_vulnerable = !export_ciphers_found.is_empty();
        let security_concern = if freak_vulnerable {
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
        let null_cipher_names = [
            "NULL-MD5",
            "NULL-SHA",
            "NULL-SHA256",
            "AECDH-NULL-SHA",
            "ECDHE-RSA-NULL-SHA",
            "ECDHE-ECDSA-NULL-SHA",
        ];

        let mut null_ciphers_found = Vec::new();

        for cipher in &null_cipher_names {
            if self.test_cipher_support(cipher).await? {
                null_ciphers_found.push(cipher.to_string());
            }
        }

        let null_encryption = !null_ciphers_found.is_empty();
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
        let anonymous_cipher_names = [
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

        let mut adh_support = false;
        let mut aecdh_support = false;
        let mut anonymous_ciphers_found = Vec::new();

        for cipher in &anonymous_cipher_names {
            if self.test_cipher_support(cipher).await? {
                anonymous_ciphers_found.push(cipher.to_string());
                if cipher.starts_with("ADH-") {
                    adh_support = true;
                } else if cipher.starts_with("AECDH-") {
                    aecdh_support = true;
                }
            }
        }

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

        assert_eq!(result.compatibility_level, CompatibilityLevel::Unknown);
        assert!(result.inconclusive);
        assert!(!result.sslv2_support.supported);
        assert!(result.weak_ciphers.weak_ciphers_found.is_empty());
        assert!(result.export_ciphers.export_ciphers_found.is_empty());
        assert!(!result.null_ciphers.null_encryption);
        assert!(!result.anonymous_dh.adh_support);
        assert!(result.details.contains("Compatibility"));
    }

    #[tokio::test]
    async fn test_legacy_compat_inactive_target_is_inconclusive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let target = Target::with_ips(
            "localhost".to_string(),
            addr.port(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = LegacyCompatTester::new(target);
        let result = tester.test().await.unwrap();

        assert_eq!(result.compatibility_level, CompatibilityLevel::Unknown);
        assert!(
            result.inconclusive,
            "inactive target must not be classified as Modern: {result:?}"
        );
        assert!(result.details.contains("inconclusive"));
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
