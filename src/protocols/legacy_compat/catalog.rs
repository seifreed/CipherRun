use super::{CipherInfo, SecurityConcern};
use std::collections::HashMap;

/// Legacy cipher suites database
pub struct LegacyCiphers;

impl LegacyCiphers {
    /// Get all legacy cipher suites by category
    pub fn all_by_category() -> HashMap<String, Vec<String>> {
        let mut categories = HashMap::new();

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

        categories.insert(
            "Windows2003".to_string(),
            vec![
                "RC4-SHA".to_string(),
                "RC4-MD5".to_string(),
                "DES-CBC3-SHA".to_string(),
                "DES-CBC-SHA".to_string(),
            ],
        );

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
