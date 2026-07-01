// Cipher Mapping Parser - Parses cipher-mapping.txt

use crate::Result;
use crate::ciphers::CipherSuite;
use crate::error::TlsError;
use std::collections::HashMap;
use std::sync::Arc;

/// Get the global cipher database
///
/// Returns the database if already initialized, or initializes it on first call.
/// Returns an error if the embedded database is malformed.
pub fn cipher_db() -> Result<Arc<CipherDatabase>> {
    CIPHER_DB
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| TlsError::Other(e.clone()))
}

/// Cached embedded cipher database.
pub static CIPHER_DB: std::sync::LazyLock<std::result::Result<Arc<CipherDatabase>, String>> =
    std::sync::LazyLock::new(|| {
        CipherDatabase::load()
            .map(Arc::new)
            .map_err(|e| format!("Failed to load embedded cipher database: {e}"))
    });

/// Database of all cipher suites
pub struct CipherDatabase {
    /// Map from hexcode to cipher suite
    by_hexcode: HashMap<String, CipherSuite>,
}

impl CipherDatabase {
    /// Load cipher database from embedded data
    pub fn load() -> Result<Self> {
        let data = include_str!("../../data/cipher-mapping.txt");
        Self::parse(data)
    }

    /// Create an empty database (fallback for loading errors)
    pub fn empty() -> Self {
        Self {
            by_hexcode: HashMap::new(),
        }
    }

    /// Parse cipher-mapping.txt format
    /// Format: 0xHH,0xHH - OpenSSLName  IANAName  Version  Kx=X  Au=Y  Enc=Z  Mac=W
    pub fn parse(data: &str) -> Result<Self> {
        let mut by_hexcode = HashMap::new();

        for (line_num, line) in data.lines().enumerate() {
            // Skip comments and empty lines
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let cipher = Self::parse_line(line).map_err(|e| TlsError::ParseError {
                message: format!("Invalid cipher mapping line {}: {}", line_num + 1, e),
            })?;
            if by_hexcode.insert(cipher.hexcode.clone(), cipher).is_some() {
                return Err(TlsError::ParseError {
                    message: format!("Duplicate cipher hexcode on line {}", line_num + 1),
                });
            }
        }

        Ok(Self { by_hexcode })
    }

    /// Parse a single line from cipher-mapping.txt
    fn parse_line(line: &str) -> Result<CipherSuite> {
        // Split by " - " to separate hexcode from rest
        let (hexcode, rest) = line.split_once(" - ").ok_or_else(|| TlsError::ParseError {
            message: "Invalid format: missing ' - ' separator".to_string(),
        })?;
        // Parse hexcode (e.g., "0xCC,0x14" -> "cc14"). TLS ciphers use
        // two bytes; legacy SSLv2 ciphers in this dataset use three bytes.
        let hexcode = Self::normalize_hexcode(hexcode)?;

        // Split rest into fields
        let mut fields = rest.split_whitespace();
        let openssl_name = fields
            .next()
            .ok_or_else(|| TlsError::ParseError {
                message: "Invalid format: not enough fields".to_string(),
            })?
            .to_string();
        let iana_name = fields
            .next()
            .ok_or_else(|| TlsError::ParseError {
                message: "Invalid format: not enough fields".to_string(),
            })?
            .to_string();
        let protocol = fields
            .next()
            .ok_or_else(|| TlsError::ParseError {
                message: "Invalid format: not enough fields".to_string(),
            })?
            .to_string();

        // Parse key exchange, authentication, encryption, mac
        let mut kx = String::new();
        let mut auth = String::new();
        let mut enc = String::new();
        let mut mac = String::new();

        for field in fields {
            if let Some(value) = field.strip_prefix("Kx=") {
                kx = value.to_string();
            } else if let Some(value) = field.strip_prefix("Au=") {
                auth = value.to_string();
            } else if let Some(value) = field.strip_prefix("Enc=") {
                enc = value.to_string();
            } else if let Some(value) = field.strip_prefix("Mac=") {
                mac = value.to_string();
            }
        }
        if [kx.as_str(), auth.as_str(), enc.as_str(), mac.as_str()]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(TlsError::ParseError {
                message: "Invalid format: missing cipher attributes".to_string(),
            });
        }

        // Extract bit strength from encryption field
        let bits = Self::extract_bits(&enc);

        // Determine if export cipher
        let export = openssl_name.contains("EXP") || openssl_name.contains("EXPORT");

        Ok(CipherSuite {
            hexcode,
            openssl_name,
            iana_name,
            protocol,
            key_exchange: kx,
            authentication: auth,
            encryption: enc,
            mac,
            bits,
            export,
        })
    }

    fn normalize_hexcode(hexcode: &str) -> Result<String> {
        let hexcode = hexcode
            .trim()
            .replace("0x", "")
            .replace(",", "")
            .to_lowercase();
        if !matches!(hexcode.len(), 4 | 6) || !hexcode.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TlsError::ParseError {
                message: "Invalid format: invalid cipher hexcode".to_string(),
            });
        }
        Ok(hexcode)
    }

    /// Extract bit strength from encryption string (e.g., "AES(256)" -> 256)
    fn extract_bits(enc: &str) -> u16 {
        // Try to find number in parentheses
        if let Some(start) = enc.find('(')
            && let Some(end) = enc.find(')')
            && end > start
            && let Some(num_str) = enc.get(start + 1..end)
            && let Ok(bits) = num_str.parse::<u16>()
        {
            return bits;
        }

        // Special cases
        if enc.contains("3DES") {
            return 168;
        }
        if enc.contains("DES(") || enc == "DES" {
            return 56;
        }
        if enc.contains("RC4") {
            return 128;
        }
        // NULL ciphers carry no encryption. OpenSSL renders this as either
        // "NULL" or "None" depending on the field; both mean zero bits.
        if enc.contains("NULL") || enc.eq_ignore_ascii_case("None") {
            return 0;
        }

        // Default - unknown encryption, don't assume security
        tracing::warn!(
            "Unknown encryption algorithm, cannot determine bit strength: {}",
            enc
        );
        0
    }

    /// Get cipher by hexcode (reference)
    pub fn get_by_hexcode_ref(&self, hexcode: &str) -> Option<&CipherSuite> {
        self.by_hexcode.get(hexcode)
    }

    /// Get all ciphers
    pub fn all_ciphers(&self) -> impl Iterator<Item = &CipherSuite> {
        self.by_hexcode.values()
    }

    /// Get ciphers with forward secrecy
    pub fn forward_secrecy_ciphers(&self) -> Vec<&CipherSuite> {
        self.by_hexcode
            .values()
            .filter(|c| c.has_forward_secrecy())
            .collect()
    }

    /// Get export ciphers
    pub fn export_ciphers(&self) -> Vec<&CipherSuite> {
        self.by_hexcode.values().filter(|c| c.export).collect()
    }

    /// Get cipher count
    pub fn count(&self) -> usize {
        self.by_hexcode.len()
    }

    /// Get NULL ciphers
    pub fn null_ciphers(&self) -> Vec<&CipherSuite> {
        self.by_hexcode
            .values()
            .filter(|c| c.is_null_encryption())
            .collect()
    }

    /// Get all ciphers as a vector (cloned)
    pub fn get_all_ciphers(&self) -> Vec<CipherSuite> {
        self.by_hexcode.values().cloned().collect()
    }

    /// Get recommended ciphers (common, modern, secure)
    pub fn get_recommended_ciphers(&self) -> Vec<CipherSuite> {
        self.by_hexcode
            .values()
            .filter(|c| {
                // Filter for modern, secure ciphers
                !c.export
                    && !c.is_null_encryption()
                    && c.bits >= 128
                    && !c.encryption.contains("RC4")
                    && !c.encryption.contains("DES")
                    && !c.mac.contains("MD5")
            })
            .cloned()
            .collect()
    }

    /// Get cipher by hexcode (cloned)
    pub fn get_by_hexcode(&self, hexcode: &str) -> Option<CipherSuite> {
        self.by_hexcode.get(hexcode).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cipher_line() {
        let line = "0xCC,0x14 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  TLSv1.2  Kx=ECDH  Au=ECDSA  Enc=CHACHA20/POLY1305(256)  Mac=AEAD";

        let cipher = CipherDatabase::parse_line(line).expect("test assertion should succeed");

        assert_eq!(cipher.hexcode, "cc14");
        assert_eq!(
            cipher.openssl_name,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(cipher.protocol, "TLSv1.2");
        assert_eq!(cipher.key_exchange, "ECDH");
        assert_eq!(cipher.authentication, "ECDSA");
        assert_eq!(cipher.bits, 256);
        assert!(!cipher.export);
        assert!(cipher.has_forward_secrecy());
        assert!(cipher.is_aead());
    }

    #[test]
    fn test_parse_export_cipher() {
        let line = "0x00,0x03 - EXP-RC4-MD5  TLS_RSA_EXPORT_WITH_RC4_40_MD5  SSLv3  Kx=RSA(512)  Au=RSA  Enc=RC4(40)  Mac=MD5";

        let cipher = CipherDatabase::parse_line(line).expect("test assertion should succeed");

        assert_eq!(cipher.hexcode, "0003");
        assert_eq!(cipher.bits, 40);
        assert!(cipher.export);
    }

    #[test]
    fn test_parse_cipher_with_dash_iana_name() {
        let line = "0xFF,0x02 - GOST-GOST89MAC - TLSv1 Kx=RSA Au=RSA Enc=GOST(256) Mac=GOST89IMIT";
        let cipher = CipherDatabase::parse_line(line).expect("dash IANA name should parse");

        assert_eq!(cipher.hexcode, "ff02");
        assert_eq!(cipher.iana_name, "-");
        assert_eq!(cipher.protocol, "TLSv1");
    }

    #[test]
    fn test_load_database() {
        let db = CipherDatabase::load();
        assert!(db.is_ok());

        let db = db.expect("test assertion should succeed");
        assert!(db.count() > 100); // Should have at least 100 ciphers
    }

    #[test]
    fn test_lookup_by_hexcode() {
        let db = cipher_db().expect("embedded cipher database should load");

        // Test a common cipher
        if let Some(cipher) = db.get_by_hexcode_ref("c030") {
            assert!(cipher.openssl_name.contains("ECDHE"));
        }
    }

    #[test]
    fn test_forward_secrecy_filter() {
        let db = cipher_db().expect("embedded cipher database should load");
        let fs_ciphers = db.forward_secrecy_ciphers();

        assert!(!fs_ciphers.is_empty());
        for cipher in fs_ciphers {
            assert!(cipher.has_forward_secrecy());
        }
    }

    #[test]
    fn test_parse_line_invalid_format() {
        let line = "invalid line";
        let err = CipherDatabase::parse_line(line).expect_err("should fail");
        assert!(err.to_string().contains("Invalid format"));
    }

    #[test]
    fn test_parse_line_rejects_invalid_hexcode() {
        let line = "0xGG,0x02 - TLS_AES_256_GCM_SHA384 TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=any Au=any Enc=AESGCM(256) Mac=AEAD";
        let err = CipherDatabase::parse_line(line).expect_err("should fail");

        assert!(err.to_string().contains("invalid cipher hexcode"));
    }

    #[test]
    fn test_parse_line_rejects_missing_cipher_attributes() {
        let line = "0x13,0x02 - TLS_AES_256_GCM_SHA384 TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=any Au=any Enc=AESGCM(256)";
        let err = CipherDatabase::parse_line(line).expect_err("should fail");

        assert!(err.to_string().contains("missing cipher attributes"));
    }

    #[test]
    fn test_parse_database_rejects_invalid_cipher_line() {
        let data = "0x13,0x02 - TLS_AES_256_GCM_SHA384 TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=any Au=any Enc=AESGCM(256) Mac=AEAD\ninvalid line";
        let err = match CipherDatabase::parse(data) {
            Ok(_) => panic!("invalid cipher line should fail database parsing"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Invalid cipher mapping line 2"));
    }

    #[test]
    fn test_parse_database_rejects_duplicate_hexcode() {
        let data = "\
0x13,0x02 - TLS_AES_256_GCM_SHA384 TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=any Au=any Enc=AESGCM(256) Mac=AEAD
0x13,0x02 - TLS_AES_128_GCM_SHA256 TLS_AES_128_GCM_SHA256 TLSv1.3 Kx=any Au=any Enc=AESGCM(128) Mac=AEAD";

        let err = match CipherDatabase::parse(data) {
            Ok(_) => panic!("duplicate hexcode should fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("Duplicate cipher hexcode on line 2")
        );
    }

    #[test]
    fn test_extract_bits_special_cases() {
        assert_eq!(CipherDatabase::extract_bits("3DES"), 168);
        assert_eq!(CipherDatabase::extract_bits("DES"), 56);
        assert_eq!(CipherDatabase::extract_bits("RC4"), 128);
        assert_eq!(CipherDatabase::extract_bits("NULL"), 0);
        // OpenSSL renders NULL ciphers as "None" in the Enc field; this is a
        // known zero-bit case, not an unknown algorithm.
        assert_eq!(CipherDatabase::extract_bits("None"), 0);
    }
}
