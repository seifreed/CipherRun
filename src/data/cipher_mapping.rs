// Cipher Mapping Parser - Parses cipher-mapping.txt

use crate::ciphers::CipherSuite;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Global cipher database loaded at startup
///
/// Uses OnceLock for safe initialization with proper error handling.
static CIPHER_DB_INNER: std::sync::OnceLock<Arc<CipherDatabase>> = std::sync::OnceLock::new();

/// Get the global cipher database
///
/// Returns the database if already initialized, or initializes it on first call.
/// Initialization errors are logged and an empty database is used as fallback.
pub fn cipher_db() -> Arc<CipherDatabase> {
    CIPHER_DB_INNER
        .get_or_init(|| match CipherDatabase::load() {
            Ok(db) => Arc::new(db),
            Err(e) => {
                tracing::error!(
                    "Failed to load cipher database: {}. Using empty database.",
                    e
                );
                Arc::new(CipherDatabase::empty())
            }
        })
        .clone()
}

/// Check if the cipher database is healthy (loaded successfully with entries)
///
/// Returns true if the database is loaded and contains cipher entries.
/// Returns false if loading failed or database is empty.
pub fn cipher_db_is_healthy() -> bool {
    CIPHER_DB_INNER
        .get()
        .map(|db| db.is_healthy())
        .unwrap_or(false)
}

/// Legacy static for backward compatibility
/// Delegates to `cipher_db()` to avoid loading data twice into memory
pub static CIPHER_DB: std::sync::LazyLock<Arc<CipherDatabase>> =
    std::sync::LazyLock::new(cipher_db);

/// Database of all cipher suites
pub struct CipherDatabase {
    /// Map from hexcode to cipher suite
    by_hexcode: HashMap<String, CipherSuite>,
    /// Map from OpenSSL name to cipher suite
    by_openssl_name: HashMap<String, CipherSuite>,
    /// Map from IANA name to cipher suite
    by_iana_name: HashMap<String, CipherSuite>,
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
            by_openssl_name: HashMap::new(),
            by_iana_name: HashMap::new(),
        }
    }

    /// Parse cipher-mapping.txt format
    /// Format: 0xHH,0xHH - OpenSSLName  IANAName  Version  Kx=X  Au=Y  Enc=Z  Mac=W
    pub fn parse(data: &str) -> Result<Self> {
        let mut by_hexcode = HashMap::new();
        let mut by_openssl_name = HashMap::new();
        let mut by_iana_name = HashMap::new();

        for (line_num, line) in data.lines().enumerate() {
            // Skip comments and empty lines
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line
            match Self::parse_line(line) {
                Ok(cipher) => {
                    by_hexcode.insert(cipher.hexcode.clone(), cipher.clone());
                    by_openssl_name.insert(cipher.openssl_name.clone(), cipher.clone());
                    by_iana_name.insert(cipher.iana_name.clone(), cipher.clone());
                }
                Err(e) => {
                    // Suppress warnings for GOST ciphers (non-standard format)
                    if !line.contains("GOST") {
                        eprintln!(
                            "Warning: Failed to parse line {}: {} - {}",
                            line_num + 1,
                            line,
                            e
                        );
                    }
                }
            }
        }

        Ok(Self {
            by_hexcode,
            by_openssl_name,
            by_iana_name,
        })
    }

    /// Parse a single line from cipher-mapping.txt
    fn parse_line(line: &str) -> Result<CipherSuite> {
        // Split by " - " to separate hexcode from rest
        let parts: Vec<&str> = line.split(" - ").collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid format: missing ' - ' separator");
        }

        let hexcode = parts[0].trim();
        let rest = parts[1];

        // Parse hexcode (e.g., "0xCC,0x14" -> "cc14")
        let hexcode = hexcode.replace("0x", "").replace(",", "").to_lowercase();

        // Split rest into fields
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 3 {
            anyhow::bail!("Invalid format: not enough fields");
        }

        let openssl_name = fields[0].to_string();
        let iana_name = fields[1].to_string();
        let protocol = fields[2].to_string();

        // Parse key exchange, authentication, encryption, mac
        let mut kx = String::new();
        let mut auth = String::new();
        let mut enc = String::new();
        let mut mac = String::new();

        for field in &fields[3..] {
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

    /// Extract bit strength from encryption string (e.g., "AES(256)" -> 256)
    fn extract_bits(enc: &str) -> u16 {
        // Try to find number in parentheses
        if let Some(start) = enc.find('(')
            && let Some(end) = enc.find(')')
            && end > start
        {
            let num_str = &enc[start + 1..end];
            if let Ok(bits) = num_str.parse::<u16>() {
                return bits;
            }
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
        if enc.contains("NULL") {
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

    /// Get cipher by OpenSSL name
    pub fn get_by_openssl_name(&self, name: &str) -> Option<&CipherSuite> {
        self.by_openssl_name.get(name)
    }

    /// Get cipher by IANA name
    pub fn get_by_iana_name(&self, name: &str) -> Option<&CipherSuite> {
        self.by_iana_name.get(name)
    }

    /// Get all ciphers
    pub fn all_ciphers(&self) -> impl Iterator<Item = &CipherSuite> {
        self.by_hexcode.values()
    }

    /// Get ciphers by protocol version
    pub fn by_protocol(&self, protocol: &str) -> Vec<&CipherSuite> {
        self.by_hexcode
            .values()
            .filter(|c| c.protocol == protocol)
            .collect()
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

    /// Check if database is healthy (loaded successfully and has entries)
    pub fn is_healthy(&self) -> bool {
        !self.by_hexcode.is_empty()
    }

    /// Get cipher count
    pub fn count(&self) -> usize {
        self.by_hexcode.len()
    }

    /// Get NULL ciphers
    pub fn null_ciphers(&self) -> Vec<&CipherSuite> {
        self.by_hexcode
            .values()
            .filter(|c| c.encryption.contains("NULL"))
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
                    && !c.encryption.contains("NULL")
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
    fn test_load_database() {
        let db = CipherDatabase::load();
        assert!(db.is_ok());

        let db = db.expect("test assertion should succeed");
        assert!(db.count() > 100); // Should have at least 100 ciphers
    }

    #[test]
    fn test_lookup_by_hexcode() {
        let db = CIPHER_DB.as_ref();

        // Test a common cipher
        if let Some(cipher) = db.get_by_hexcode_ref("c030") {
            assert!(cipher.openssl_name.contains("ECDHE"));
        }
    }

    #[test]
    fn test_forward_secrecy_filter() {
        let db = CIPHER_DB.as_ref();
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
    fn test_extract_bits_special_cases() {
        assert_eq!(CipherDatabase::extract_bits("3DES"), 168);
        assert_eq!(CipherDatabase::extract_bits("DES"), 56);
        assert_eq!(CipherDatabase::extract_bits("RC4"), 128);
        assert_eq!(CipherDatabase::extract_bits("NULL"), 0);
    }
}
