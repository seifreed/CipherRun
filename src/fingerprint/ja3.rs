// JA3 TLS Client Fingerprinting
// Implements the JA3 algorithm for generating MD5 fingerprints of TLS ClientHello messages
// Reference: https://github.com/salesforce/ja3

use crate::fingerprint::client_hello_capture::ClientHelloCapture;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JA3 Fingerprint structure containing the raw string and hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    /// Raw JA3 string (SSLVersion,Ciphers,Extensions,Curves,PointFormats)
    pub ja3_string: String,

    /// MD5 hash of JA3 string (32 hex characters)
    pub ja3_hash: String,

    /// SSL/TLS version (decimal, e.g., 771 for TLS 1.2)
    pub ssl_version: u16,

    /// Cipher suites (GREASE filtered)
    pub ciphers: Vec<u16>,

    /// Extensions (GREASE filtered)
    pub extensions: Vec<u16>,

    /// Supported groups/curves (GREASE filtered)
    pub curves: Vec<u16>,

    /// EC point formats
    pub point_formats: Vec<u8>,
}

impl Ja3Fingerprint {
    /// Generate JA3 fingerprint from ClientHello
    pub fn from_client_hello(client_hello: &ClientHelloCapture) -> Self {
        // 1. Extract SSL version
        let ssl_version = client_hello.version;

        // 2. Extract and filter cipher suites (remove GREASE)
        let ciphers: Vec<u16> = client_hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|&c| !Self::is_grease(c))
            .collect();

        // 3. Extract and filter extensions (remove GREASE and padding)
        let extensions: Vec<u16> = client_hello
            .extensions
            .iter()
            .map(|e| e.extension_type)
            .filter(|&t| !Self::is_grease(t) && t != 21) // Filter GREASE and padding (21)
            .collect();

        // 4. Extract supported groups/curves from extensions
        let curves = client_hello.get_supported_groups();
        let curves_filtered: Vec<u16> = curves
            .iter()
            .copied()
            .filter(|&c| !Self::is_grease(c))
            .collect();

        // 5. Extract EC point formats from extensions
        let point_formats = client_hello.get_point_formats();

        // 6. Build JA3 string
        let ja3_string = Self::build_ja3_string(
            ssl_version,
            &ciphers,
            &extensions,
            &curves_filtered,
            &point_formats,
        );

        // 7. Calculate MD5 hash
        let ja3_hash = Self::calculate_md5(&ja3_string);

        Self {
            ja3_string,
            ja3_hash,
            ssl_version,
            ciphers,
            extensions,
            curves: curves_filtered,
            point_formats,
        }
    }

    /// Check if a value is GREASE (RFC 8701)
    /// GREASE values follow the pattern: 0x0a0a, 0x1a1a, 0x2a2a, etc.
    /// Both bytes must have same nibbles: 0xXaXa where X is any hex digit
    fn is_grease(value: u16) -> bool {
        // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
        // 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
        // 0xeaea, 0xfafa
        // Check: low nibble of each byte is 0xa, and high nibbles match across bytes
        let low_byte = (value & 0xff) as u8;
        let high_byte = ((value >> 8) & 0xff) as u8;
        (low_byte & 0x0f) == 0x0a && (high_byte & 0x0f) == 0x0a && (low_byte >> 4) == (high_byte >> 4)
    }

    /// Build JA3 string from components
    /// Format: SSLVersion,Ciphers,Extensions,Curves,PointFormats
    fn build_ja3_string(
        ssl_version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        curves: &[u16],
        point_formats: &[u8],
    ) -> String {
        let mut parts = Vec::new();

        // Part 1: SSL version (decimal)
        parts.push(ssl_version.to_string());

        // Part 2: Cipher suites (decimal, dash-separated)
        let ciphers_str = if ciphers.is_empty() {
            String::new()
        } else {
            ciphers
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        parts.push(ciphers_str);

        // Part 3: Extensions (decimal, dash-separated)
        let extensions_str = if extensions.is_empty() {
            String::new()
        } else {
            extensions
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        parts.push(extensions_str);

        // Part 4: Supported groups/curves (decimal, dash-separated)
        let curves_str = if curves.is_empty() {
            String::new()
        } else {
            curves
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        parts.push(curves_str);

        // Part 5: EC point formats (decimal, dash-separated)
        let formats_str = if point_formats.is_empty() {
            String::new()
        } else {
            point_formats
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        parts.push(formats_str);

        parts.join(",")
    }

    /// Calculate MD5 hash of JA3 string
    fn calculate_md5(ja3_string: &str) -> String {
        let digest = md5::compute(ja3_string.as_bytes());
        format!("{:x}", digest)
    }

    /// Get a human-readable description of the SSL/TLS version
    pub fn ssl_version_name(&self) -> &'static str {
        match self.ssl_version {
            0x0200 => "SSL 2.0",
            0x0300 => "SSL 3.0",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown",
        }
    }

    /// Get named curves as string array
    pub fn curve_names(&self) -> Vec<String> {
        self.curves
            .iter()
            .map(|&id| Self::curve_name(id).to_string())
            .collect()
    }

    /// Get curve name from ID
    fn curve_name(id: u16) -> &'static str {
        match id {
            23 => "secp256r1",
            24 => "secp384r1",
            25 => "secp521r1",
            29 => "X25519",
            30 => "X448",
            256 => "ffdhe2048",
            257 => "ffdhe3072",
            258 => "ffdhe4096",
            259 => "ffdhe6144",
            260 => "ffdhe8192",
            _ => "unknown",
        }
    }
}

/// JA3 Signature from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Signature {
    /// Friendly name (e.g., "Chrome 120", "Firefox 121")
    pub name: String,

    /// Category (Browser, Malware, Tool, Library, etc.)
    pub category: String,

    /// Detailed description
    pub description: String,

    /// Threat level (none, low, medium, high, critical)
    pub threat_level: String,
}

/// JA3 signature database
#[derive(Debug, Clone)]
pub struct Ja3Database {
    signatures: HashMap<String, Ja3Signature>,
}

impl Ja3Database {
    /// Create a new empty database
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Load database from JSON file
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let signatures: HashMap<String, Ja3Signature> = serde_json::from_str(&contents)?;
        Ok(Self { signatures })
    }

    /// Load default embedded database
    pub fn default() -> Self {
        let mut signatures = HashMap::new();

        // Add known signatures
        signatures.insert(
            "773906b0efdefa24a7f2b8eb6985bf37".to_string(),
            Ja3Signature {
                name: "Chrome 120".to_string(),
                category: "Browser".to_string(),
                description: "Google Chrome 120.x on Windows".to_string(),
                threat_level: "none".to_string(),
            },
        );

        signatures.insert(
            "a0e9f5d64349fb13191bc781f81f42e1".to_string(),
            Ja3Signature {
                name: "Cobalt Strike".to_string(),
                category: "Malware".to_string(),
                description: "Cobalt Strike C2 beacon".to_string(),
                threat_level: "high".to_string(),
            },
        );

        signatures.insert(
            "e7d705a3286e19ea42f587b344ee6865".to_string(),
            Ja3Signature {
                name: "Metasploit".to_string(),
                category: "Tool".to_string(),
                description: "Metasploit Framework".to_string(),
                threat_level: "medium".to_string(),
            },
        );

        signatures.insert(
            "51c64c77e60f3980eea90869b68c58a8".to_string(),
            Ja3Signature {
                name: "Firefox 121".to_string(),
                category: "Browser".to_string(),
                description: "Mozilla Firefox 121.x".to_string(),
                threat_level: "none".to_string(),
            },
        );

        signatures.insert(
            "ada70206e40642a3e4461f35503241d5".to_string(),
            Ja3Signature {
                name: "Safari 17".to_string(),
                category: "Browser".to_string(),
                description: "Apple Safari 17.x on macOS".to_string(),
                threat_level: "none".to_string(),
            },
        );

        signatures.insert(
            "6734f37431670b3ab4292b8f60f29984".to_string(),
            Ja3Signature {
                name: "curl".to_string(),
                category: "Tool".to_string(),
                description: "curl command-line tool".to_string(),
                threat_level: "none".to_string(),
            },
        );

        signatures.insert(
            "e35df3e00ca4ef31d42b34bebaa2f86e".to_string(),
            Ja3Signature {
                name: "Python Requests".to_string(),
                category: "Library".to_string(),
                description: "Python requests library".to_string(),
                threat_level: "none".to_string(),
            },
        );

        signatures.insert(
            "b32309a26951912be7dba376398abc3b".to_string(),
            Ja3Signature {
                name: "OpenSSL".to_string(),
                category: "Library".to_string(),
                description: "OpenSSL s_client".to_string(),
                threat_level: "none".to_string(),
            },
        );

        Self { signatures }
    }

    /// Match a JA3 hash against the database
    pub fn match_fingerprint(&self, ja3_hash: &str) -> Option<&Ja3Signature> {
        self.signatures.get(ja3_hash)
    }

    /// Add a signature to the database
    pub fn add_signature(&mut self, ja3_hash: String, signature: Ja3Signature) {
        self.signatures.insert(ja3_hash, signature);
    }

    /// Get all signatures
    pub fn signatures(&self) -> &HashMap<String, Ja3Signature> {
        &self.signatures
    }
}

impl Default for Ja3Database {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        // GREASE values should be detected
        assert!(Ja3Fingerprint::is_grease(0x0a0a));
        assert!(Ja3Fingerprint::is_grease(0x1a1a));
        assert!(Ja3Fingerprint::is_grease(0x2a2a));
        assert!(Ja3Fingerprint::is_grease(0x3a3a));
        assert!(Ja3Fingerprint::is_grease(0xfafa));

        // Non-GREASE values should not be detected
        assert!(!Ja3Fingerprint::is_grease(0x0000));
        assert!(!Ja3Fingerprint::is_grease(0x0001));
        assert!(!Ja3Fingerprint::is_grease(0x002f));
        assert!(!Ja3Fingerprint::is_grease(0xc02f));
    }

    #[test]
    fn test_ja3_string_building() {
        let ja3_string = Ja3Fingerprint::build_ja3_string(
            771,  // TLS 1.2
            &[49195, 49199, 52393, 52392],
            &[0, 10, 11, 13, 35],
            &[29, 23, 24],
            &[0],
        );

        assert_eq!(
            ja3_string,
            "771,49195-49199-52393-52392,0-10-11-13-35,29-23-24,0"
        );
    }

    #[test]
    fn test_md5_calculation() {
        let ja3_string = "771,49195-49199-52393-52392,0-10-11-13-35,29-23-24,0";
        let hash = Ja3Fingerprint::calculate_md5(ja3_string);

        // MD5 hash should be 32 hex characters
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_database_matching() {
        let db = Ja3Database::default();

        // Test known signature
        let chrome_sig = db.match_fingerprint("773906b0efdefa24a7f2b8eb6985bf37");
        assert!(chrome_sig.is_some());
        assert_eq!(chrome_sig.unwrap().category, "Browser");

        // Test unknown signature
        let unknown = db.match_fingerprint("0000000000000000000000000000000");
        assert!(unknown.is_none());
    }

    #[test]
    fn test_ssl_version_names() {
        let mut fp = Ja3Fingerprint {
            ja3_string: String::new(),
            ja3_hash: String::new(),
            ssl_version: 0x0303,
            ciphers: vec![],
            extensions: vec![],
            curves: vec![],
            point_formats: vec![],
        };

        assert_eq!(fp.ssl_version_name(), "TLS 1.2");

        fp.ssl_version = 0x0304;
        assert_eq!(fp.ssl_version_name(), "TLS 1.3");

        fp.ssl_version = 0x0301;
        assert_eq!(fp.ssl_version_name(), "TLS 1.0");
    }

    #[test]
    fn test_curve_names() {
        let fp = Ja3Fingerprint {
            ja3_string: String::new(),
            ja3_hash: String::new(),
            ssl_version: 0x0303,
            ciphers: vec![],
            extensions: vec![],
            curves: vec![29, 23, 24],  // X25519, secp256r1, secp384r1
            point_formats: vec![],
        };

        let names = fp.curve_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"X25519".to_string()));
        assert!(names.contains(&"secp256r1".to_string()));
        assert!(names.contains(&"secp384r1".to_string()));
    }
}
