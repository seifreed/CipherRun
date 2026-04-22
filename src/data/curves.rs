// Elliptic Curves Parser - Parses curves-mapping.txt

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Global curves database loaded at startup
///
/// Uses OnceLock for safe initialization with proper error handling.
static CURVES_DB_INNER: std::sync::OnceLock<Arc<CurvesDatabase>> = std::sync::OnceLock::new();

/// Get the global curves database
///
/// Returns the database if already initialized, or initializes it on first call.
/// Initialization errors are logged and an empty database is used as fallback.
pub fn curves_db() -> Arc<CurvesDatabase> {
    CURVES_DB_INNER
        .get_or_init(|| match CurvesDatabase::load() {
            Ok(db) => Arc::new(db),
            Err(e) => {
                tracing::error!(
                    "Failed to load curves database: {}. Using empty database.",
                    e
                );
                Arc::new(CurvesDatabase::empty())
            }
        })
        .clone()
}

/// Legacy static for backward compatibility
/// Delegates to `curves_db()` to avoid loading data twice into memory
pub static CURVES_DB: std::sync::LazyLock<Arc<CurvesDatabase>> =
    std::sync::LazyLock::new(curves_db);

/// Elliptic curve information
#[derive(Debug, Clone)]
pub struct EllipticCurve {
    /// Curve ID (hex)
    pub id: String,
    /// Short name
    pub short_name: String,
    /// Full name
    pub full_name: String,
    /// Bits of security
    pub bits: Option<u16>,
    /// Post-quantum
    pub post_quantum: bool,
    /// Hybrid (classical + PQ)
    pub hybrid: bool,
    /// Vulnerable to quantum attack (Shor's algorithm breaks classical ECDH/DH)
    pub quantum_vulnerable: bool,
}

/// Database of elliptic curves
pub struct CurvesDatabase {
    /// Map from ID to curve
    by_id: HashMap<String, EllipticCurve>,
    /// Map from short name to curve
    by_name: HashMap<String, EllipticCurve>,
}

impl CurvesDatabase {
    /// Load curves database from embedded data
    pub fn load() -> Result<Self> {
        let data = include_str!("../../data/curves-mapping.txt");
        Self::parse(data)
    }

    /// Create an empty database (fallback for loading errors)
    pub fn empty() -> Self {
        Self {
            by_id: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Parse curves-mapping.txt format
    /// Format: 0xHH,0xHH - ShortName  FullName
    pub fn parse(data: &str) -> Result<Self> {
        let mut by_id = HashMap::new();
        let mut by_name = HashMap::new();

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(curve) = Self::parse_line(line) {
                by_id.insert(curve.id.clone(), curve.clone());
                by_name.insert(curve.short_name.to_lowercase(), curve.clone());
            }
        }

        Ok(Self { by_id, by_name })
    }

    /// Parse a single line
    fn parse_line(line: &str) -> Result<EllipticCurve> {
        let parts: Vec<&str> = line.split(" - ").collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid format");
        }

        let id = parts[0]
            .trim()
            .replace("0x", "")
            .replace(",", "")
            .to_lowercase();

        let names: Vec<&str> = parts[1].split_whitespace().collect();
        let short_name = names.first().unwrap_or(&"unknown").to_string();
        let full_name = names
            .get(1..)
            .map(|parts| parts.join(" "))
            .unwrap_or_default();

        let bits = Self::extract_bits(&short_name, &full_name);
        let post_quantum = Self::is_post_quantum(&short_name);
        let hybrid = Self::is_hybrid(&short_name);
        let quantum_vulnerable = !post_quantum && !hybrid;

        Ok(EllipticCurve {
            id,
            short_name,
            full_name,
            bits,
            post_quantum,
            hybrid,
            quantum_vulnerable,
        })
    }

    /// Extract security bits from curve name
    fn extract_bits(short_name: &str, full_name: &str) -> Option<u16> {
        // Special cases for modern curves
        if short_name.contains("X25519") || short_name.contains("25519") {
            Some(256)
        } else if short_name.contains("X448") || short_name.contains("448") {
            Some(448)
        } else if short_name.contains("256") || full_name.contains("256") {
            Some(256)
        } else if short_name.contains("384") || full_name.contains("384") {
            Some(384)
        } else if short_name.contains("521") || full_name.contains("521") {
            Some(521)
        } else if short_name.contains("192") {
            Some(192)
        } else if short_name.contains("224") {
            Some(224)
        } else if short_name.contains("512") {
            Some(512)
        } else {
            None
        }
    }

    /// Check if post-quantum curve
    fn is_post_quantum(name: &str) -> bool {
        name.to_lowercase().contains("mlkem")
            || name.to_lowercase().contains("kyber")
            || name.to_lowercase().contains("ntru")
    }

    /// Check if hybrid curve (case-insensitive)
    fn is_hybrid(name: &str) -> bool {
        let lower = name.to_lowercase();
        (lower.contains("mlkem") || lower.contains("kyber"))
            && (lower.contains("x25519") || lower.contains("secp"))
    }

    /// Get curve by ID
    pub fn get_by_id(&self, id: &str) -> Option<&EllipticCurve> {
        self.by_id.get(&id.to_lowercase())
    }

    /// Get curve by name
    pub fn get_by_name(&self, name: &str) -> Option<&EllipticCurve> {
        self.by_name.get(&name.to_lowercase())
    }

    /// Get all curves
    pub fn all_curves(&self) -> impl Iterator<Item = &EllipticCurve> {
        self.by_id.values()
    }

    /// Get recommended curves (strong, modern)
    pub fn recommended_curves(&self) -> Vec<&EllipticCurve> {
        self.by_id
            .values()
            .filter(|c| {
                matches!(c.bits, Some(b) if b >= 256)
                    && (c.short_name.contains("X25519")
                        || c.short_name.contains("X448")
                        || c.short_name.contains("secp384r1")
                        || c.short_name.contains("secp256r1"))
            })
            .collect()
    }

    /// Get post-quantum curves
    pub fn post_quantum_curves(&self) -> Vec<&EllipticCurve> {
        self.by_id.values().filter(|c| c.post_quantum).collect()
    }

    /// Get curve count
    pub fn count(&self) -> usize {
        self.by_id.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_curve_line() {
        let line = "0x00,0x1d - X25519  Curve25519";
        let curve = CurvesDatabase::parse_line(line).expect("test assertion should succeed");

        assert_eq!(curve.id, "001d");
        assert_eq!(curve.short_name, "X25519");
        assert_eq!(curve.bits, Some(256));
    }

    #[test]
    fn test_parse_curve_line_x448_bits() {
        let line = "0x00,0x1e - X448  X448";
        let curve = CurvesDatabase::parse_line(line).expect("test assertion should succeed");
        assert_eq!(curve.bits, Some(448));
        assert!(!curve.post_quantum);
        assert!(!curve.hybrid);
    }

    #[test]
    fn test_post_quantum_detection() {
        assert!(CurvesDatabase::is_post_quantum("MLKEM768"));
        assert!(CurvesDatabase::is_hybrid("X25519MLKEM768"));
        assert!(!CurvesDatabase::is_post_quantum("X25519"));
    }

    #[test]
    fn test_quantum_vulnerable_flag() {
        let data = "0x00,0x1d - X25519  Curve25519\n0x11,0xec - X25519MLKEM768  X25519MLKEM768";
        let db = CurvesDatabase::parse(data).expect("test assertion should succeed");

        let x25519 = db.get_by_name("x25519").expect("x25519 should exist");
        assert!(x25519.quantum_vulnerable, "X25519 is quantum-vulnerable");

        let hybrid = db.get_by_name("x25519mlkem768").expect("hybrid should exist");
        assert!(!hybrid.quantum_vulnerable, "X25519MLKEM768 is not quantum-vulnerable");
    }

    #[test]
    fn test_load_database() {
        let db = CURVES_DB.as_ref();
        assert!(db.count() > 10);
    }

    #[test]
    fn test_recommended_curves() {
        let db = CURVES_DB.as_ref();
        let recommended = db.recommended_curves();

        assert!(!recommended.is_empty());
        for curve in recommended {
            assert!(curve.bits.unwrap_or(0) >= 256);
        }
    }

    #[test]
    fn test_parse_curve_line_invalid() {
        let err = CurvesDatabase::parse_line("invalid").expect_err("should fail");
        assert!(err.to_string().contains("Invalid format"));
    }

    #[test]
    fn test_get_by_id_normalizes_case() {
        let data = "0x00,0x1d - X25519  Curve25519";
        let db = CurvesDatabase::parse(data).expect("test assertion should succeed");
        assert!(db.get_by_id("001D").is_some());
        assert!(db.get_by_id("001d").is_some());
    }
}
