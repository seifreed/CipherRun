// Elliptic Curves Parser - Parses curves-mapping.txt

use anyhow::Result;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;

lazy_static! {
    /// Global curves database loaded at startup
    pub static ref CURVES_DB: Arc<CurvesDatabase> = Arc::new(
        CurvesDatabase::load().expect("Failed to load curves database")
    );
}

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
                by_name.insert(curve.short_name.clone(), curve.clone());
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

        Ok(EllipticCurve {
            id,
            short_name,
            full_name,
            bits,
            post_quantum,
            hybrid,
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

    /// Check if hybrid curve
    fn is_hybrid(name: &str) -> bool {
        (name.contains("MLKEM") || name.contains("Kyber"))
            && (name.contains("X25519") || name.contains("SecP"))
    }

    /// Get curve by ID
    pub fn get_by_id(&self, id: &str) -> Option<&EllipticCurve> {
        self.by_id.get(&id.to_lowercase())
    }

    /// Get curve by name
    pub fn get_by_name(&self, name: &str) -> Option<&EllipticCurve> {
        self.by_name.get(name)
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
        let curve = CurvesDatabase::parse_line(line).unwrap();

        assert_eq!(curve.id, "001d");
        assert_eq!(curve.short_name, "X25519");
        assert_eq!(curve.bits, Some(256));
    }

    #[test]
    fn test_post_quantum_detection() {
        assert!(CurvesDatabase::is_post_quantum("MLKEM768"));
        assert!(CurvesDatabase::is_hybrid("X25519MLKEM768"));
        assert!(!CurvesDatabase::is_post_quantum("X25519"));
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
}
