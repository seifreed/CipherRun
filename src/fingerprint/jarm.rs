// JARM (TLS Server Active Fingerprinting) implementation
// Based on https://github.com/salesforce/jarm and https://github.com/hdm/jarm-go
//
// JARM sends 10 specially crafted TLS Client Hello packets to a server
// and observes the responses to create a unique 62-character fingerprint.
//
// This is useful for:
// - Server identification and classification
// - Threat detection (malware C2, phishing sites)
// - CDN/Load balancer detection
// - Anycast deployment analysis

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub use super::jarm_probes::{JarmProbe, JarmProbeOptions, get_probes};

/// JARM fingerprint result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JarmFingerprint {
    /// The 62-character JARM hash
    pub hash: String,

    /// Raw probe responses (for debugging)
    pub raw_responses: Vec<String>,

    /// Matched signature (if any)
    pub signature: Option<JarmSignature>,
}

/// JARM signature from database
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JarmSignature {
    /// JARM hash
    pub hash: String,

    /// Server/service name
    pub name: String,

    /// Server type (CDN, server, load balancer, etc.)
    pub server_type: String,

    /// Additional details
    pub description: Option<String>,

    /// Threat level (if applicable)
    pub threat_level: Option<String>,
}

/// JARM signature database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarmDatabase {
    signatures: HashMap<String, JarmSignature>,
}

impl JarmDatabase {
    /// Create empty database
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Load database from JSON file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JARM database from {}", path))?;

        let signatures: Vec<JarmSignature> =
            serde_json::from_str(&content).with_context(|| "Failed to parse JARM database JSON")?;

        let mut db = Self::new();
        for sig in signatures {
            db.signatures.insert(sig.hash.clone(), sig);
        }

        Ok(db)
    }

    /// Load builtin database
    pub fn builtin() -> Self {
        let builtin_json = include_str!("../../data/jarm_signatures.json");
        let signatures: Vec<JarmSignature> =
            serde_json::from_str(builtin_json).expect("Failed to parse builtin JARM database");

        let mut db = Self::new();
        for sig in signatures {
            db.signatures.insert(sig.hash.clone(), sig);
        }

        db
    }

    /// Look up a JARM hash
    pub fn lookup(&self, hash: &str) -> Option<&JarmSignature> {
        self.signatures.get(hash)
    }

    /// Add signature to database
    pub fn add_signature(&mut self, signature: JarmSignature) {
        self.signatures.insert(signature.hash.clone(), signature);
    }

    /// Get all signatures
    pub fn all_signatures(&self) -> Vec<&JarmSignature> {
        self.signatures.values().collect()
    }
}

impl Default for JarmDatabase {
    fn default() -> Self {
        Self::builtin()
    }
}

/// JARM fingerprinter
pub struct JarmFingerprinter {
    /// Connection timeout
    timeout: Duration,

    /// Signature database
    database: JarmDatabase,
}

impl JarmFingerprinter {
    /// Create new JARM fingerprinter
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            database: JarmDatabase::builtin(),
        }
    }

    /// Create with custom database
    pub fn with_database(timeout: Duration, database: JarmDatabase) -> Self {
        Self { timeout, database }
    }

    /// Fingerprint a target
    pub async fn fingerprint(&self, addr: SocketAddr, hostname: &str) -> Result<JarmFingerprint> {
        let probes = get_probes(hostname, addr.port());
        let mut raw_responses = Vec::new();

        for probe in &probes {
            let response = self.send_probe(addr, probe).await?;
            raw_responses.push(response);
        }

        let hash = raw_hash_to_fuzzy_hash(&raw_responses.join(","));
        let signature = self.database.lookup(&hash).cloned();

        Ok(JarmFingerprint {
            hash,
            raw_responses,
            signature,
        })
    }

    /// Send single probe and parse response
    async fn send_probe(&self, addr: SocketAddr, probe: &JarmProbe) -> Result<String> {
        // Connect with timeout
        let stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_e)) => return Ok("|||".to_string()), // Connection failed
            Err(_) => return Ok("|||".to_string()),      // Timeout
        };

        // Build Client Hello packet
        let client_hello = probe.build();

        // Send Client Hello
        let mut stream = stream;
        if timeout(self.timeout, stream.write_all(&client_hello))
            .await
            .is_err()
        {
            return Ok("|||".to_string());
        }

        // Read ServerHello response (max 1484 bytes)
        let mut buffer = vec![0u8; 1484];
        let n = match timeout(self.timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Ok("|||".to_string()),
            Err(_) => return Ok("|||".to_string()),
        };

        buffer.truncate(n);

        // Parse ServerHello
        parse_server_hello(&buffer, probe)
    }
}

/// Parse ServerHello response
fn parse_server_hello(data: &[u8], _probe: &JarmProbe) -> Result<String> {
    if data.is_empty() {
        return Ok("|||".to_string());
    }

    // Alert indicates failed handshake
    if data[0] == 21 {
        return Ok("|||".to_string());
    }

    // Not a ServerHello response (should be 22 = handshake, type 2 = server_hello)
    if !(data[0] == 22 && data.len() > 5 && data[5] == 2) {
        return Ok("|||".to_string());
    }

    // ServerHello length
    let server_hello_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    // Too short
    if data.len() < 44 {
        return Ok("|||".to_string());
    }

    // Session ID length
    let counter = data[43] as usize;
    let cipher_offset = counter + 44;

    if data.len() < cipher_offset + 2 {
        return Ok("|||".to_string());
    }

    // Extract cipher
    let server_cipher = hex::encode(&data[cipher_offset..cipher_offset + 2]);

    // Extract version
    let server_version = hex::encode(&data[9..11]);

    // Extract extensions
    let server_ext = extract_extension_info(data, counter, server_hello_length);

    Ok(format!(
        "{}|{}|{}",
        server_cipher, server_version, server_ext
    ))
}

/// Extract extension information from ServerHello
fn extract_extension_info(data: &[u8], offset: usize, server_hello_length: usize) -> String {
    if data.len() < 85 || data.len() < offset + 53 {
        return "|".to_string();
    }

    if data[offset + 47] == 11 {
        return "|".to_string();
    }

    if offset + 42 >= server_hello_length {
        return "|".to_string();
    }

    // Check for malformed responses
    if (offset + 53 <= data.len() && data[offset + 50..offset + 53] == [0x0e, 0xac, 0x0b])
        || (85 <= data.len() && data[82..85] == [0x0f, 0xf0, 0x0b])
    {
        return "|".to_string();
    }

    let ecnt_start = offset + 49;
    let elen = u16::from_be_bytes([data[offset + 47], data[offset + 48]]) as usize;
    let emax = elen + ecnt_start;

    let mut etypes = Vec::new();
    let mut evals = Vec::new();
    let mut ecnt = ecnt_start;

    while ecnt < emax && ecnt + 4 <= data.len() {
        // Extension type (2 bytes)
        let ext_type = [data[ecnt], data[ecnt + 1]];
        etypes.push(ext_type);

        // Extension length (2 bytes)
        let ext_len = u16::from_be_bytes([data[ecnt + 2], data[ecnt + 3]]) as usize;

        // Extension value
        if ecnt + 4 + ext_len <= data.len() {
            if ext_len == 0 {
                evals.push(Vec::new());
            } else {
                evals.push(data[ecnt + 4..ecnt + 4 + ext_len].to_vec());
            }
            ecnt += ext_len + 4;
        } else {
            break;
        }
    }

    // Extract ALPN (extension type 0x0010)
    let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);

    // Build extension type list
    let etype_list: Vec<String> = etypes.iter().map(hex::encode).collect();

    format!("{}|{}", alpn, etype_list.join("-"))
}

/// Extract specific extension type value
fn extract_extension_type(ext: &[u8], etypes: &[[u8; 2]], evals: &[Vec<u8>]) -> String {
    for (i, etype) in etypes.iter().enumerate() {
        if etype == ext && i < evals.len() {
            let eval = &evals[i];

            // ALPN extension (0x0010)
            if ext == [0x00, 0x10] && eval.len() >= 4 {
                // ALPN format: 2-byte length, then protocols
                // Return the actual protocol string
                return String::from_utf8_lossy(&eval[3..]).to_string();
            }

            return hex::encode(eval);
        }
    }

    String::new()
}

/// Zero hash (all probes failed)
const ZERO_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000";

/// Convert raw hash to fuzzy JARM hash
fn raw_hash_to_fuzzy_hash(raw: &str) -> String {
    // All probes failed
    if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
        return ZERO_HASH.to_string();
    }

    let mut fhash = String::new();
    let mut alpex = String::new();

    for handshake in raw.split(',') {
        let comp: Vec<&str> = handshake.split('|').collect();
        if comp.len() != 4 {
            return ZERO_HASH.to_string();
        }

        fhash.push_str(&extract_cipher_bytes(comp[0]));
        fhash.push_str(&extract_version_byte(comp[1]));
        alpex.push_str(comp[2]);
        alpex.push_str(comp[3]);
    }

    // Hash the ALPN and extensions portion
    let mut hasher = Sha256::new();
    hasher.update(alpex.as_bytes());
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);

    // Append first 32 characters of SHA256 hash
    fhash.push_str(&hash_hex[0..32]);

    fhash
}

/// Cipher list order for JARM (used for index-based encoding)
const CIPHER_LIST_ORDER: &[[u8; 2]] = &[
    [0x00, 0x04],
    [0x00, 0x05],
    [0x00, 0x07],
    [0x00, 0x0a],
    [0x00, 0x16],
    [0x00, 0x2f],
    [0x00, 0x33],
    [0x00, 0x35],
    [0x00, 0x39],
    [0x00, 0x3c],
    [0x00, 0x3d],
    [0x00, 0x41],
    [0x00, 0x45],
    [0x00, 0x67],
    [0x00, 0x6b],
    [0x00, 0x84],
    [0x00, 0x88],
    [0x00, 0x9a],
    [0x00, 0x9c],
    [0x00, 0x9d],
    [0x00, 0x9e],
    [0x00, 0x9f],
    [0x00, 0xba],
    [0x00, 0xbe],
    [0x00, 0xc0],
    [0x00, 0xc4],
    [0xc0, 0x07],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x0a],
    [0xc0, 0x11],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x14],
    [0xc0, 0x23],
    [0xc0, 0x24],
    [0xc0, 0x27],
    [0xc0, 0x28],
    [0xc0, 0x2b],
    [0xc0, 0x2c],
    [0xc0, 0x2f],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xc0, 0x9c],
    [0xc0, 0x9d],
    [0xc0, 0x9e],
    [0xc0, 0x9f],
    [0xc0, 0xa0],
    [0xc0, 0xa1],
    [0xc0, 0xa2],
    [0xc0, 0xa3],
    [0xc0, 0xac],
    [0xc0, 0xad],
    [0xc0, 0xae],
    [0xc0, 0xaf],
    [0xcc, 0x13],
    [0xcc, 0x14],
    [0xcc, 0xa8],
    [0xcc, 0xa9],
    [0x13, 0x01],
    [0x13, 0x02],
    [0x13, 0x03],
    [0x13, 0x04],
    [0x13, 0x05],
];

/// Convert cipher hex to index-based encoding
fn extract_cipher_bytes(cipher_hex: &str) -> String {
    if cipher_hex.is_empty() {
        return "00".to_string();
    }

    // Decode hex string
    let cipher_bytes = match hex::decode(cipher_hex) {
        Ok(b) if b.len() == 2 => [b[0], b[1]],
        _ => return "00".to_string(),
    };

    // Find index in cipher list
    let mut count = 1;
    for known_cipher in CIPHER_LIST_ORDER {
        if known_cipher == &cipher_bytes {
            break;
        }
        count += 1;
    }

    format!("{:02x}", count)
}

/// Extract version byte (convert to character)
fn extract_version_byte(version_hex: &str) -> String {
    if version_hex.is_empty() || version_hex.len() < 4 {
        return "0".to_string();
    }

    // Extract last character and convert to number
    match version_hex.chars().nth(3).and_then(|c| c.to_digit(16)) {
        Some(val) => {
            let ch = (0x61 + val) as u8 as char;
            ch.to_string()
        }
        None => "0".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_hash() {
        let raw = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";
        let hash = raw_hash_to_fuzzy_hash(raw);
        assert_eq!(hash, ZERO_HASH);
    }

    #[test]
    fn test_cipher_extraction() {
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
        assert_eq!(extract_cipher_bytes("c02f"), "29");

        // TLS_AES_128_GCM_SHA256 (0x1301)
        assert_eq!(extract_cipher_bytes("1301"), "41");

        // Empty
        assert_eq!(extract_cipher_bytes(""), "00");
    }

    #[test]
    fn test_version_extraction() {
        assert_eq!(extract_version_byte("0303"), "d"); // TLS 1.2 (0x0303)
        assert_eq!(extract_version_byte("0304"), "e"); // TLS 1.3 (0x0304)
        assert_eq!(extract_version_byte("0301"), "b"); // TLS 1.0 (0x0301)
        assert_eq!(extract_version_byte(""), "0");
    }

    #[test]
    fn test_database_lookup() {
        let mut db = JarmDatabase::new();

        let sig = JarmSignature {
            hash: "test_hash_123".to_string(),
            name: "Test Server".to_string(),
            server_type: "web".to_string(),
            description: Some("Test description".to_string()),
            threat_level: None,
        };

        db.add_signature(sig.clone());

        let found = db.lookup("test_hash_123");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test Server");

        let not_found = db.lookup("nonexistent");
        assert!(not_found.is_none());
    }
}
