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

use crate::Result;
use crate::error::TlsError;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub use super::jarm_probes::{JarmProbe, JarmProbeOptions, get_probes};

fn read_u8_at(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())?;
    Some(u16::from_be_bytes(bytes))
}

fn slice_range(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    data.get(start..start.checked_add(len)?)
}

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
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = super::read_signature_database(path)?;

        let signatures: Vec<JarmSignature> =
            serde_json::from_str(&content).map_err(|e| TlsError::ParseError {
                message: format!("Failed to parse JARM database JSON: {e}"),
            })?;

        Self::from_signatures(signatures)
    }

    /// Load builtin database.
    pub fn builtin() -> Result<Self> {
        let builtin_json = include_str!("../../data/jarm_signatures.json");
        let signatures: Vec<JarmSignature> =
            serde_json::from_str(builtin_json).map_err(|e| TlsError::ParseError {
                message: format!("Failed to parse embedded JARM database: {e}"),
            })?;

        Self::from_signatures(signatures)
    }

    fn from_signatures(signatures: Vec<JarmSignature>) -> Result<Self> {
        let mut db = Self::new();
        for sig in signatures {
            if !Self::is_valid_jarm_hash(&sig.hash) {
                return Err(TlsError::ParseError {
                    message: format!("Invalid JARM signature hash: {}", sig.hash),
                });
            }
            if db.signatures.contains_key(&sig.hash) {
                return Err(TlsError::ParseError {
                    message: format!("Duplicate JARM signature hash: {}", sig.hash),
                });
            }
            db.signatures.insert(sig.hash.clone(), sig);
        }

        Ok(db)
    }

    fn is_valid_jarm_hash(hash: &str) -> bool {
        hash.len() == 62
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        Self::new()
    }
}

/// JARM fingerprinter
pub struct JarmFingerprinter {
    /// Connection timeout
    timeout: Duration,

    /// Signature database
    database: JarmDatabase,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    starttls_server_mode: bool,
}

impl JarmFingerprinter {
    /// Create new JARM fingerprinter
    pub fn new(timeout: Duration) -> Result<Self> {
        Ok(Self {
            timeout,
            database: JarmDatabase::builtin()?,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
        })
    }

    /// Create with custom database
    pub fn with_database(timeout: Duration, database: JarmDatabase) -> Self {
        Self {
            timeout,
            database,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
        }
    }

    pub fn with_starttls(
        mut self,
        starttls: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = starttls;
        self.starttls_hostname = hostname;
        self
    }

    pub fn with_starttls_server_mode(mut self, server_mode: bool) -> Self {
        self.starttls_server_mode = server_mode;
        self
    }

    /// Fingerprint a target
    pub async fn fingerprint(&self, addr: SocketAddr, hostname: &str) -> Result<JarmFingerprint> {
        let probes = get_probes(hostname, addr.port())?;
        let mut raw_responses = Vec::new();

        for probe in &probes {
            let response = self.send_probe(addr, hostname, probe).await?;
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
    async fn send_probe(
        &self,
        addr: SocketAddr,
        hostname: &str,
        probe: &JarmProbe,
    ) -> Result<String> {
        let hostname = self
            .starttls_hostname
            .as_deref()
            .unwrap_or(hostname);

        // Connect with timeout, optionally upgrading with STARTTLS first.
        let stream = if let Some(starttls) = self.starttls {
            match crate::utils::network::connect_with_starttls(
                addr,
                self.timeout,
                Some(starttls),
                &hostname,
                self.starttls_server_mode,
            )
            .await
            {
                Ok(stream) => stream,
                Err(_) => return Ok("|||".to_string()),
            }
        } else {
            match timeout(self.timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(_e)) => return Ok("|||".to_string()),
                Err(_) => return Ok("|||".to_string()),
            }
        };

        // Build Client Hello packet
        let client_hello = probe.build();

        // Send Client Hello
        let mut stream = stream;
        if timeout(self.timeout, stream.write_all(&client_hello))
            .await
            .is_err()
        {
            // Attempt graceful shutdown before returning
            let _ = stream.shutdown().await;
            return Ok("|||".to_string());
        }

        // Read the full response so fragmented ServerHello records do not get
        // misclassified as empty or truncated.
        let mut buffer = vec![0u8; 1484];
        let n = match Self::read_complete_response(&mut stream, &mut buffer, self.timeout).await {
            Ok(n) => n,
            Err(_) => {
                let _ = stream.shutdown().await;
                return Ok("|||".to_string());
            }
        };

        // Explicitly close stream to release resources
        let _ = stream.shutdown().await;

        buffer.truncate(n);

        // Parse ServerHello
        parse_server_hello(&buffer, probe)
    }

    async fn read_complete_response(
        stream: &mut TcpStream,
        buffer: &mut [u8],
        timeout_duration: Duration,
    ) -> std::io::Result<usize> {
        use std::io::ErrorKind;

        let mut total = 0;
        while total < buffer.len() {
            match timeout(timeout_duration, stream.read(&mut buffer[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => total += n,
                Ok(Err(err))
                    if total == 0
                        && matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    return Ok(0);
                }
                Ok(Err(err))
                    if total > 0
                        && matches!(
                            err.kind(),
                            ErrorKind::TimedOut
                                | ErrorKind::WouldBlock
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::ConnectionReset
                        ) =>
                {
                    break;
                }
                Ok(Err(err)) => return Err(err),
                Err(_) if total > 0 => break,
                Err(_) => return Ok(0),
            }
        }

        Ok(total)
    }
}

/// Parse ServerHello response
fn parse_server_hello(data: &[u8], _probe: &JarmProbe) -> Result<String> {
    if data.is_empty() {
        return Ok("|||".to_string());
    }

    // Alert indicates failed handshake
    if read_u8_at(data, 0) == Some(21) {
        return Ok("|||".to_string());
    }

    // Not a ServerHello response (should be 22 = handshake, type 2 = server_hello)
    if !(read_u8_at(data, 0) == Some(22) && read_u8_at(data, 5) == Some(2)) {
        return Ok("|||".to_string());
    }

    // ServerHello length
    let Some(server_hello_length) = read_u16_at(data, 3) else {
        return Ok("|||".to_string());
    };
    let server_hello_length = server_hello_length as usize;

    // Too short
    if data.len() < 44 {
        return Ok("|||".to_string());
    }

    // Session ID length
    let Some(counter) = read_u8_at(data, 43) else {
        return Ok("|||".to_string());
    };
    let counter = counter as usize;
    let Some(cipher_offset) = counter.checked_add(44) else {
        return Ok("|||".to_string());
    };

    let Some(cipher_end) = cipher_offset.checked_add(2) else {
        return Ok("|||".to_string());
    };
    if data.len() < cipher_end {
        return Ok("|||".to_string());
    }

    // Extract cipher
    let Some(server_cipher) = slice_range(data, cipher_offset, 2) else {
        return Ok("|||".to_string());
    };
    let server_cipher = hex::encode(server_cipher);

    // Extract version
    let Some(server_version) = slice_range(data, 9, 2) else {
        return Ok("|||".to_string());
    };
    let server_version = hex::encode(server_version);

    // Extract extensions
    let server_ext = extract_extension_info(data, counter, server_hello_length)?;

    Ok(format!(
        "{}|{}|{}",
        server_cipher, server_version, server_ext
    ))
}

/// Extract extension information from ServerHello
///
/// `offset` is the session ID length (data[43]), used to compute positions:
///   cipher:     offset + 44 .. offset + 46
///   compress:   offset + 46
///   ext_len:    offset + 47 .. offset + 49
///   ext_data:   offset + 49 ..
fn extract_extension_info(
    data: &[u8],
    offset: usize,
    server_hello_length: usize,
) -> Result<String> {
    // Check if the server sent no extensions by reading the full 2-byte extension length.
    // Previously this only checked data[offset + 47] == 0x0b, which collided with valid
    // extension lengths 0x0B00-0x0BFF (2816-3071 bytes).
    let Some(ext_len_offset) = offset.checked_add(47) else {
        return Ok("|".to_string());
    };
    let Some(ext_len_end) = ext_len_offset.checked_add(2) else {
        return Ok("|".to_string());
    };
    if data.len() < ext_len_end {
        return Ok("|".to_string());
    }
    let Some(potential_ext_len) = read_u16_at(data, ext_len_offset) else {
        return Ok("|".to_string());
    };
    if potential_ext_len == 0 {
        return Ok("|".to_string());
    }
    if potential_ext_len < 4 {
        return Err(TlsError::ParseError {
            message: format!(
                "Truncated JARM extension list: declared length {} is shorter than an extension header",
                potential_ext_len
            ),
        });
    }
    // If the high byte looks like a Certificate handshake type (0x0b) AND the claimed
    // extension length exceeds available data, the server likely sent no extensions
    // and the next handshake record follows immediately.
    let Some(ecnt_start) = offset.checked_add(49) else {
        return Ok("|".to_string());
    };
    if read_u8_at(data, ext_len_offset) == Some(0x0b)
        && ecnt_start.saturating_add(potential_ext_len as usize) > data.len()
    {
        return Ok("|".to_string());
    }

    // S7 fix: `server_hello_length` is read from the *first* TLS record header
    // (bytes 3..5). On fragmented responses — where ServerHello + Certificate
    // span multiple records — this value covers only the first record, so the
    // bound `5 + server_hello_length` truncates the extension region and
    // produces a misaligned JARM fingerprint. The real bound is `data.len()`,
    // and the `emax` computation below (ecnt_start + elen) already gates the
    // extension-iteration loop against the declared extension length.
    let _ = server_hello_length;
    if ecnt_start > data.len() {
        return Ok("|".to_string());
    }

    // Check for malformed responses
    let Some(malformed_offset) = offset.checked_add(50) else {
        return Ok("|".to_string());
    };
    if slice_range(data, malformed_offset, 3) == Some(&[0x0e, 0xac, 0x0b]) {
        return Ok("|".to_string());
    }
    // Secondary malformed check at fixed offset (original JARM reference)
    if slice_range(data, 82, 3) == Some(&[0x0f, 0xf0, 0x0b]) {
        return Ok("|".to_string());
    }

    let elen = potential_ext_len as usize;

    // Check for overflow in emax calculation
    let emax = match ecnt_start.checked_add(elen) {
        Some(sum) => sum,
        None => {
            tracing::debug!("Extension length overflow");
            return Ok("|".to_string());
        }
    };

    let mut etypes = Vec::new();
    let mut evals = Vec::new();
    let mut ecnt = ecnt_start;

    // Improved bounds checking in extension iteration
    while ecnt < emax && ecnt + 4 <= data.len() {
        // Extension type (2 bytes)
        let Some(ext_type) =
            slice_range(data, ecnt, 2).and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return Err(TlsError::ParseError {
                message: format!("Truncated JARM extension type at offset {}", ecnt),
            });
        };

        // Extension length (2 bytes)
        let Some(ext_len) = read_u16_at(data, ecnt + 2) else {
            return Err(TlsError::ParseError {
                message: format!("Truncated JARM extension length at offset {}", ecnt),
            });
        };
        let ext_len = ext_len as usize;

        // Check bounds for extension value
        // Use <= because next_cnt == data.len() is a valid end-of-data position
        let next_cnt = match ecnt.checked_add(4).and_then(|n| n.checked_add(ext_len)) {
            Some(n) if n <= data.len() => n,
            _ => {
                return Err(TlsError::ParseError {
                    message: format!("Truncated JARM extension at offset {}", ecnt),
                });
            }
        };

        // Push type and value together to keep vectors aligned
        etypes.push(ext_type);
        if ext_len == 0 {
            evals.push(Vec::new());
        } else {
            let Some(value) = slice_range(data, ecnt + 4, ext_len) else {
                return Err(TlsError::ParseError {
                    message: format!("Truncated JARM extension value at offset {}", ecnt),
                });
            };
            evals.push(value.to_vec());
        }
        ecnt = next_cnt;
    }
    if ecnt != emax {
        return Err(TlsError::ParseError {
            message: format!(
                "Truncated JARM extension list: stopped at offset {} before declared end {}",
                ecnt, emax
            ),
        });
    }

    // Extract ALPN (extension type 0x0010)
    let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);

    // Build extension type list
    let etype_list: Vec<String> = etypes.iter().map(hex::encode).collect();

    Ok(format!("{}|{}", alpn, etype_list.join("-")))
}

/// Extract specific extension type value
fn extract_extension_type(ext: &[u8], etypes: &[[u8; 2]], evals: &[Vec<u8>]) -> String {
    for (etype, eval) in etypes.iter().zip(evals) {
        if etype == ext {
            // ALPN extension (0x0010)
            // Format: [2-byte list_len][1-byte proto_len][proto_name...]...
            if ext == [0x00, 0x10] && eval.len() >= 3 {
                let list_len = u16::from_be_bytes([eval[0], eval[1]]) as usize;
                let proto_len = eval[2] as usize;
                let list_end = 2usize.saturating_add(list_len);
                let proto_end = 3usize.saturating_add(proto_len);
                if proto_end <= list_end
                    && list_end == eval.len()
                    && let Some(proto) = eval.get(3..proto_end)
                    && let Ok(proto) = std::str::from_utf8(proto)
                {
                    return proto.to_string();
                }
            }

            return hex::encode(eval);
        }
    }

    String::new()
}

/// Zero hash (all probes failed)
const ZERO_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000";

/// Expected number of JARM probes per the specification
const JARM_PROBE_COUNT: usize = 10;

/// Convert raw hash to fuzzy JARM hash
fn raw_hash_to_fuzzy_hash(raw: &str) -> String {
    // All probes failed
    if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
        return ZERO_HASH.to_string();
    }

    let mut fhash = String::new();
    let mut alpex = String::new();

    let handshakes: Vec<&str> = raw.split(',').collect();

    // JARM specification requires exactly 10 probe responses
    if handshakes.len() != JARM_PROBE_COUNT {
        tracing::warn!(
            "JARM fingerprint requires {} probe responses, got {}",
            JARM_PROBE_COUNT,
            handshakes.len()
        );
        return ZERO_HASH.to_string();
    }

    for handshake in handshakes {
        let mut comp = handshake.split('|');
        let (Some(cipher), Some(version), Some(alpn), Some(extensions), None) = (
            comp.next(),
            comp.next(),
            comp.next(),
            comp.next(),
            comp.next(),
        ) else {
            return ZERO_HASH.to_string();
        };

        fhash.push_str(&extract_cipher_bytes(cipher));
        fhash.push_str(&extract_version_byte(version));
        alpex.push_str(alpn);
        alpex.push_str(extensions);
    }

    // Hash the ALPN and extensions portion
    let hash_result = digest(&SHA256, alpex.as_bytes());
    let hash_hex = hex::encode(hash_result.as_ref());

    // Append first 32 characters of SHA256 hash
    fhash.push_str(hash_hex.get(..32).unwrap_or(&hash_hex));

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
        Ok(bytes) => match <[u8; 2]>::try_from(bytes.as_slice()) {
            Ok(bytes) => bytes,
            Err(_) => return "00".to_string(),
        },
        _ => return "00".to_string(),
    };

    // Find index in cipher list (1-based).
    for (i, known_cipher) in CIPHER_LIST_ORDER.iter().enumerate() {
        if known_cipher == &cipher_bytes {
            return format!("{:02x}", i + 1);
        }
    }

    // Cipher present but not in JARM's known list. Canonical JARM encodes this as
    // the post-loop counter (list length + 1), NOT "00" — "00" is reserved for
    // the no-cipher case (empty/failed probe). Returning "00" here would make the
    // fuzzy hash diverge from canonical for any server negotiating an off-list
    // cipher, so it would never match the canonical-derived signature database.
    format!("{:02x}", CIPHER_LIST_ORDER.len() + 1)
}

/// Extract version byte (convert to character)
fn extract_version_byte(version_hex: &str) -> String {
    if version_hex.is_empty() || version_hex.len() < 4 {
        return "0".to_string();
    }

    // Extract last character and convert to number
    match version_hex.chars().nth(3).and_then(|c| c.to_digit(16)) {
        Some(val) => char::from_u32(0x61 + val)
            .map(|ch| ch.to_string())
            .unwrap_or_else(|| "0".to_string()),
        None => "0".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

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

        // Empty (no cipher negotiated / failed probe) encodes as "00".
        assert_eq!(extract_cipher_bytes(""), "00");

        // A cipher not in JARM's known list encodes as the post-loop counter
        // (list length + 1 = 70 = 0x46), matching canonical JARM — not "00".
        assert_eq!(extract_cipher_bytes("ffff"), "46");
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

    fn test_jarm_signature(hash: &str) -> JarmSignature {
        JarmSignature {
            hash: hash.to_string(),
            name: "Test Server".to_string(),
            server_type: "web".to_string(),
            description: Some("Test description".to_string()),
            threat_level: None,
        }
    }

    #[test]
    fn test_database_load_rejects_invalid_hash() {
        let err = JarmDatabase::from_signatures(vec![test_jarm_signature("not-a-jarm-hash")])
            .expect_err("invalid JARM hash should fail");

        assert!(err.to_string().contains("Invalid JARM signature hash"));
    }

    #[test]
    fn test_database_load_rejects_duplicate_hashes() {
        let hash = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d";
        let err = JarmDatabase::from_signatures(vec![
            test_jarm_signature(hash),
            test_jarm_signature(hash),
        ])
        .expect_err("duplicate JARM hash should fail");

        assert!(err.to_string().contains("Duplicate JARM signature hash"));
    }

    #[test]
    fn test_extract_extension_type_alpn() {
        let etypes = vec![[0x00, 0x10]];
        let evals = vec![vec![0x00, 0x03, 0x02, b'h', b'2']];
        let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);
        assert_eq!(alpn, "h2");
    }

    #[test]
    fn test_extract_extension_type_alpn_rejects_truncated_list() {
        let etypes = vec![[0x00, 0x10]];
        let evals = vec![vec![0x00, 0x01, 0x02, b'h', b'2']];
        let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);
        assert_eq!(alpn, "0001026832");
    }

    #[test]
    fn test_extract_extension_type_alpn_rejects_trailing_bytes() {
        let etypes = vec![[0x00, 0x10]];
        let evals = vec![vec![0x00, 0x02, 0x01, b'h', 0x00]];
        let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);
        assert_eq!(alpn, "0002016800");
    }

    #[test]
    fn test_extract_extension_type_alpn_rejects_invalid_utf8() {
        let etypes = vec![[0x00, 0x10]];
        let evals = vec![vec![0x00, 0x02, 0x01, 0xff]];
        let alpn = extract_extension_type(&[0x00, 0x10], &etypes, &evals);
        assert_eq!(alpn, "000201ff");
    }

    #[test]
    fn test_extract_extension_type_non_alpn_hex() {
        let etypes = vec![[0x00, 0x0a]];
        let evals = vec![vec![0xde, 0xad, 0xbe, 0xef]];
        let value = extract_extension_type(&[0x00, 0x0a], &etypes, &evals);
        assert_eq!(value, "deadbeef");
    }

    #[test]
    fn test_parse_server_hello_rejects_truncated_extension() {
        let probes = get_probes("example.com", 443).expect("JARM probes should build");
        let probe = &probes[0];
        let response = vec![
            0x16, 0x03, 0x03, 0x00, 0x3b, // TLS record
            0x02, 0x00, 0x00, 0x37, // ServerHello handshake
            0x03, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x9c, // cipher
            0x00, // compression
            0x00, 0x04, // extensions length
            0x00, 0x10, // NPN extension type
            0x00, 0x02, // extension length
            0x01, // truncated extension data
        ];

        let err = parse_server_hello(&response, probe).unwrap_err();
        assert!(err.to_string().contains("Truncated JARM extension"));
    }

    #[test]
    fn test_parse_server_hello_rejects_truncated_extension_header() {
        let probes = get_probes("example.com", 443).expect("JARM probes should build");
        let probe = &probes[0];
        let response = vec![
            0x16, 0x03, 0x03, 0x00, 0x3a, // TLS record
            0x02, 0x00, 0x00, 0x36, // ServerHello handshake
            0x03, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // random
            0x00, // session id length
            0x00, 0x9c, // cipher
            0x00, // compression
            0x00, 0x03, // extensions length
            0x00, 0x10, 0x00, // truncated extension header
        ];

        let err = parse_server_hello(&response, probe).unwrap_err();
        assert!(err.to_string().contains("Truncated JARM extension list"));
    }

    fn build_server_hello_response() -> Vec<u8> {
        let mut response = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x36, 0x03, 0x03,
        ];
        response.extend_from_slice(&[0xAA; 32]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x9c]);
        response.push(0x00);
        response.extend_from_slice(&[0x00, 0x04]);
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        let rec_len = (response.len() - 5) as u16;
        response[3..5].copy_from_slice(&rec_len.to_be_bytes());
        let hs_len = (response.len() - 9) as u32;
        response[6..9].copy_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        response
    }

    #[tokio::test]
    async fn test_read_complete_response_handles_fragmented_server_hello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let probe = get_probes("example.com", 443).unwrap().remove(0);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let response = build_server_hello_response();
            let split = 19;
            let _ = socket.write_all(&response[..split]).await;
            sleep(Duration::from_millis(50)).await;
            let _ = socket.write_all(&response[split..]).await;
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(&probe.build()).await.unwrap();

        let mut buffer = vec![0u8; 1484];
        let n = JarmFingerprinter::read_complete_response(
            &mut stream,
            &mut buffer,
            Duration::from_secs(2),
        )
        .await
        .expect("read should succeed");

        assert_eq!(n, build_server_hello_response().len());

        server.await.unwrap();
    }
}
