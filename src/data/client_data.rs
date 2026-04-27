// Client Simulation Data Parser - Parses client-simulation.txt

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Global client database loaded at startup
///
/// Uses OnceLock for safe initialization with proper error handling.
/// If loading fails, the error is captured and returned on first access.
static CLIENT_DB_INNER: std::sync::OnceLock<Arc<ClientDatabase>> = std::sync::OnceLock::new();

/// Get the global client database
///
/// Returns the database if already initialized, or initializes it on first call.
/// Initialization errors are cached and returned on subsequent calls.
pub fn client_db() -> Arc<ClientDatabase> {
    CLIENT_DB_INNER
        .get_or_init(|| match ClientDatabase::load() {
            Ok(db) => Arc::new(db),
            Err(e) => {
                tracing::error!(
                    "Failed to load client database: {}. Using empty database.",
                    e
                );
                Arc::new(ClientDatabase::empty())
            }
        })
        .clone()
}

/// Legacy static for backward compatibility
/// Delegates to `client_db()` to avoid loading data twice into memory
pub static CLIENT_DB: std::sync::LazyLock<Arc<ClientDatabase>> =
    std::sync::LazyLock::new(client_db);

/// Client handshake profile
#[derive(Debug, Clone)]
pub struct ClientProfile {
    /// Human-readable name
    pub name: String,
    /// Short identifier
    pub short_id: String,
    /// OpenSSL cipher string
    pub cipher_string: Option<String>,
    /// TLS 1.3 ciphersuites
    pub tls13_ciphers: Option<String>,
    /// SNI usage
    pub uses_sni: bool,
    /// Warning message
    pub warning: Option<String>,
    /// Raw ClientHello bytes (hex)
    pub handshake_bytes: Option<String>,
    /// Protocol flags
    pub protocol_flags: Vec<String>,
    /// TLS version used
    pub tls_version: Option<String>,
    /// Lowest protocol supported
    pub lowest_protocol: Option<String>,
    /// Highest protocol supported
    pub highest_protocol: Option<String>,
    /// Service types (HTTP, FTP, etc.)
    pub services: Vec<String>,
    /// Minimum DH bits
    pub min_dh_bits: Option<i32>,
    /// Maximum DH bits
    pub max_dh_bits: Option<i32>,
    /// Minimum RSA bits
    pub min_rsa_bits: Option<i32>,
    /// Maximum RSA bits
    pub max_rsa_bits: Option<i32>,
    /// Minimum ECDSA bits
    pub min_ecdsa_bits: Option<i32>,
    /// Supported curves
    pub curves: Vec<String>,
    /// Requires SHA-2
    pub requires_sha2: bool,
    /// Currently maintained/used
    pub current: bool,
}

/// Database of client profiles
pub struct ClientDatabase {
    /// All client profiles
    clients: Vec<ClientProfile>,
    /// Map from short ID to client
    by_id: HashMap<String, usize>,
}

impl ClientDatabase {
    /// Load client database from embedded data
    pub fn load() -> Result<Self> {
        let data = include_str!("../../data/client-simulation.txt");
        Self::parse(data)
    }

    /// Create an empty database (fallback for loading errors)
    pub fn empty() -> Self {
        Self {
            clients: Vec::new(),
            by_id: HashMap::new(),
        }
    }

    /// Parse client-simulation.txt format (bash array format)
    pub fn parse(data: &str) -> Result<Self> {
        let mut clients = Vec::new();
        let mut by_id = HashMap::new();

        let mut current_section = String::new();
        let mut current_values: Vec<String> = Vec::new();
        let mut all_sections: HashMap<String, Vec<String>> = HashMap::new();

        for line in data.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Detect section start (e.g., "names+=(")
            if let Some((section, rest)) = line.split_once("+=(") {
                Self::append_section_values(
                    &mut all_sections,
                    &mut current_section,
                    &mut current_values,
                );

                current_section = section.trim().to_string();
                current_values.extend(Self::extract_array_values(rest));

                if rest.contains(')') {
                    Self::append_section_values(
                        &mut all_sections,
                        &mut current_section,
                        &mut current_values,
                    );
                }
                continue;
            }

            if current_section.is_empty() {
                continue;
            }

            current_values.extend(Self::extract_array_values(line));

            // End of section
            if line.contains(')') {
                Self::append_section_values(
                    &mut all_sections,
                    &mut current_section,
                    &mut current_values,
                );
            }
        }

        Self::append_section_values(&mut all_sections, &mut current_section, &mut current_values);

        // Build client profiles from sections
        if let Some(names) = all_sections.get("names") {
            for (i, name) in names.iter().enumerate() {
                let profile = ClientProfile {
                    name: name.clone(),
                    short_id: all_sections
                        .get("short")
                        .and_then(|v| v.get(i))
                        .cloned()
                        .unwrap_or_else(|| format!("client_{}", i)),
                    cipher_string: all_sections
                        .get("ch_ciphers")
                        .and_then(|v| v.get(i))
                        .cloned(),
                    tls13_ciphers: all_sections
                        .get("ciphersuites")
                        .and_then(|v| v.get(i))
                        .cloned(),
                    uses_sni: all_sections
                        .get("ch_sni")
                        .and_then(|v| v.get(i))
                        .map(|s| !s.is_empty())
                        .unwrap_or(true),
                    warning: all_sections.get("warning").and_then(|v| v.get(i)).cloned(),
                    handshake_bytes: all_sections
                        .get("handshakebytes")
                        .and_then(|v| v.get(i))
                        .cloned(),
                    protocol_flags: all_sections
                        .get("protos")
                        .and_then(|v| v.get(i))
                        .map(|s| s.split_whitespace().map(String::from).collect())
                        .unwrap_or_default(),
                    tls_version: all_sections.get("tlsvers").and_then(|v| v.get(i)).cloned(),
                    lowest_protocol: all_sections
                        .get("lowest_protocol")
                        .and_then(|v| v.get(i))
                        .cloned(),
                    highest_protocol: all_sections
                        .get("highest_protocol")
                        .and_then(|v| v.get(i))
                        .cloned(),
                    services: all_sections
                        .get("service")
                        .and_then(|v| v.get(i))
                        .map(|s| {
                            s.split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default(),
                    min_dh_bits: all_sections
                        .get("minDhBits")
                        .and_then(|v| v.get(i))
                        .and_then(|s| s.parse().ok()),
                    max_dh_bits: all_sections
                        .get("maxDhBits")
                        .and_then(|v| v.get(i))
                        .and_then(|s| s.parse().ok()),
                    min_rsa_bits: all_sections
                        .get("minRsaBits")
                        .and_then(|v| v.get(i))
                        .and_then(|s| s.parse().ok()),
                    max_rsa_bits: all_sections
                        .get("maxRsaBits")
                        .and_then(|v| v.get(i))
                        .and_then(|s| s.parse().ok()),
                    min_ecdsa_bits: all_sections
                        .get("minEcdsaBits")
                        .and_then(|v| v.get(i))
                        .and_then(|s| s.parse().ok()),
                    curves: all_sections
                        .get("curves")
                        .and_then(|v| v.get(i))
                        .map(|s| {
                            s.split(|c: char| c == ':' || c.is_ascii_whitespace())
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default(),
                    requires_sha2: all_sections
                        .get("requiresSha2")
                        .and_then(|v| v.get(i))
                        .and_then(|s| Self::parse_bool(s))
                        .unwrap_or(false),
                    current: all_sections
                        .get("current")
                        .and_then(|v| v.get(i))
                        .and_then(|s| Self::parse_bool(s))
                        .unwrap_or(true),
                };

                by_id.insert(profile.short_id.clone(), i);
                clients.push(profile);
            }
        }

        Ok(Self { clients, by_id })
    }

    fn append_section_values(
        all_sections: &mut HashMap<String, Vec<String>>,
        current_section: &mut String,
        current_values: &mut Vec<String>,
    ) {
        if current_section.is_empty() {
            return;
        }

        all_sections
            .entry(std::mem::take(current_section))
            .or_default()
            .append(current_values);
    }

    fn extract_array_values(line: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut current = String::new();
        let mut in_quote = false;
        let mut in_token = false;
        let mut escape_next = false;

        for ch in line.chars() {
            if escape_next {
                current.push(ch);
                escape_next = false;
                continue;
            }

            if in_quote {
                match ch {
                    '\\' => escape_next = true,
                    '"' => {
                        values.push(std::mem::take(&mut current));
                        in_quote = false;
                        in_token = false;
                    }
                    _ => current.push(ch),
                }
                continue;
            }

            match ch {
                '"' => {
                    current.clear();
                    in_quote = true;
                    in_token = true;
                }
                ')' => {
                    if in_token {
                        values.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                    break;
                }
                '(' => {}
                '#' => break,
                ch if ch.is_ascii_whitespace() => {
                    if in_token {
                        values.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                }
                _ => {
                    current.push(ch);
                    in_token = true;
                }
            }
        }

        if in_token && !in_quote {
            values.push(current);
        }

        values
    }

    fn parse_bool(value: &str) -> Option<bool> {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    }

    /// Get client by ID
    pub fn get_by_id(&self, id: &str) -> Option<&ClientProfile> {
        self.by_id.get(id).and_then(|&i| self.clients.get(i))
    }

    /// Get all clients
    pub fn all_clients(&self) -> &[ClientProfile] {
        &self.clients
    }

    /// Get current/maintained clients only
    pub fn current_clients(&self) -> Vec<&ClientProfile> {
        self.clients.iter().filter(|c| c.current).collect()
    }

    /// Get clients by service
    pub fn by_service(&self, service: &str) -> Vec<&ClientProfile> {
        self.clients
            .iter()
            .filter(|c| c.services.iter().any(|s| s.eq_ignore_ascii_case(service)))
            .collect()
    }

    /// Get client count
    pub fn count(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_database() {
        let db = ClientDatabase::load();
        assert!(db.is_ok());

        let db = db.expect("test assertion should succeed");
        assert!(db.count() > 0);
    }

    #[test]
    fn test_current_clients_filter() {
        let db = client_db();
        let current = db.current_clients();

        for client in current {
            assert!(client.current);
        }
    }

    #[test]
    fn test_by_service_and_lookup_by_id() {
        let data = r#"
names+=(
"Client A"
)
short+=(
"client_a"
)
service+=(
"HTTP,FTP"
)
"#;

        let db = ClientDatabase::parse(data).expect("test assertion should succeed");
        let by_http = db.by_service("http");
        assert_eq!(by_http.len(), 1);
        assert_eq!(by_http[0].short_id, "client_a");

        let by_ftp = db.by_service("FTP");
        assert_eq!(by_ftp.len(), 1);

        let profile = db.get_by_id("client_a").expect("client should exist");
        assert_eq!(profile.name, "Client A");
    }

    #[test]
    fn test_parse_accumulates_repeated_single_value_sections() {
        let data = r#"
names+=("Client A")
short+=("client_a")
current+=(true)
names+=("Client B")
short+=("client_b")
current+=(false)
"#;

        let db = ClientDatabase::parse(data).expect("test assertion should succeed");

        assert_eq!(db.count(), 2);
        assert_eq!(
            db.get_by_id("client_a")
                .expect("client A should exist")
                .name,
            "Client A"
        );
        let client_b = db.get_by_id("client_b").expect("client B should exist");
        assert_eq!(client_b.name, "Client B");
        assert!(!client_b.current);
    }

    #[test]
    fn test_parse_preserves_empty_quoted_values_for_column_alignment() {
        let data = r#"
names+=("Client A")
short+=("client_a")
ch_sni+=("")
names+=("Client B")
short+=("client_b")
ch_sni+=("SNI")
"#;

        let db = ClientDatabase::parse(data).expect("test assertion should succeed");

        assert!(!db.get_by_id("client_a").expect("client A").uses_sni);
        assert!(db.get_by_id("client_b").expect("client B").uses_sni);
    }

    #[test]
    fn test_parse_splits_curves_on_colons_and_whitespace() {
        let data = r#"
names+=("Client A")
short+=("client_a")
curves+=("X25519:secp256r1 secp384r1")
"#;

        let db = ClientDatabase::parse(data).expect("test assertion should succeed");
        let client = db.get_by_id("client_a").expect("client should exist");

        assert_eq!(client.curves, ["X25519", "secp256r1", "secp384r1"]);
    }

    #[test]
    fn test_load_database_keeps_legacy_clients_out_of_current_set() {
        let db = ClientDatabase::load().expect("embedded client database should load");
        let legacy = db
            .get_by_id("android_237")
            .expect("legacy Android profile should exist");

        assert!(!legacy.current);
        assert!(db.get_by_id("android_81").expect("current profile").current);
        assert!(db.current_clients().len() < db.count());
    }
}
