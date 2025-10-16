// Client Simulation Data Parser - Parses client-simulation.txt

use anyhow::Result;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;

lazy_static! {
    /// Global client database loaded at startup
    pub static ref CLIENT_DB: Arc<ClientDatabase> = Arc::new(
        ClientDatabase::load().expect("Failed to load client database")
    );
}

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

    /// Parse client-simulation.txt format (bash array format)
    pub fn parse(data: &str) -> Result<Self> {
        let mut clients = Vec::new();
        let mut by_id = HashMap::new();

        // This is a simplified parser - the real format is complex bash arrays
        // For now, we'll parse the basic structure

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
            if line.contains("+=(") {
                // Save previous section
                if !current_section.is_empty() {
                    all_sections.insert(current_section.clone(), current_values.clone());
                    current_values.clear();
                }

                // Start new section
                if let Some(name) = line.split('+').next() {
                    current_section = name.trim().to_string();
                }

                // Extract value from same line if present (e.g., names+=("value"))
                if line.contains('"')
                    && let Some(value) = Self::extract_quoted(line)
                {
                    current_values.push(value);
                }
                continue;
            }

            // Collect values
            if line.starts_with('"') || line.contains('"') {
                // Extract quoted string
                if let Some(value) = Self::extract_quoted(line) {
                    current_values.push(value);
                }
            }

            // End of section
            if line.starts_with(')') && !current_section.is_empty() {
                all_sections.insert(current_section.clone(), current_values.clone());
                current_values.clear();
                current_section.clear();
            }
        }

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
                        .map(|s| s.split(',').map(String::from).collect())
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
                        .map(|s| s.split_whitespace().map(String::from).collect())
                        .unwrap_or_default(),
                    requires_sha2: all_sections
                        .get("requiresSha2")
                        .and_then(|v| v.get(i))
                        .map(|s| s == "true")
                        .unwrap_or(false),
                    current: all_sections
                        .get("current")
                        .and_then(|v| v.get(i))
                        .map(|s| s == "true")
                        .unwrap_or(true),
                };

                by_id.insert(profile.short_id.clone(), i);
                clients.push(profile);
            }
        }

        Ok(Self { clients, by_id })
    }

    /// Extract quoted string from line
    fn extract_quoted(line: &str) -> Option<String> {
        let mut in_quote = false;
        let mut result = String::new();
        let mut escape_next = false;

        for ch in line.chars() {
            if escape_next {
                result.push(ch);
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => escape_next = true,
                '"' => {
                    if in_quote {
                        return Some(result);
                    }
                    in_quote = true;
                }
                _ if in_quote => result.push(ch),
                _ => {}
            }
        }

        if !result.is_empty() {
            Some(result)
        } else {
            None
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
    fn test_extract_quoted() {
        assert_eq!(
            ClientDatabase::extract_quoted(r#""Hello World""#),
            Some("Hello World".to_string())
        );

        assert_eq!(
            ClientDatabase::extract_quoted(r#"  "Test String"  "#),
            Some("Test String".to_string())
        );
    }

    #[test]
    fn test_load_database() {
        let db = ClientDatabase::load();
        assert!(db.is_ok());

        let db = db.unwrap();
        assert!(db.count() > 0);
    }

    #[test]
    fn test_current_clients_filter() {
        let db = CLIENT_DB.as_ref();
        let current = db.current_clients();

        for client in current {
            assert!(client.current);
        }
    }
}
