// JA3S TLS Server Fingerprinting module
//
// JA3S is a method for creating SSL/TLS server fingerprints based on
// the ServerHello message. The fingerprint helps identify CDNs, load balancers,
// and server software.
//
// JA3S Format: SSLVersion,Cipher,Extensions
// - SSLVersion: Decimal representation of TLS version (e.g., 771 for TLS 1.2)
// - Cipher: Single selected cipher suite in decimal
// - Extensions: Comma-separated extension IDs in decimal (order preserved)
//
// Reference: https://github.com/salesforce/ja3

use crate::fingerprint::server_hello::ServerHelloCapture;
use crate::Result;
use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JA3S fingerprint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3sFingerprint {
    /// Raw JA3S string before hashing
    pub ja3s_string: String,
    /// MD5 hash of JA3S string (32 hex characters)
    pub ja3s_hash: String,
    /// SSL/TLS version in decimal
    pub ssl_version: u16,
    /// Selected cipher suite in decimal
    pub cipher: u16,
    /// Extension IDs in order
    pub extensions: Vec<u16>,
}

impl Ja3sFingerprint {
    /// Generate JA3S fingerprint from ServerHello
    pub fn from_server_hello(server_hello: &ServerHelloCapture) -> Self {
        let version = server_hello.version;
        let cipher = server_hello.cipher_suite;
        let extensions = server_hello.get_extension_ids();

        let ja3s_string = Self::build_ja3s_string(version, cipher, &extensions);
        let ja3s_hash = Self::calculate_hash(&ja3s_string);

        Ja3sFingerprint {
            ja3s_string,
            ja3s_hash,
            ssl_version: version,
            cipher,
            extensions,
        }
    }

    /// Build JA3S string from components
    ///
    /// Format: "SSLVersion,Cipher,Extension1-Extension2-Extension3"
    fn build_ja3s_string(version: u16, cipher: u16, extensions: &[u16]) -> String {
        let ext_str = if extensions.is_empty() {
            String::new()
        } else {
            extensions.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };

        format!("{},{},{}", version, cipher, ext_str)
    }

    /// Calculate MD5 hash of JA3S string
    fn calculate_hash(ja3s_string: &str) -> String {
        let digest = md5::compute(ja3s_string.as_bytes());
        format!("{:x}", digest)
    }

    /// Get TLS version name
    pub fn version_name(&self) -> String {
        match self.ssl_version {
            0x0200 => "SSL 2.0".to_string(),
            0x0300 => "SSL 3.0".to_string(),
            0x0301 => "TLS 1.0".to_string(),
            0x0302 => "TLS 1.1".to_string(),
            0x0303 => "TLS 1.2".to_string(),
            0x0304 => "TLS 1.3".to_string(),
            _ => format!("Unknown (0x{:04x})", self.ssl_version),
        }
    }

    /// Get cipher suite name (basic mapping)
    pub fn cipher_name(&self) -> String {
        // Use the cipher database if available
        use crate::data::CIPHER_DB;

        // Convert decimal cipher value to hex string (lowercase, no 0x prefix)
        let hexcode = format!("{:04x}", self.cipher);

        if let Some(cipher_info) = CIPHER_DB.get_by_hexcode(&hexcode) {
            cipher_info.openssl_name.clone()
        } else {
            format!("Unknown (0x{:04X})", self.cipher)
        }
    }

    /// Get extension names
    pub fn extension_names(&self) -> Vec<String> {
        self.extensions.iter().map(|&ext_id| {
            get_extension_name(ext_id)
        }).collect()
    }
}

/// Server type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServerType {
    CDN,
    LoadBalancer,
    WebServer,
    ApplicationServer,
    Firewall,
    ReverseProxy,
    Unknown,
}

impl std::fmt::Display for ServerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerType::CDN => write!(f, "CDN"),
            ServerType::LoadBalancer => write!(f, "Load Balancer"),
            ServerType::WebServer => write!(f, "Web Server"),
            ServerType::ApplicationServer => write!(f, "Application Server"),
            ServerType::Firewall => write!(f, "Firewall"),
            ServerType::ReverseProxy => write!(f, "Reverse Proxy"),
            ServerType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// JA3S signature from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3sSignature {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: ServerType,
    pub description: String,
    pub common_ports: Vec<u16>,
    pub indicators: Vec<String>,
}

/// JA3S signature database
#[derive(Debug, Clone)]
pub struct Ja3sDatabase {
    signatures: HashMap<String, Ja3sSignature>,
}

impl Ja3sDatabase {
    /// Load default database from embedded JSON
    pub fn load_default() -> Result<Self> {
        let json = include_str!("../../data/ja3s_signatures.json");
        let signatures: HashMap<String, Ja3sSignature> = serde_json::from_str(json)
            .map_err(|e| TlsError::ParseError { message: format!("Failed to parse JA3S database: {}", e) })?;

        Ok(Ja3sDatabase { signatures })
    }

    /// Match a JA3S hash against the database
    pub fn match_fingerprint(&self, ja3s_hash: &str) -> Option<&Ja3sSignature> {
        self.signatures.get(ja3s_hash)
    }

    /// Get all signatures
    pub fn all_signatures(&self) -> &HashMap<String, Ja3sSignature> {
        &self.signatures
    }

    /// Get signature count
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

/// CDN detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnDetection {
    pub is_cdn: bool,
    pub cdn_provider: Option<String>,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

impl CdnDetection {
    /// Detect CDN from JA3S fingerprint and HTTP headers
    pub fn from_ja3s_and_headers(
        ja3s: &Ja3sFingerprint,
        ja3s_match: Option<&Ja3sSignature>,
        http_headers: &HashMap<String, String>,
    ) -> Self {
        let mut is_cdn = false;
        let mut cdn_provider = None;
        let mut confidence: f32 = 0.0;
        let mut indicators = Vec::new();

        // Check JA3S signature match
        if let Some(sig) = ja3s_match {
            if sig.server_type == ServerType::CDN {
                is_cdn = true;
                cdn_provider = Some(sig.name.clone());
                confidence += 0.7;
                indicators.push(format!("JA3S signature matches {}", sig.name));
            }
        }

        // Check HTTP headers for CDN indicators
        for (header_name, header_value) in http_headers {
            let header_lower = header_name.to_lowercase();
            let value_lower = header_value.to_lowercase();

            // Cloudflare indicators
            if header_lower == "cf-ray" || header_lower == "cf-cache-status" {
                is_cdn = true;
                if cdn_provider.is_none() {
                    cdn_provider = Some("Cloudflare".to_string());
                }
                confidence += 0.3;
                indicators.push(format!("Header: {}", header_name));
            }
            if header_lower == "server" && value_lower.contains("cloudflare") {
                is_cdn = true;
                cdn_provider = Some("Cloudflare".to_string());
                confidence += 0.2;
                indicators.push("Server header contains 'cloudflare'".to_string());
            }

            // Akamai indicators
            if header_lower.starts_with("x-akamai") {
                is_cdn = true;
                if cdn_provider.is_none() {
                    cdn_provider = Some("Akamai".to_string());
                }
                confidence += 0.3;
                indicators.push(format!("Header: {}", header_name));
            }

            // Fastly indicators
            if header_lower.starts_with("x-fastly") || header_lower == "fastly-debug-digest" {
                is_cdn = true;
                if cdn_provider.is_none() {
                    cdn_provider = Some("Fastly".to_string());
                }
                confidence += 0.3;
                indicators.push(format!("Header: {}", header_name));
            }

            // AWS CloudFront indicators
            if header_lower.starts_with("x-amz-cf-") || header_lower == "x-cache" && value_lower.contains("cloudfront") {
                is_cdn = true;
                if cdn_provider.is_none() {
                    cdn_provider = Some("AWS CloudFront".to_string());
                }
                confidence += 0.3;
                indicators.push(format!("Header: {}", header_name));
            }

            // Other CDN indicators
            if header_lower == "x-cdn" || header_lower == "x-cdn-forward" {
                is_cdn = true;
                confidence += 0.2;
                indicators.push("Generic CDN header detected".to_string());
            }
        }

        confidence = confidence.min(1.0);

        CdnDetection {
            is_cdn,
            cdn_provider,
            confidence,
            indicators,
        }
    }
}

/// Load balancer detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerInfo {
    pub detected: bool,
    pub lb_type: Option<String>,
    pub sticky_sessions: bool,
    pub indicators: Vec<String>,
}

impl LoadBalancerInfo {
    /// Detect load balancer from JA3S and headers
    pub fn from_ja3s_and_headers(
        ja3s_match: Option<&Ja3sSignature>,
        http_headers: &HashMap<String, String>,
    ) -> Self {
        let mut detected = false;
        let mut lb_type = None;
        let mut sticky_sessions = false;
        let mut indicators = Vec::new();

        // Check JA3S signature
        if let Some(sig) = ja3s_match {
            if sig.server_type == ServerType::LoadBalancer {
                detected = true;
                lb_type = Some(sig.name.clone());
                indicators.push(format!("JA3S signature matches {}", sig.name));
            }
        }

        // Check HTTP headers
        for (header_name, header_value) in http_headers {
            let header_lower = header_name.to_lowercase();
            let value_lower = header_value.to_lowercase();

            // AWS ELB/ALB
            if header_lower == "x-amzn-trace-id" || header_lower == "x-amzn-requestid" {
                detected = true;
                if lb_type.is_none() {
                    lb_type = Some("AWS ELB/ALB".to_string());
                }
                indicators.push(format!("AWS header: {}", header_name));
            }

            // HAProxy
            if header_lower.starts_with("x-haproxy-") {
                detected = true;
                if lb_type.is_none() {
                    lb_type = Some("HAProxy".to_string());
                }
                indicators.push("HAProxy header detected".to_string());
            }

            // nginx load balancer
            if header_lower == "x-upstream-addr" || header_lower == "x-upstream-status" {
                detected = true;
                if lb_type.is_none() {
                    lb_type = Some("nginx".to_string());
                }
                indicators.push("nginx upstream headers detected".to_string());
            }

            // Sticky session indicators
            if value_lower.contains("route") || value_lower.contains("sticky") || value_lower.contains("persist") {
                sticky_sessions = true;
                indicators.push("Sticky session cookie detected".to_string());
            }
        }

        LoadBalancerInfo {
            detected,
            lb_type,
            sticky_sessions,
            indicators,
        }
    }
}

/// Get human-readable extension name
fn get_extension_name(extension_id: u16) -> String {
    match extension_id {
        0 => "server_name".to_string(),
        1 => "max_fragment_length".to_string(),
        5 => "status_request".to_string(),
        10 => "supported_groups".to_string(),
        11 => "ec_point_formats".to_string(),
        13 => "signature_algorithms".to_string(),
        14 => "use_srtp".to_string(),
        15 => "heartbeat".to_string(),
        16 => "application_layer_protocol_negotiation".to_string(),
        18 => "signed_certificate_timestamp".to_string(),
        19 => "client_certificate_type".to_string(),
        20 => "server_certificate_type".to_string(),
        21 => "padding".to_string(),
        23 => "extended_master_secret".to_string(),
        35 => "session_ticket".to_string(),
        41 => "pre_shared_key".to_string(),
        42 => "early_data".to_string(),
        43 => "supported_versions".to_string(),
        44 => "cookie".to_string(),
        45 => "psk_key_exchange_modes".to_string(),
        47 => "certificate_authorities".to_string(),
        48 => "oid_filters".to_string(),
        49 => "post_handshake_auth".to_string(),
        50 => "signature_algorithms_cert".to_string(),
        51 => "key_share".to_string(),
        13172 => "next_protocol_negotiation".to_string(),
        65281 => "renegotiation_info".to_string(),
        _ => format!("unknown_{}", extension_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja3s_hash_cloudflare() {
        // Known Cloudflare JA3S: "771,49199,65281-0-11-35-23"
        let ja3s_string = "771,49199,65281-0-11-35-23";
        let hash = Ja3sFingerprint::calculate_hash(ja3s_string);
        assert_eq!(hash, "098e26e2609212ac1bfac552fbe04127");
    }

    #[test]
    fn test_ja3s_build_string() {
        let version = 771; // TLS 1.2
        let cipher = 49199; // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        let extensions = vec![65281, 0, 11, 35, 23];

        let ja3s_string = Ja3sFingerprint::build_ja3s_string(version, cipher, &extensions);
        assert_eq!(ja3s_string, "771,49199,65281-0-11-35-23");
    }

    #[test]
    fn test_ja3s_no_extensions() {
        let version = 771;
        let cipher = 47; // TLS_RSA_WITH_AES_128_CBC_SHA
        let extensions = vec![];

        let ja3s_string = Ja3sFingerprint::build_ja3s_string(version, cipher, &extensions);
        assert_eq!(ja3s_string, "771,47,");
    }

    #[test]
    fn test_version_name() {
        let mut fp = Ja3sFingerprint {
            ja3s_string: String::new(),
            ja3s_hash: String::new(),
            ssl_version: 0x0303,
            cipher: 0,
            extensions: vec![],
        };

        assert_eq!(fp.version_name(), "TLS 1.2");

        fp.ssl_version = 0x0304;
        assert_eq!(fp.version_name(), "TLS 1.3");
    }

    #[test]
    fn test_cdn_detection_cloudflare() {
        let ja3s = Ja3sFingerprint {
            ja3s_string: "771,49199,65281-0-11-35-23".to_string(),
            ja3s_hash: "098e26e2609212ac1bfac552fbe04127".to_string(),
            ssl_version: 771,
            cipher: 49199,
            extensions: vec![65281, 0, 11, 35, 23],
        };

        let mut headers = HashMap::new();
        headers.insert("CF-RAY".to_string(), "12345678-SJC".to_string());
        headers.insert("Server".to_string(), "cloudflare".to_string());

        let detection = CdnDetection::from_ja3s_and_headers(&ja3s, None, &headers);

        assert!(detection.is_cdn);
        assert_eq!(detection.cdn_provider, Some("Cloudflare".to_string()));
        assert!(detection.confidence > 0.0);
    }

    #[test]
    fn test_lb_detection_aws() {
        let mut headers = HashMap::new();
        headers.insert("X-Amzn-Trace-Id".to_string(), "Root=1-123456".to_string());

        let detection = LoadBalancerInfo::from_ja3s_and_headers(None, &headers);

        assert!(detection.detected);
        assert_eq!(detection.lb_type, Some("AWS ELB/ALB".to_string()));
    }
}
