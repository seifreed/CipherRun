// Protocols module - TLS/SSL protocol definitions and testing

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// TLS/SSL protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Protocol {
    SSLv2,
    SSLv3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    QUIC,
}

impl Protocol {
    /// Get protocol version as hex value
    pub fn as_hex(&self) -> u16 {
        match self {
            Protocol::SSLv2 => 0x0002,
            Protocol::SSLv3 => 0x0300,
            Protocol::TLS10 => 0x0301,
            Protocol::TLS11 => 0x0302,
            Protocol::TLS12 => 0x0303,
            Protocol::TLS13 => 0x0304,
            Protocol::QUIC => 0x0305, // Not standard, for internal use
        }
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::SSLv2 => "SSLv2",
            Protocol::SSLv3 => "SSLv3",
            Protocol::TLS10 => "TLS 1.0",
            Protocol::TLS11 => "TLS 1.1",
            Protocol::TLS12 => "TLS 1.2",
            Protocol::TLS13 => "TLS 1.3",
            Protocol::QUIC => "QUIC",
        }
    }

    /// Check if protocol is deprecated
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            Protocol::SSLv2 | Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11
        )
    }

    /// Get all protocols
    pub fn all() -> Vec<Protocol> {
        vec![
            Protocol::SSLv2,
            Protocol::SSLv3,
            Protocol::TLS10,
            Protocol::TLS11,
            Protocol::TLS12,
            Protocol::TLS13,
        ]
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Standard display format with spaces
            "SSLv2" | "SSL 2.0" => Ok(Protocol::SSLv2),
            "SSLv3" | "SSL 3.0" => Ok(Protocol::SSLv3),
            "TLS 1.0" | "TLSv1.0" | "TLSv1" => Ok(Protocol::TLS10),
            "TLS 1.1" | "TLSv1.1" => Ok(Protocol::TLS11),
            "TLS 1.2" | "TLSv1.2" => Ok(Protocol::TLS12),
            "TLS 1.3" | "TLSv1.3" => Ok(Protocol::TLS13),
            "QUIC" => Ok(Protocol::QUIC),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

impl From<u16> for Protocol {
    fn from(value: u16) -> Self {
        match value {
            0x0002 => Protocol::SSLv2,
            0x0300 => Protocol::SSLv3,
            0x0301 => Protocol::TLS10,
            0x0302 => Protocol::TLS11,
            0x0303 => Protocol::TLS12,
            0x0304 => Protocol::TLS13,
            _ => Protocol::TLS12, // Default to TLS 1.2
        }
    }
}

/// Protocol test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTestResult {
    pub protocol: Protocol,
    pub supported: bool,
    pub preferred: bool,
    pub ciphers_count: usize,
    pub handshake_time_ms: Option<u64>,
    /// Heartbeat extension (RFC 6520) support detection
    /// Some(true) if server supports heartbeat extension (type 0x000f)
    /// Some(false) if server does not support it
    /// None if not tested or handshake failed
    pub heartbeat_enabled: Option<bool>,
}

/// TLS extension
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: u16,
    pub name: String,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn new(extension_type: u16, data: Vec<u8>) -> Self {
        let name = match extension_type {
            0x0000 => "server_name (SNI)",
            0x0001 => "max_fragment_length",
            0x0005 => "status_request (OCSP stapling)",
            0x000a => "supported_groups",
            0x000b => "ec_point_formats",
            0x000d => "signature_algorithms",
            0x000f => "heartbeat",
            0x0010 => "application_layer_protocol_negotiation (ALPN)",
            0x0012 => "signed_certificate_timestamp",
            0x0015 => "padding",
            0x0017 => "extended_master_secret",
            0x0018 => "compress_certificate",
            0x001b => "cert_compression",
            0x0023 => "session_ticket",
            0x002b => "supported_versions",
            0x002d => "psk_key_exchange_modes",
            0x0033 => "key_share",
            0xff01 => "renegotiation_info",
            _ => "unknown",
        };

        Self {
            extension_type,
            name: name.to_string(),
            data,
        }
    }
}

pub mod advanced;
pub mod alpn;
pub mod auto_detection;
pub mod client_cas;
pub mod extensions_complete;
pub mod fallback_scsv;
pub mod groups;
pub mod handshake;
pub mod hello_export;
pub mod intolerance;
pub mod legacy_compat;
pub mod npn;
pub mod pre_handshake;
pub mod rc4;
pub mod rdp;
pub mod renegotiation;
pub mod server_defaults_advanced;
pub mod session_resumption;
pub mod signatures;
pub mod tester;
