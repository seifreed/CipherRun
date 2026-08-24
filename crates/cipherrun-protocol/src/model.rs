use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// TLS/SSL protocol versions.
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
    /// Get protocol version as hex value.
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

    /// Get protocol name.
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

    /// Check if protocol is deprecated.
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            Protocol::SSLv2 | Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11
        )
    }

    /// Get all protocols that this scanner can actively probe over TCP/TLS.
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
        let normalized = s
            .trim()
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != '-')
            .collect::<String>()
            .to_ascii_lowercase();

        match normalized.as_str() {
            "sslv2" | "sslv2.0" | "sslv20" | "ssl2.0" | "ssl20" => Ok(Protocol::SSLv2),
            "sslv3" | "sslv3.0" | "sslv30" | "ssl3.0" | "ssl30" => Ok(Protocol::SSLv3),
            "tls1.0" | "tlsv1.0" | "tlsv1" | "tls10" | "tlsv10" => Ok(Protocol::TLS10),
            "tls1.1" | "tlsv1.1" | "tls11" | "tlsv11" => Ok(Protocol::TLS11),
            "tls1.2" | "tlsv1.2" | "tls12" | "tlsv12" => Ok(Protocol::TLS12),
            "tls1.3" | "tlsv1.3" | "tls13" | "tlsv13" => Ok(Protocol::TLS13),
            "quic" => Ok(Protocol::QUIC),
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
            0x0305 => Protocol::QUIC,
            _ => {
                tracing::warn!(
                    "Unknown protocol version 0x{:04x}, defaulting to TLS 1.2",
                    value
                );
                Protocol::TLS12
            }
        }
    }
}

/// Protocol test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTestResult {
    pub protocol: Protocol,
    pub supported: bool,
    #[serde(default)]
    pub inconclusive: bool,
    pub preferred: bool,
    pub ciphers_count: usize,
    pub handshake_time_ms: Option<u64>,
    /// Heartbeat extension (RFC 6520) support detection.
    pub heartbeat_enabled: Option<bool>,
    /// Session resumption via session ID caching.
    pub session_resumption_caching: Option<bool>,
    /// Session resumption via session tickets (RFC 5077).
    pub session_resumption_tickets: Option<bool>,
    /// Secure Renegotiation (RFC 5746) support detection.
    pub secure_renegotiation: Option<bool>,
}

impl ProtocolTestResult {
    /// Human-readable three-state support label.
    pub fn status_label(&self) -> &'static str {
        if self.supported {
            "Supported"
        } else if self.inconclusive {
            "Inconclusive"
        } else {
            "Not supported"
        }
    }
}
