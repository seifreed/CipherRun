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
                    event_name = "protocol.version.unknown",
                    protocol_version = value,
                    fallback = "tls1.2",
                    "Unknown protocol version; using fallback"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    struct CapturedOutputWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for CapturedOutput {
        type Writer = CapturedOutputWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedOutputWriter(self.0.clone())
        }
    }

    impl Write for CapturedOutputWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn protocol_contracts_cover_names_versions_and_deprecation() {
        let cases = [
            (Protocol::SSLv2, 0x0002, "SSLv2", true),
            (Protocol::SSLv3, 0x0300, "SSLv3", true),
            (Protocol::TLS10, 0x0301, "TLS 1.0", true),
            (Protocol::TLS11, 0x0302, "TLS 1.1", true),
            (Protocol::TLS12, 0x0303, "TLS 1.2", false),
            (Protocol::TLS13, 0x0304, "TLS 1.3", false),
            (Protocol::QUIC, 0x0305, "QUIC", false),
        ];

        for (protocol, version, name, deprecated) in cases {
            assert_eq!(protocol.as_hex(), version);
            assert_eq!(protocol.name(), name);
            assert_eq!(protocol.to_string(), name);
            assert_eq!(protocol.is_deprecated(), deprecated);
            assert_eq!(Protocol::from(version), protocol);
        }

        assert_eq!(
            Protocol::all(),
            vec![
                Protocol::SSLv2,
                Protocol::SSLv3,
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13,
            ]
        );
    }

    #[test]
    fn protocol_parser_accepts_aliases_and_rejects_unknown_values() {
        for (name, expected) in [
            ("SSLv2.0", Protocol::SSLv2),
            ("ssl2.0", Protocol::SSLv2),
            ("SSLv3.0", Protocol::SSLv3),
            ("ssl3.0", Protocol::SSLv3),
            ("TLSv1", Protocol::TLS10),
            ("TLSv10", Protocol::TLS10),
            ("TLSv1.1", Protocol::TLS11),
            ("TLS11", Protocol::TLS11),
            ("TLSv1.2", Protocol::TLS12),
            ("TLS12", Protocol::TLS12),
            ("TLSv1.3", Protocol::TLS13),
            ("TLS13", Protocol::TLS13),
            ("QUIC", Protocol::QUIC),
        ] {
            assert_eq!(name.parse::<Protocol>().unwrap(), expected, "{name}");
        }
        assert!("TLS 9.9".parse::<Protocol>().is_err());
    }

    #[test]
    fn unknown_numeric_protocol_versions_fall_back_to_tls12() {
        let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.clone())
            .finish();

        let protocol = tracing::subscriber::with_default(subscriber, || Protocol::from(0xffff));
        CapturedOutputWriter(output.0.clone()).flush().unwrap();

        assert_eq!(protocol, Protocol::TLS12);
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(event["fields"]["event_name"], "protocol.version.unknown");
        assert_eq!(event["fields"]["protocol_version"], 0xffff);
        assert_eq!(event["fields"]["fallback"], "tls1.2");
    }

    #[test]
    fn protocol_result_status_prefers_supported_then_inconclusive() {
        let result = |supported, inconclusive| ProtocolTestResult {
            protocol: Protocol::TLS12,
            supported,
            inconclusive,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        };

        assert_eq!(result(true, true).status_label(), "Supported");
        assert_eq!(result(false, true).status_label(), "Inconclusive");
        assert_eq!(result(false, false).status_label(), "Not supported");
    }
}
