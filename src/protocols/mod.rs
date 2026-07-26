// Protocols module - TLS/SSL protocol definitions and testing

use serde::{Deserialize, Serialize};

mod model;
pub(crate) mod parse_bytes;
pub(crate) mod tls_record;
pub(crate) mod tls_vector;
pub use model::{Protocol, ProtocolTestResult};

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

pub mod alpn;
pub mod auto_detection;
pub mod client_cas;
pub mod fallback_scsv;
pub mod groups;
pub mod handshake;
pub mod intolerance;
pub mod npn;
pub mod pre_handshake;
pub mod rdp;
pub mod renegotiation;
pub mod session_resumption;
pub mod signatures;
pub mod tester;

pub use tester::{ProtocolTestable, ProtocolTester};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_new_known_and_unknown() {
        let ext = Extension::new(0x0000, vec![1, 2, 3]);
        assert_eq!(ext.name, "server_name (SNI)");
        assert_eq!(ext.data, vec![1, 2, 3]);

        let unknown = Extension::new(0x9999, vec![]);
        assert_eq!(unknown.name, "unknown");
    }

    #[test]
    fn test_protocol_all_excludes_quic() {
        let all = Protocol::all();
        assert!(all.contains(&Protocol::TLS12));
        assert!(!all.contains(&Protocol::QUIC));
    }

    #[test]
    fn test_protocol_from_str_known() {
        let protocol: Protocol = "TLS 1.2".parse().expect("should parse");
        assert_eq!(protocol, Protocol::TLS12);
        let protocol: Protocol = "SSLv3".parse().expect("should parse");
        assert_eq!(protocol, Protocol::SSLv3);
    }

    #[test]
    fn test_protocol_from_hex_includes_quic() {
        assert_eq!(Protocol::from(0x0305), Protocol::QUIC);
    }
}
