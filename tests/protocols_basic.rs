// Basic tests for protocol enums and extensions.

use cipherrun::protocols::{Extension, Protocol};
use std::str::FromStr;

#[test]
fn test_protocol_name_and_hex() {
    assert_eq!(Protocol::TLS13.name(), "TLS 1.3");
    assert_eq!(Protocol::TLS13.as_hex(), 0x0304);
    assert_eq!(Protocol::SSLv3.as_hex(), 0x0300);
    assert_eq!(Protocol::QUIC.name(), "QUIC");
}

#[test]
fn test_protocol_is_deprecated() {
    assert!(Protocol::SSLv2.is_deprecated());
    assert!(Protocol::TLS10.is_deprecated());
    assert!(!Protocol::TLS12.is_deprecated());
    assert!(!Protocol::TLS13.is_deprecated());
    assert!(!Protocol::QUIC.is_deprecated());
}

#[test]
fn test_protocol_all_excludes_quic() {
    let all = Protocol::all();
    assert!(all.contains(&Protocol::TLS12));
    assert!(!all.contains(&Protocol::QUIC));
}

#[test]
fn test_protocol_from_str() {
    assert_eq!(Protocol::from_str("TLS 1.2").unwrap(), Protocol::TLS12);
    assert_eq!(Protocol::from_str("TLSv1.3").unwrap(), Protocol::TLS13);
    assert_eq!(Protocol::from_str("SSL 3.0").unwrap(), Protocol::SSLv3);
    assert!(Protocol::from_str("NOPE").is_err());
}

#[test]
fn test_protocol_from_u16() {
    assert_eq!(Protocol::from(0x0304), Protocol::TLS13);
    assert_eq!(Protocol::from(0x0301), Protocol::TLS10);
    assert_eq!(Protocol::from(0x1234), Protocol::TLS12);
}

#[test]
fn test_extension_new_names() {
    let sni = Extension::new(0x0000, vec![1, 2, 3]);
    assert_eq!(sni.name, "server_name (SNI)");

    let unknown = Extension::new(0x9999, vec![]);
    assert_eq!(unknown.name, "unknown");
}
