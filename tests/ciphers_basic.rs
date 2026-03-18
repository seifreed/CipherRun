// Basic tests for cipher suite helpers.

use cipherrun::ciphers::{CipherStrength, CipherSuite};

fn make_cipher(
    protocol: &str,
    key_exchange: &str,
    openssl_name: &str,
    iana_name: &str,
    encryption: &str,
    bits: u16,
    export: bool,
) -> CipherSuite {
    CipherSuite {
        hexcode: "0x0000".to_string(),
        openssl_name: openssl_name.to_string(),
        iana_name: iana_name.to_string(),
        protocol: protocol.to_string(),
        key_exchange: key_exchange.to_string(),
        authentication: "RSA".to_string(),
        encryption: encryption.to_string(),
        mac: "SHA256".to_string(),
        bits,
        export,
    }
}

#[test]
fn test_cipher_strength_categories() {
    let null_cipher = make_cipher("TLSv1.2", "", "", "", "NULL", 0, false);
    assert_eq!(null_cipher.strength(), CipherStrength::NULL);

    let export_cipher = make_cipher("TLSv1.2", "", "", "", "AES", 56, true);
    assert_eq!(export_cipher.strength(), CipherStrength::Export);

    let low_cipher = make_cipher("TLSv1.2", "", "", "", "AES", 112, false);
    assert_eq!(low_cipher.strength(), CipherStrength::Low);

    let medium_cipher = make_cipher("TLSv1.2", "", "", "", "AES", 128, false);
    assert_eq!(medium_cipher.strength(), CipherStrength::Medium);

    let high_cipher = make_cipher("TLSv1.2", "", "", "", "AES", 256, false);
    assert_eq!(high_cipher.strength(), CipherStrength::High);
}

#[test]
fn test_forward_secrecy_detection() {
    let tls13 = make_cipher("TLSv1.3", "", "", "", "AES", 128, false);
    assert!(tls13.has_forward_secrecy());

    let ecdhe = make_cipher(
        "TLSv1.2",
        "ECDHE",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "AES",
        128,
        false,
    );
    assert!(ecdhe.has_forward_secrecy());

    let rsa = make_cipher(
        "TLSv1.2",
        "RSA",
        "RSA-AES128-SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "AES",
        128,
        false,
    );
    assert!(!rsa.has_forward_secrecy());
}

#[test]
fn test_aead_detection() {
    let gcm = make_cipher("TLSv1.2", "", "", "", "AES_GCM", 128, false);
    assert!(gcm.is_aead());

    let chacha = make_cipher("TLSv1.2", "", "", "", "CHACHA20_POLY1305", 256, false);
    assert!(chacha.is_aead());

    let cbc = make_cipher("TLSv1.2", "", "", "", "AES_CBC", 128, false);
    assert!(!cbc.is_aead());
}

#[test]
fn test_cipher_strength_display() {
    assert_eq!(format!("{}", CipherStrength::NULL), "NULL");
    assert_eq!(format!("{}", CipherStrength::Export), "EXPORT");
    assert_eq!(format!("{}", CipherStrength::Low), "LOW");
    assert_eq!(format!("{}", CipherStrength::Medium), "MEDIUM");
    assert_eq!(format!("{}", CipherStrength::High), "HIGH");
}
