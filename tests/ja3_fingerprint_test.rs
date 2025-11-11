// JA3 Fingerprinting Tests
// Tests for JA3 TLS client fingerprinting implementation

use cipherrun::fingerprint::{ClientHelloCapture, Ja3Database, Ja3Fingerprint};

#[test]
fn test_ja3_chrome_fingerprint() {
    // Simulate Chrome 120 ClientHello
    let client_hello = ClientHelloCapture::synthetic(
        0x0303, // TLS 1.2
        vec![
            0x1301, 0x1302, 0x1303, // TLS 1.3 ciphers
            0xc02f, 0xc030, 0xc02b, 0xc02c, // TLS 1.2 ECDHE
        ],
        vec![
            (0, vec![]),                           // server_name
            (10, build_groups(&[0x001d, 0x0017])), // X25519, secp256r1
            (11, vec![1, 0]),                      // ec_point_formats
            (13, vec![]),                          // signature_algorithms (simplified)
            (43, vec![2, 0x03, 0x04]),             // supported_versions: TLS 1.3
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    // Verify JA3 structure
    assert_eq!(ja3.ssl_version, 0x0303);
    assert!(!ja3.ciphers.is_empty());
    assert!(!ja3.extensions.is_empty());
    assert!(!ja3.curves.is_empty());

    // Verify hash length
    assert_eq!(ja3.ja3_hash.len(), 32); // MD5 = 32 hex chars

    // Verify string format
    assert!(ja3.ja3_string.contains(','));
    assert!(ja3.ja3_string.starts_with("771")); // TLS 1.2 = 0x0303 = 771
}

#[test]
fn test_ja3_firefox_fingerprint() {
    // Simulate Firefox 121 ClientHello
    let client_hello = ClientHelloCapture::synthetic(
        0x0303, // TLS 1.2
        vec![
            0x1301, 0x1303, 0x1302, // TLS 1.3 ciphers (different order than Chrome)
            0xc02b, 0xc02f, 0xc02c, 0xc030,
        ],
        vec![
            (0, vec![]),                           // server_name
            (10, build_groups(&[0x001d, 0x0018])), // X25519, secp384r1
            (11, vec![1, 0]),                      // ec_point_formats
            (13, vec![]),                          // signature_algorithms
            (43, vec![2, 0x03, 0x04]),             // supported_versions
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    // Different cipher order should produce different hash
    assert_eq!(ja3.ssl_version, 0x0303);
    assert_eq!(ja3.ja3_hash.len(), 32);
}

#[test]
fn test_ja3_grease_filtering() {
    // Test that GREASE values are filtered out
    let client_hello = ClientHelloCapture::synthetic(
        0x0303,
        vec![
            0x0a0a, // GREASE cipher
            0xc02f, // Real cipher
            0x1a1a, // GREASE cipher
            0xc030, // Real cipher
        ],
        vec![
            (0x0a0a, vec![]), // GREASE extension (should be filtered)
            (0, vec![]),      // server_name
            (
                10,
                build_groups(&[
                    0x0a0a, // GREASE curve
                    0x001d, // X25519
                    0x1a1a, // GREASE curve
                    0x0017, // secp256r1
                ]),
            ),
            (11, vec![1, 0]), // ec_point_formats
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    // GREASE values should be filtered
    assert_eq!(ja3.ciphers.len(), 2); // Only 2 real ciphers
    assert!(!ja3.ciphers.contains(&0x0a0a));
    assert!(!ja3.ciphers.contains(&0x1a1a));

    assert_eq!(ja3.curves.len(), 2); // Only 2 real curves
    assert!(!ja3.curves.contains(&0x0a0a));
    assert!(!ja3.curves.contains(&0x1a1a));

    // Extensions should not contain GREASE
    assert!(!ja3.extensions.contains(&0x0a0a));
}

#[test]
fn test_ja3_padding_extension_filtering() {
    // Test that padding extension (21) is filtered
    let client_hello = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02f, 0xc030],
        vec![
            (0, vec![]),                   // server_name
            (10, build_groups(&[0x001d])), // supported_groups
            (11, vec![1, 0]),              // ec_point_formats
            (21, vec![0; 100]),            // padding (should be filtered)
            (13, vec![]),                  // signature_algorithms
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    // Padding extension (21) should be filtered
    assert!(!ja3.extensions.contains(&21));
}

#[test]
fn test_ja3_string_format() {
    // Test JA3 string format
    let client_hello = ClientHelloCapture::synthetic(
        771, // TLS 1.2
        vec![49195, 49199],
        vec![(0, vec![]), (10, build_groups(&[29, 23])), (11, vec![1, 0])],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    // Parse JA3 string parts
    let parts: Vec<&str> = ja3.ja3_string.split(',').collect();
    assert_eq!(parts.len(), 5); // SSLVersion,Ciphers,Extensions,Curves,PointFormats

    // SSLVersion
    assert_eq!(parts[0], "771");

    // Ciphers (dash-separated)
    assert!(parts[1].contains("49195"));
    assert!(parts[1].contains('-'));

    // Extensions
    assert!(parts[2].contains("0"));
    assert!(parts[2].contains("10"));
    assert!(parts[2].contains("11"));

    // Curves
    assert!(parts[3].contains("29"));
    assert!(parts[3].contains("23"));

    // Point formats
    assert_eq!(parts[4], "0");
}

#[test]
fn test_ja3_database_matching() {
    let db = Ja3Database::default();

    // Test Chrome signature
    let chrome_sig = db.match_fingerprint("773906b0efdefa24a7f2b8eb6985bf37");
    assert!(chrome_sig.is_some());
    let sig = chrome_sig.unwrap();
    assert_eq!(sig.name, "Chrome 120");
    assert_eq!(sig.category, "Browser");
    assert_eq!(sig.threat_level, "none");

    // Test malware signature
    let malware_sig = db.match_fingerprint("a0e9f5d64349fb13191bc781f81f42e1");
    assert!(malware_sig.is_some());
    let sig = malware_sig.unwrap();
    assert_eq!(sig.name, "Cobalt Strike");
    assert_eq!(sig.category, "Malware");
    assert_eq!(sig.threat_level, "high");

    // Test unknown signature
    let unknown = db.match_fingerprint("0000000000000000000000000000000");
    assert!(unknown.is_none());
}

#[test]
fn test_ja3_ssl_version_names() {
    let versions = vec![
        (0x0200, "SSL 2.0"),
        (0x0300, "SSL 3.0"),
        (0x0301, "TLS 1.0"),
        (0x0302, "TLS 1.1"),
        (0x0303, "TLS 1.2"),
        (0x0304, "TLS 1.3"),
    ];

    for (version_id, version_name) in versions {
        let client_hello = ClientHelloCapture::synthetic(version_id, vec![0xc02f], vec![]);
        let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);
        assert_eq!(ja3.ssl_version_name(), version_name);
    }
}

#[test]
fn test_ja3_curve_names() {
    let client_hello = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02f],
        vec![(10, build_groups(&[29, 23, 24, 25]))], // X25519, secp256r1, secp384r1, secp521r1
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);
    let curve_names = ja3.curve_names();

    assert!(curve_names.contains(&"X25519".to_string()));
    assert!(curve_names.contains(&"secp256r1".to_string()));
    assert!(curve_names.contains(&"secp384r1".to_string()));
    assert!(curve_names.contains(&"secp521r1".to_string()));
}

#[test]
fn test_ja3_empty_extensions() {
    // Test ClientHello with no extensions
    let client_hello = ClientHelloCapture::synthetic(0x0303, vec![0xc02f, 0xc030], vec![]);

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    assert!(ja3.extensions.is_empty());
    assert!(ja3.curves.is_empty());
    assert!(ja3.point_formats.is_empty());

    // JA3 string should still be valid
    let parts: Vec<&str> = ja3.ja3_string.split(',').collect();
    assert_eq!(parts.len(), 5);
}

#[test]
fn test_ja3_deterministic() {
    // Test that same input produces same hash
    let client_hello1 = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02f, 0xc030],
        vec![(0, vec![]), (10, build_groups(&[29, 23])), (11, vec![1, 0])],
    );

    let client_hello2 = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02f, 0xc030],
        vec![(0, vec![]), (10, build_groups(&[29, 23])), (11, vec![1, 0])],
    );

    let ja3_1 = Ja3Fingerprint::from_client_hello(&client_hello1);
    let ja3_2 = Ja3Fingerprint::from_client_hello(&client_hello2);

    assert_eq!(ja3_1.ja3_string, ja3_2.ja3_string);
    assert_eq!(ja3_1.ja3_hash, ja3_2.ja3_hash);
}

#[test]
fn test_ja3_different_order_different_hash() {
    // Different cipher order should produce different hash
    let client_hello1 = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02f, 0xc030, 0xc02b], // Order 1
        vec![(10, build_groups(&[29, 23]))],
    );

    let client_hello2 = ClientHelloCapture::synthetic(
        0x0303,
        vec![0xc02b, 0xc02f, 0xc030], // Order 2 (different)
        vec![(10, build_groups(&[29, 23]))],
    );

    let ja3_1 = Ja3Fingerprint::from_client_hello(&client_hello1);
    let ja3_2 = Ja3Fingerprint::from_client_hello(&client_hello2);

    assert_ne!(ja3_1.ja3_string, ja3_2.ja3_string);
    assert_ne!(ja3_1.ja3_hash, ja3_2.ja3_hash);
}

#[test]
fn test_ja3_database_custom_signatures() {
    let mut db = Ja3Database::new();

    // Add custom signature
    db.add_signature(
        "test_hash_123".to_string(),
        cipherrun::fingerprint::Ja3Signature {
            name: "Test Client".to_string(),
            category: "Test".to_string(),
            description: "Test signature".to_string(),
            threat_level: "none".to_string(),
        },
    );

    let sig = db.match_fingerprint("test_hash_123");
    assert!(sig.is_some());
    assert_eq!(sig.unwrap().name, "Test Client");
}

// Helper function to build supported_groups extension data
fn build_groups(groups: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();

    // List length
    data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());

    // Groups
    for &group in groups {
        data.extend_from_slice(&group.to_be_bytes());
    }

    data
}
