// JA3 Fingerprinting Demo
// Demonstrates JA3 TLS client fingerprinting capabilities

use cipherrun::fingerprint::{ClientHelloCapture, Ja3Database, Ja3Fingerprint};

fn main() {
    println!("=== JA3 TLS Client Fingerprinting Demo ===\n");

    // Demo 1: Chrome-like fingerprint
    demo_chrome_fingerprint();

    println!("\n{}", "=".repeat(60));

    // Demo 2: Firefox-like fingerprint
    demo_firefox_fingerprint();

    println!("\n{}", "=".repeat(60));

    // Demo 3: GREASE filtering
    demo_grease_filtering();

    println!("\n{}", "=".repeat(60));

    // Demo 4: Database matching
    demo_database_matching();
}

fn demo_chrome_fingerprint() {
    println!("Demo 1: Chrome-like TLS Fingerprint\n");

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
            (13, vec![]),                          // signature_algorithms
            (43, vec![2, 0x03, 0x04]),             // supported_versions
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    println!("  JA3 Hash:       {}", ja3.ja3_hash);
    println!("  SSL Version:    {} ({})", ja3.ssl_version_name(), ja3.ssl_version);
    println!("  Cipher Suites:  {} suites", ja3.ciphers.len());
    println!("  Extensions:     {} extensions", ja3.extensions.len());
    println!("  Curves:         {} curves", ja3.curves.len());
    println!("\n  JA3 String:");
    println!("  {}", ja3.ja3_string);
}

fn demo_firefox_fingerprint() {
    println!("Demo 2: Firefox-like TLS Fingerprint\n");

    let client_hello = ClientHelloCapture::synthetic(
        0x0303, // TLS 1.2
        vec![
            0x1301, 0x1303, 0x1302, // Different cipher order
            0xc02b, 0xc02f, 0xc02c, 0xc030,
        ],
        vec![
            (0, vec![]),
            (10, build_groups(&[0x001d, 0x0018])), // Different curve preference
            (11, vec![1, 0]),
            (13, vec![]),
            (43, vec![2, 0x03, 0x04]),
        ],
    );

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    println!("  JA3 Hash:       {}", ja3.ja3_hash);
    println!("  SSL Version:    {} ({})", ja3.ssl_version_name(), ja3.ssl_version);
    println!("  Curve Names:    {}", ja3.curve_names().join(", "));
    println!("\n  JA3 String:");
    println!("  {}", ja3.ja3_string);
    println!("\n  Note: Different cipher/curve order produces different hash!");
}

fn demo_grease_filtering() {
    println!("Demo 3: GREASE Value Filtering\n");

    println!("  GREASE values are random placeholders used by some clients");
    println!("  to prevent TLS ossification. They must be filtered for JA3.\n");

    let client_hello = ClientHelloCapture::synthetic(
        0x0303,
        vec![
            0x0a0a, // GREASE
            0xc02f, // Real cipher
            0x1a1a, // GREASE
            0xc030, // Real cipher
        ],
        vec![
            (0x0a0a, vec![]), // GREASE extension
            (0, vec![]),
            (10, build_groups(&[
                0x0a0a, // GREASE curve
                0x001d, // X25519
                0x1a1a, // GREASE curve
                0x0017, // secp256r1
            ])),
            (11, vec![1, 0]),
        ],
    );

    println!("  Input:");
    println!("    Ciphers:    0x0a0a (GREASE), 0xc02f, 0x1a1a (GREASE), 0xc030");
    println!("    Extensions: 0x0a0a (GREASE), 0, 10, 11");
    println!("    Curves:     0x0a0a (GREASE), 0x001d, 0x1a1a (GREASE), 0x0017");

    let ja3 = Ja3Fingerprint::from_client_hello(&client_hello);

    println!("\n  After GREASE filtering:");
    println!("    Ciphers:    {} values -> {:?}", ja3.ciphers.len(), ja3.ciphers);
    println!("    Extensions: {} values -> {:?}", ja3.extensions.len(), ja3.extensions);
    println!("    Curves:     {} values -> {:?}", ja3.curves.len(), ja3.curves);

    println!("\n  JA3 Hash: {}", ja3.ja3_hash);
}

fn demo_database_matching() {
    println!("Demo 4: Signature Database Matching\n");

    let db = Ja3Database::default();

    println!("  Built-in database contains {} signatures\n", db.signatures().len());

    // Test known signatures
    let test_hashes = vec![
        ("773906b0efdefa24a7f2b8eb6985bf37", "Browser"),
        ("a0e9f5d64349fb13191bc781f81f42e1", "Malware"),
        ("6734f37431670b3ab4292b8f60f29984", "Tool"),
        ("unknown_hash_12345", "Unknown"),
    ];

    for (hash, expected_category) in test_hashes {
        print!("  Hash: {}... ", &hash[..16]);

        if let Some(sig) = db.match_fingerprint(hash) {
            println!("✓ Matched!");
            println!("    Name:         {}", sig.name);
            println!("    Category:     {}", sig.category);
            println!("    Threat Level: {}", sig.threat_level);
        } else {
            println!("✗ No match ({})", expected_category);
        }
        println!();
    }
}

// Helper function to build supported_groups extension data
fn build_groups(groups: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for &group in groups {
        data.extend_from_slice(&group.to_be_bytes());
    }
    data
}
