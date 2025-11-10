// JARM fingerprinting integration tests
//
// Tests JARM TLS server active fingerprinting functionality including:
// - Probe generation
// - Server response parsing
// - Hash calculation
// - Signature database matching
// - Live server fingerprinting

use cipherrun::fingerprint::{
    JarmFingerprinter, JarmDatabase, JarmSignature, get_probes,
};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn test_jarm_probe_generation() {
    let probes = get_probes("example.com", 443);

    // JARM uses exactly 10 probes
    assert_eq!(probes.len(), 10);

    // Each probe should generate a non-empty packet
    for probe in &probes {
        let packet = probe.build();
        assert!(!packet.is_empty());

        // All packets should start with handshake content type (0x16)
        assert_eq!(packet[0], 0x16);

        // Should have reasonable length (at least 100 bytes)
        assert!(packet.len() >= 100);
    }
}

#[test]
fn test_jarm_database_loading() {
    // Test builtin database
    let db = JarmDatabase::builtin();
    let sigs = db.all_signatures();

    // Should have multiple signatures
    assert!(sigs.len() > 0);

    // Should include known signatures
    let cloudflare = db.lookup("27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d");
    assert!(cloudflare.is_some());
    if let Some(sig) = cloudflare {
        assert_eq!(sig.name, "Cloudflare");
        assert_eq!(sig.server_type, "CDN");
    }

    // Zero hash should exist
    let zero = db.lookup("00000000000000000000000000000000000000000000000000000000000000");
    assert!(zero.is_some());
    if let Some(sig) = zero {
        assert_eq!(sig.name, "No Response");
    }
}

#[test]
fn test_jarm_database_add_signature() {
    let mut db = JarmDatabase::new();

    let sig = JarmSignature {
        hash: "test_hash_abc123".to_string(),
        name: "Test Server".to_string(),
        server_type: "web".to_string(),
        description: Some("Test description".to_string()),
        threat_level: None,
    };

    db.add_signature(sig.clone());

    let found = db.lookup("test_hash_abc123");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "Test Server");
}

#[test]
fn test_jarm_signature_serialization() {
    let sig = JarmSignature {
        hash: "abc123".to_string(),
        name: "Test".to_string(),
        server_type: "test".to_string(),
        description: Some("Description".to_string()),
        threat_level: Some("high".to_string()),
    };

    // Should serialize to JSON
    let json = serde_json::to_string(&sig).expect("Failed to serialize");
    assert!(json.contains("abc123"));
    assert!(json.contains("Test"));

    // Should deserialize from JSON
    let deserialized: JarmSignature = serde_json::from_str(&json)
        .expect("Failed to deserialize");
    assert_eq!(deserialized.hash, sig.hash);
    assert_eq!(deserialized.name, sig.name);
}

#[tokio::test]
async fn test_jarm_fingerprint_timeout() {
    // Test with non-existent server (should timeout quickly)
    let fingerprinter = JarmFingerprinter::new(Duration::from_millis(100));

    // Use a non-routable IP address
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);

    let result = fingerprinter.fingerprint(addr, "example.com").await;

    // Should complete (not hang) and likely return zero hash
    assert!(result.is_ok());
    if let Ok(fp) = result {
        // All probes likely failed due to timeout
        assert_eq!(fp.hash.len(), 62); // JARM hash is always 62 chars
    }
}

#[tokio::test]
#[ignore] // Ignored by default - requires internet connection
async fn test_jarm_fingerprint_google() {
    // Test against Google (stable, well-known server)
    let fingerprinter = JarmFingerprinter::new(Duration::from_secs(5));

    // Resolve google.com
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = "google.com:443"
        .to_socket_addrs()
        .expect("Failed to resolve google.com")
        .collect();

    assert!(!addrs.is_empty());

    let result = fingerprinter.fingerprint(addrs[0], "google.com").await;

    assert!(result.is_ok());
    let fp = result.unwrap();

    // Should have valid hash (62 characters)
    assert_eq!(fp.hash.len(), 62);

    // Hash should not be all zeros (Google is responsive)
    assert_ne!(fp.hash, "00000000000000000000000000000000000000000000000000000000000000");

    // Should have 10 raw responses
    assert_eq!(fp.raw_responses.len(), 10);

    println!("Google JARM: {}", fp.hash);
    if let Some(sig) = fp.signature {
        println!("Matched: {} ({})", sig.name, sig.server_type);
    }
}

#[tokio::test]
#[ignore] // Ignored by default - requires internet connection
async fn test_jarm_fingerprint_cloudflare() {
    // Test against Cloudflare (1.1.1.1)
    let fingerprinter = JarmFingerprinter::new(Duration::from_secs(5));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

    let result = fingerprinter.fingerprint(addr, "one.one.one.one").await;

    assert!(result.is_ok());
    let fp = result.unwrap();

    // Should have valid hash
    assert_eq!(fp.hash.len(), 62);

    // Cloudflare should be responsive
    assert_ne!(fp.hash, "00000000000000000000000000000000000000000000000000000000000000");

    println!("Cloudflare JARM: {}", fp.hash);
    if let Some(sig) = fp.signature {
        println!("Matched: {} ({})", sig.name, sig.server_type);
        // May or may not match exactly due to Cloudflare updates
    }
}

#[test]
fn test_jarm_threat_detection() {
    let db = JarmDatabase::builtin();

    // Check for known malware C2 signatures
    let signatures = db.all_signatures();

    let malware_sigs: Vec<_> = signatures
        .iter()
        .filter(|sig| sig.threat_level.is_some())
        .collect();

    // Should have several threat signatures
    assert!(malware_sigs.len() > 0);

    // Check specific malware signatures exist
    for sig in malware_sigs {
        assert!(sig.server_type.contains("Malware") || sig.server_type.contains("C2"));
        assert!(sig.threat_level.as_ref().unwrap() == "high"
            || sig.threat_level.as_ref().unwrap() == "critical");
    }
}

#[test]
fn test_jarm_cdn_detection() {
    let db = JarmDatabase::builtin();
    let signatures = db.all_signatures();

    let cdn_sigs: Vec<_> = signatures
        .iter()
        .filter(|sig| sig.server_type == "CDN")
        .collect();

    // Should have multiple CDN signatures
    assert!(cdn_sigs.len() >= 3);

    // Should include major CDNs
    let cdn_names: Vec<String> = cdn_sigs.iter().map(|s| s.name.clone()).collect();

    assert!(cdn_names.iter().any(|n| n.contains("Cloudflare")));
    assert!(cdn_names.iter().any(|n| n.contains("Akamai")));
}

#[test]
fn test_jarm_load_balancer_detection() {
    let db = JarmDatabase::builtin();
    let signatures = db.all_signatures();

    let lb_sigs: Vec<_> = signatures
        .iter()
        .filter(|sig| sig.server_type == "Load Balancer")
        .collect();

    // Should have load balancer signatures
    assert!(lb_sigs.len() > 0);
}

#[test]
fn test_jarm_waf_detection() {
    let db = JarmDatabase::builtin();
    let signatures = db.all_signatures();

    let waf_sigs: Vec<_> = signatures
        .iter()
        .filter(|sig| sig.server_type == "WAF")
        .collect();

    // Should have WAF signatures
    assert!(waf_sigs.len() > 0);
}

#[test]
fn test_jarm_hash_format() {
    // JARM hashes should always be exactly 62 characters
    let db = JarmDatabase::builtin();

    for sig in db.all_signatures() {
        assert_eq!(
            sig.hash.len(),
            62,
            "JARM hash for {} has invalid length: {}",
            sig.name,
            sig.hash.len()
        );

        // Should be valid hex characters
        assert!(
            sig.hash.chars().all(|c| c.is_ascii_hexdigit() || c.is_ascii_digit()),
            "JARM hash for {} contains invalid characters",
            sig.name
        );
    }
}

#[tokio::test]
async fn test_jarm_custom_database() {
    let mut custom_db = JarmDatabase::new();

    custom_db.add_signature(JarmSignature {
        hash: "custom_hash_123".to_string(),
        name: "Custom Server".to_string(),
        server_type: "custom".to_string(),
        description: Some("Test".to_string()),
        threat_level: None,
    });

    let fingerprinter = JarmFingerprinter::with_database(
        Duration::from_secs(5),
        custom_db.clone(),
    );

    // Database should contain our custom signature
    let found = custom_db.lookup("custom_hash_123");
    assert!(found.is_some());
}

#[test]
fn test_jarm_probe_packet_structure() {
    let probes = get_probes("test.example.com", 443);

    for (i, probe) in probes.iter().enumerate() {
        let packet = probe.build();

        // Content type should be Handshake (0x16)
        assert_eq!(packet[0], 0x16, "Probe {} has wrong content type", i);

        // Should have TLS version in bytes 1-2
        let version = u16::from_be_bytes([packet[1], packet[2]]);
        assert!(
            version >= 0x0300 && version <= 0x0304,
            "Probe {} has invalid TLS version: 0x{:04x}",
            i,
            version
        );

        // Should have length field in bytes 3-4
        let length = u16::from_be_bytes([packet[3], packet[4]]) as usize;
        assert_eq!(
            packet.len(),
            5 + length,
            "Probe {} length field doesn't match actual length",
            i
        );

        // Handshake type should be ClientHello (0x01)
        assert_eq!(packet[5], 0x01, "Probe {} is not a ClientHello", i);
    }
}

#[test]
fn test_jarm_signature_coverage() {
    let db = JarmDatabase::builtin();
    let signatures = db.all_signatures();

    // Should have reasonable coverage of different server types
    let server_types: std::collections::HashSet<String> = signatures
        .iter()
        .map(|s| s.server_type.clone())
        .collect();

    assert!(server_types.contains("CDN"));
    assert!(server_types.contains("Web Server"));
    assert!(server_types.contains("Load Balancer"));
    assert!(server_types.contains("Malware C2"));

    println!("JARM database statistics:");
    println!("  Total signatures: {}", signatures.len());
    println!("  Server types: {}", server_types.len());

    for server_type in &server_types {
        let count = signatures
            .iter()
            .filter(|s| &s.server_type == server_type)
            .count();
        println!("    {}: {}", server_type, count);
    }
}
