// JA3S TLS Server Fingerprinting Tests
//
// Tests for JA3S fingerprint generation, database matching,
// and CDN/load balancer detection

use cipherrun::fingerprint::{
    ServerHelloCapture, Ja3sFingerprint, Ja3sDatabase,
    CdnDetection, LoadBalancerInfo, ServerType
};
use std::collections::HashMap;

#[test]
fn test_ja3s_hash_cloudflare() {
    // Known Cloudflare JA3S: "771,49199,65281-0-11-35-23"
    // Expected hash: 098e26e2609212ac1bfac552fbe04127
    let ja3s_string = "771,49199,65281-0-11-35-23";
    let hash = format!("{:x}", md5::compute(ja3s_string.as_bytes()));
    assert_eq!(hash, "098e26e2609212ac1bfac552fbe04127");
}

#[test]
fn test_ja3s_build_string_with_extensions() {
    // Simulate ServerHello
    let server_hello = create_test_server_hello(771, 49199, vec![65281, 0, 11, 35, 23]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    assert_eq!(ja3s.ja3s_string, "771,49199,65281-0-11-35-23");
    assert_eq!(ja3s.ja3s_hash, "098e26e2609212ac1bfac552fbe04127");
    assert_eq!(ja3s.ssl_version, 771);
    assert_eq!(ja3s.cipher, 49199);
    assert_eq!(ja3s.extensions.len(), 5);
}

#[test]
fn test_ja3s_no_extensions() {
    let server_hello = create_test_server_hello(771, 47, vec![]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    assert_eq!(ja3s.ja3s_string, "771,47,");
    assert_eq!(ja3s.ssl_version, 771);
    assert_eq!(ja3s.cipher, 47);
    assert!(ja3s.extensions.is_empty());
}

#[test]
fn test_ja3s_version_names() {
    let test_cases = vec![
        (0x0200, "SSL 2.0"),
        (0x0300, "SSL 3.0"),
        (0x0301, "TLS 1.0"),
        (0x0302, "TLS 1.1"),
        (0x0303, "TLS 1.2"),
        (0x0304, "TLS 1.3"),
    ];

    for (version, expected_name) in test_cases {
        let server_hello = create_test_server_hello(version, 47, vec![]);
        let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);
        assert_eq!(ja3s.version_name(), expected_name);
    }
}

#[test]
fn test_ja3s_database_load() {
    let db_result = Ja3sDatabase::load_default();
    assert!(db_result.is_ok(), "Failed to load JA3S database");

    let db = db_result.unwrap();
    assert!(db.signature_count() >= 50, "Database should have at least 50 signatures");
}

#[test]
fn test_ja3s_database_match_cloudflare() {
    let db = Ja3sDatabase::load_default().expect("Failed to load database");

    let cloudflare_hash = "098e26e2609212ac1bfac552fbe04127";
    let match_result = db.match_fingerprint(cloudflare_hash);

    assert!(match_result.is_some(), "Should find Cloudflare signature");

    let signature = match_result.unwrap();
    assert_eq!(signature.name, "Cloudflare");
    assert_eq!(signature.server_type, ServerType::CDN);
    assert!(signature.common_ports.contains(&443));
}

#[test]
fn test_ja3s_database_match_unknown() {
    let db = Ja3sDatabase::load_default().expect("Failed to load database");

    let unknown_hash = "00000000000000000000000000000000";
    let match_result = db.match_fingerprint(unknown_hash);

    assert!(match_result.is_none(), "Should not match unknown hash");
}

#[test]
fn test_cdn_detection_cloudflare_by_headers() {
    let server_hello = create_test_server_hello(771, 49199, vec![65281, 0, 11, 35, 23]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let mut headers = HashMap::new();
    headers.insert("CF-RAY".to_string(), "12345678-SJC".to_string());
    headers.insert("Server".to_string(), "cloudflare".to_string());
    headers.insert("CF-Cache-Status".to_string(), "HIT".to_string());

    let detection = CdnDetection::from_ja3s_and_headers(&ja3s, None, &headers);

    assert!(detection.is_cdn, "Should detect CDN");
    assert_eq!(detection.cdn_provider, Some("Cloudflare".to_string()));
    assert!(detection.confidence > 0.5, "Confidence should be > 50%");
    assert!(!detection.indicators.is_empty(), "Should have indicators");
}

#[test]
fn test_cdn_detection_akamai_by_headers() {
    let server_hello = create_test_server_hello(771, 49199, vec![]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let mut headers = HashMap::new();
    headers.insert("X-Akamai-Transformed".to_string(), "9 - 0 pmb=mRUM,3".to_string());
    headers.insert("X-Akamai-Session-Info".to_string(), "name=value".to_string());

    let detection = CdnDetection::from_ja3s_and_headers(&ja3s, None, &headers);

    assert!(detection.is_cdn, "Should detect CDN");
    assert_eq!(detection.cdn_provider, Some("Akamai".to_string()));
    assert!(detection.confidence > 0.0);
}

#[test]
fn test_cdn_detection_no_cdn() {
    let server_hello = create_test_server_hello(771, 47, vec![]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let headers = HashMap::new(); // No CDN headers

    let detection = CdnDetection::from_ja3s_and_headers(&ja3s, None, &headers);

    assert!(!detection.is_cdn, "Should not detect CDN");
    assert_eq!(detection.cdn_provider, None);
    assert_eq!(detection.confidence, 0.0);
}

#[test]
fn test_load_balancer_detection_aws_elb() {
    let mut headers = HashMap::new();
    headers.insert("X-Amzn-Trace-Id".to_string(), "Root=1-67891234-56789abcdef".to_string());
    headers.insert("X-Amzn-RequestId".to_string(), "abc123".to_string());

    let lb_info = LoadBalancerInfo::from_ja3s_and_headers(None, &headers);

    assert!(lb_info.detected, "Should detect load balancer");
    assert_eq!(lb_info.lb_type, Some("AWS ELB/ALB".to_string()));
    assert!(!lb_info.indicators.is_empty());
}

#[test]
fn test_load_balancer_detection_haproxy() {
    let mut headers = HashMap::new();
    headers.insert("X-HAProxy-Server-State".to_string(), "UP".to_string());

    let lb_info = LoadBalancerInfo::from_ja3s_and_headers(None, &headers);

    assert!(lb_info.detected, "Should detect load balancer");
    assert_eq!(lb_info.lb_type, Some("HAProxy".to_string()));
}

#[test]
fn test_load_balancer_sticky_sessions() {
    let mut headers = HashMap::new();
    headers.insert("Set-Cookie".to_string(), "route=server1; Path=/".to_string());

    let lb_info = LoadBalancerInfo::from_ja3s_and_headers(None, &headers);

    assert!(lb_info.sticky_sessions, "Should detect sticky sessions");
}

#[test]
fn test_extension_names() {
    let server_hello = create_test_server_hello(
        771,
        49199,
        vec![0, 5, 10, 11, 13, 16, 23, 35, 65281],
    );
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let ext_names = ja3s.extension_names();

    assert!(ext_names.contains(&"server_name".to_string()));
    assert!(ext_names.contains(&"status_request".to_string()));
    assert!(ext_names.contains(&"supported_groups".to_string()));
    assert!(ext_names.contains(&"ec_point_formats".to_string()));
    assert!(ext_names.contains(&"signature_algorithms".to_string()));
    assert!(ext_names.contains(&"renegotiation_info".to_string()));
}

#[test]
fn test_ja3s_roundtrip() {
    // Create a ServerHello, generate JA3S, serialize and verify
    let server_hello = create_test_server_hello(771, 49199, vec![65281, 0, 11]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    // Serialize to JSON
    let json = serde_json::to_string(&ja3s).expect("Failed to serialize");
    assert!(json.contains(&ja3s.ja3s_hash));

    // Deserialize
    let ja3s_deserialized: Ja3sFingerprint =
        serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(ja3s.ja3s_hash, ja3s_deserialized.ja3s_hash);
    assert_eq!(ja3s.ja3s_string, ja3s_deserialized.ja3s_string);
    assert_eq!(ja3s.ssl_version, ja3s_deserialized.ssl_version);
    assert_eq!(ja3s.cipher, ja3s_deserialized.cipher);
}

#[test]
fn test_multiple_cdn_indicators() {
    let server_hello = create_test_server_hello(771, 49199, vec![]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let mut headers = HashMap::new();
    headers.insert("CF-RAY".to_string(), "12345".to_string());
    headers.insert("CF-Cache-Status".to_string(), "HIT".to_string());
    headers.insert("Server".to_string(), "cloudflare-nginx".to_string());

    let detection = CdnDetection::from_ja3s_and_headers(&ja3s, None, &headers);

    assert!(detection.is_cdn);
    assert_eq!(detection.cdn_provider, Some("Cloudflare".to_string()));
    // Should have high confidence with multiple indicators
    assert!(detection.confidence > 0.7, "Multiple indicators should increase confidence");
    assert!(detection.indicators.len() >= 2, "Should have multiple indicators");
}

/// Helper function to create test ServerHello
fn create_test_server_hello(version: u16, cipher: u16, extension_ids: Vec<u16>) -> ServerHelloCapture {
    use cipherrun::fingerprint::server_hello::Extension;

    let extensions = extension_ids.into_iter()
        .map(|id| Extension {
            extension_type: id,
            data: vec![],
        })
        .collect();

    ServerHelloCapture {
        version,
        random: [0u8; 32],
        session_id: vec![],
        cipher_suite: cipher,
        compression_method: 0,
        extensions,
    }
}

#[test]
fn test_server_type_display() {
    assert_eq!(format!("{}", ServerType::CDN), "CDN");
    assert_eq!(format!("{}", ServerType::LoadBalancer), "Load Balancer");
    assert_eq!(format!("{}", ServerType::WebServer), "Web Server");
    assert_eq!(format!("{}", ServerType::Firewall), "Firewall");
}

#[test]
fn test_combined_ja3s_and_signature_cdn_detection() {
    let db = Ja3sDatabase::load_default().expect("Failed to load database");

    // Use a known Cloudflare hash
    let cloudflare_hash = "098e26e2609212ac1bfac552fbe04127";
    let signature = db.match_fingerprint(cloudflare_hash);

    let server_hello = create_test_server_hello(771, 49199, vec![65281, 0, 11, 35, 23]);
    let ja3s = Ja3sFingerprint::from_server_hello(&server_hello);

    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "nginx".to_string()); // Generic header

    let detection = CdnDetection::from_ja3s_and_headers(&ja3s, signature, &headers);

    // Should detect CDN from JA3S signature match
    assert!(detection.is_cdn, "Should detect CDN from signature match");
    assert!(detection.confidence >= 0.7, "Signature match should give high confidence");
}
