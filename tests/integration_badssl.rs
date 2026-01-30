// Integration tests against badssl.com
// badssl.com provides public test servers with known TLS issues
// Run with: cargo test --test integration_badssl -- --ignored --test-threads=1

use cipherrun::certificates::parser::CertificateParser;
use cipherrun::certificates::validator::CertificateValidator;
use cipherrun::ciphers::tester::CipherTester;
use cipherrun::protocols::Protocol;
use cipherrun::protocols::tester::ProtocolTester;
use cipherrun::utils::network::Target;
use cipherrun::vulnerabilities::heartbleed::HeartbleedTester;

/// Test against server with expired certificate
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_expired_certificate_detection() {
    let target = Target::parse("expired.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let parser = CertificateParser::new(target.clone());
    let chain_result = parser.get_certificate_chain().await;

    // Should either get an error or detect expired certificate
    match chain_result {
        Ok(chain) => {
            let validator = CertificateValidator::new(target.hostname.clone());
            let validation = validator.validate_chain(&chain).expect("Validation failed");

            // Should have issues due to expiration
            println!("Validation result: {:?}", validation);
            assert!(
                !validation.issues.is_empty(),
                "Should have validation issues"
            );
        }
        Err(e) => {
            // Connection might fail due to expired cert - that's also valid
            println!("Expected error for expired cert: {}", e);
        }
    }
}

/// Test against server with self-signed certificate
#[tokio::test]
#[ignore]
async fn test_self_signed_certificate_detection() {
    let target = Target::parse("self-signed.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let parser = CertificateParser::new(target.clone());
    let chain_result = parser.get_certificate_chain().await;

    match chain_result {
        Ok(chain) => {
            let validator = CertificateValidator::new(target.hostname.clone());
            let validation = validator.validate_chain(&chain).expect("Validation failed");

            // Should detect self-signed or untrusted CA
            println!("Self-signed validation: {:?}", validation);
            assert!(!validation.valid, "Should detect self-signed as invalid");
        }
        Err(e) => {
            // Connection might fail due to self-signed - acceptable
            println!("Expected error for self-signed: {}", e);
        }
    }
}

/// Test against server with untrusted root
#[tokio::test]
#[ignore]
async fn test_untrusted_root_detection() {
    let target = Target::parse("untrusted-root.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let parser = CertificateParser::new(target.clone());
    let chain_result = parser.get_certificate_chain().await;

    match chain_result {
        Ok(chain) => {
            let validator = CertificateValidator::new(target.hostname.clone());
            let validation = validator.validate_chain(&chain).expect("Validation failed");

            // Should detect untrusted root
            assert!(!validation.valid, "Should detect untrusted root");
            println!("Untrusted root detected: {:?}", validation);
        }
        Err(e) => {
            // Connection might fail - acceptable
            println!("Expected error for untrusted root: {}", e);
        }
    }
}

/// Test TLS 1.0 server (deprecated protocol)
#[tokio::test]
#[ignore]
async fn test_tls_1_0_detection() {
    let target = Target::parse("tls-v1-0.badssl.com:1010")
        .await
        .expect("Failed to parse target");

    let tester = ProtocolTester::new(target);
    let result = tester.test_all_protocols().await;

    match result {
        Ok(results) => {
            // Should detect TLS 1.0 support
            let has_tls10 = results
                .iter()
                .any(|r| r.protocol == Protocol::TLS10 && r.supported);

            // Should NOT support TLS 1.3
            let has_tls13 = results
                .iter()
                .any(|r| r.protocol == Protocol::TLS13 && r.supported);

            println!("TLS 1.0 server test results:");
            for r in &results {
                if r.supported {
                    println!("  - {} supported", r.protocol);
                }
            }

            assert!(has_tls10, "Should support TLS 1.0");
            assert!(!has_tls13, "Should NOT support TLS 1.3");
        }
        Err(e) => {
            println!("TLS 1.0 test error (may be expected): {}", e);
        }
    }
}

/// Test TLS 1.2 server (should work)
#[tokio::test]
#[ignore]
async fn test_tls_1_2_support() {
    let target = Target::parse("tls-v1-2.badssl.com:1012")
        .await
        .expect("Failed to parse target");

    let tester = ProtocolTester::new(target);
    let result = tester.test_all_protocols().await;

    match result {
        Ok(results) => {
            // Should support TLS 1.2
            let has_tls12 = results
                .iter()
                .any(|r| r.protocol == Protocol::TLS12 && r.supported);

            assert!(has_tls12, "Should support TLS 1.2");
            println!("✓ TLS 1.2 detected successfully");
        }
        Err(e) => {
            panic!("TLS 1.2 test should succeed: {}", e);
        }
    }
}

/// Test RC4 cipher detection
#[tokio::test]
#[ignore]
async fn test_rc4_cipher_detection() {
    let target = Target::parse("rc4.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = CipherTester::new(target);

    // Test all protocols to see which support RC4
    let result = tester.test_all_protocols().await;

    match result {
        Ok(cipher_results) => {
            let mut has_rc4 = false;

            for (protocol, summary) in &cipher_results {
                let rc4_ciphers: Vec<_> = summary
                    .supported_ciphers
                    .iter()
                    .filter(|c| c.encryption.contains("RC4"))
                    .collect();

                if !rc4_ciphers.is_empty() {
                    has_rc4 = true;
                    println!("{}: {} RC4 ciphers found", protocol, rc4_ciphers.len());
                }
            }

            assert!(has_rc4, "Should detect RC4 cipher support");
        }
        Err(e) => {
            println!("RC4 test error: {}", e);
        }
    }
}

/// Test 3DES cipher (deprecated)
#[tokio::test]
#[ignore]
async fn test_3des_cipher_detection() {
    let target = Target::parse("3des.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = CipherTester::new(target);
    let result = tester.test_all_protocols().await;

    match result {
        Ok(cipher_results) => {
            let mut has_3des = false;

            for (protocol, summary) in &cipher_results {
                let des_ciphers: Vec<_> = summary
                    .supported_ciphers
                    .iter()
                    .filter(|c| c.encryption.contains("3DES") || c.encryption.contains("DES"))
                    .collect();

                if !des_ciphers.is_empty() {
                    has_3des = true;
                    println!("{}: {} 3DES ciphers found", protocol, des_ciphers.len());
                }
            }

            assert!(has_3des, "Should detect 3DES cipher support");
        }
        Err(e) => {
            println!("3DES test error: {}", e);
        }
    }
}

/// Test against server with valid certificate (should pass)
#[tokio::test]
#[ignore]
async fn test_valid_certificate() {
    let target = Target::parse("badssl.com:443")
        .await
        .expect("Failed to parse target");

    let parser = CertificateParser::new(target.clone());
    let chain = parser
        .get_certificate_chain()
        .await
        .expect("Failed to get certificate chain");

    let validator = CertificateValidator::new(target.hostname.clone());
    let validation = validator.validate_chain(&chain).expect("Validation failed");

    println!("Validation result: {:?}", validation);
    assert!(
        validation.valid || validation.issues.len() <= 1,
        "badssl.com should have a mostly valid certificate"
    );
}

/// Test Heartbleed vulnerability (should NOT be vulnerable)
#[tokio::test]
#[ignore]
async fn test_heartbleed_not_vulnerable() {
    let target = Target::parse("badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = HeartbleedTester::new(&target);
    let result = tester.test().await;

    match result {
        Ok(is_vulnerable) => {
            assert!(
                !is_vulnerable,
                "badssl.com should NOT be vulnerable to Heartbleed"
            );
            println!("✓ Heartbleed test passed - not vulnerable");
        }
        Err(e) => {
            println!("Heartbleed test error: {}", e);
        }
    }
}

/// Test DH parameters (small key size)
#[tokio::test]
#[ignore]
async fn test_dh_small_params() {
    let target = Target::parse("dh480.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = CipherTester::new(target);
    let result = tester.test_all_protocols().await;

    // Should be able to connect but detect weak DH params
    match result {
        Ok(cipher_results) => {
            println!("DH480 connection successful");
            println!("Cipher results: {} protocols tested", cipher_results.len());
        }
        Err(e) => {
            println!("DH480 connection failed (may be expected): {}", e);
        }
    }
}

/// Test DH2048 (acceptable)
#[tokio::test]
#[ignore]
async fn test_dh_2048_params() {
    let target = Target::parse("dh2048.badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = CipherTester::new(target);
    let result = tester.test_all_protocols().await;

    // Should connect successfully with 2048-bit DH
    assert!(result.is_ok(), "DH2048 should work correctly");

    if let Ok(cipher_results) = result {
        println!("✓ DH2048 connection successful");
        println!("  Protocols tested: {}", cipher_results.len());
    }
}

/// Test protocol enumeration against main badssl.com
#[tokio::test]
#[ignore]
async fn test_protocol_enumeration_badssl() {
    let target = Target::parse("badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = ProtocolTester::new(target);
    let results = tester
        .test_all_protocols()
        .await
        .expect("Protocol testing should succeed");

    println!("Protocol enumeration results:");
    for result in &results {
        if result.supported {
            println!("  ✓ {} - {} ciphers", result.protocol, result.ciphers_count);
        } else {
            println!("  ✗ {} - not supported", result.protocol);
        }
    }

    // Should have at least one modern protocol
    let has_modern = results
        .iter()
        .any(|r| (r.protocol == Protocol::TLS12 || r.protocol == Protocol::TLS13) && r.supported);

    assert!(has_modern, "Should support at least TLS 1.2 or 1.3");
}

/// Test cipher enumeration against badssl.com
#[tokio::test]
#[ignore]
async fn test_cipher_enumeration_badssl() {
    let target = Target::parse("badssl.com:443")
        .await
        .expect("Failed to parse target");

    let tester = CipherTester::new(target);
    let results = tester
        .test_all_protocols()
        .await
        .expect("Cipher testing should succeed");

    println!("Cipher enumeration results:");
    for (protocol, summary) in &results {
        if summary.counts.total > 0 {
            println!("  {} - {} ciphers", protocol, summary.counts.total);
            println!("    High strength: {}", summary.counts.high_strength);
            println!("    Forward secrecy: {}", summary.counts.forward_secrecy);
        }
    }

    // Should find cipher suites
    let total_ciphers: usize = results.values().map(|s| s.counts.total).sum();
    assert!(total_ciphers > 0, "Should find cipher suites");
}

/// Test multiple badssl subdomains sequentially
#[tokio::test]
#[ignore]
async fn test_multiple_badssl_targets() {
    let targets = vec![
        "badssl.com:443",
        "self-signed.badssl.com:443",
        "expired.badssl.com:443",
    ];

    let mut results = Vec::new();

    for target_str in targets {
        match Target::parse(target_str).await {
            Ok(target) => {
                let tester = ProtocolTester::new(target.clone());
                let result = tester.test_all_protocols().await;
                results.push((target_str, result.is_ok()));
                println!(
                    "  {} - {}",
                    target_str,
                    if result.is_ok() { "OK" } else { "FAIL" }
                );
            }
            Err(e) => {
                println!("  {} - DNS error: {}", target_str, e);
                results.push((target_str, false));
            }
        }
    }

    // At least the main badssl.com should work
    assert!(
        results.iter().any(|(_, ok)| *ok),
        "At least one target should succeed"
    );
}
