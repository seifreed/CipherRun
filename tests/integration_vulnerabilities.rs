// Integration tests for vulnerability detection
// Tests all vulnerability checks against real servers
// Run with: cargo test --test integration_vulnerabilities -- --ignored --test-threads=1

use cipherrun::utils::network::Target;
use cipherrun::vulnerabilities::heartbleed::HeartbleedTester;
use cipherrun::vulnerabilities::tester::VulnerabilityScanner;
use std::time::Instant;

/// Helper to create target
async fn create_target(host: &str, port: u16) -> Target {
    let target_str = format!("{}:{}", host, port);
    Target::parse(&target_str)
        .await
        .expect("Failed to parse target")
}

/// Test full vulnerability scan against secure modern server
#[tokio::test]
#[ignore]
async fn test_full_vulnerability_scan_secure_server() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let start = Instant::now();
    let results = scanner.test_all().await;
    let elapsed = start.elapsed();

    assert!(results.is_ok(), "Vulnerability scan should complete");
    println!("Vulnerability scan completed in {:?}", elapsed);

    if let Ok(vuln_results) = results {
        let summary = VulnerabilityScanner::summarize_results(&vuln_results);
        println!("{}", summary);

        // Google should have no high/critical vulnerabilities
        assert_eq!(
            summary.critical, 0,
            "Google should have no critical vulnerabilities"
        );
        assert_eq!(
            summary.high, 0,
            "Google should have no high vulnerabilities"
        );

        // Print individual results
        for result in &vuln_results {
            println!(
                "  {:?}: {} - {}",
                result.vuln_type,
                if result.vulnerable {
                    "VULNERABLE"
                } else {
                    "OK"
                },
                result.details
            );
        }
    }
}

/// Test DROWN vulnerability detection (SSLv2)
#[tokio::test]
#[ignore]
async fn test_drown_vulnerability_async() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_drown().await;

    assert!(result.is_ok(), "DROWN test should complete");

    if let Ok(vuln_result) = result {
        println!("DROWN test result: {}", vuln_result.details);
        // Modern servers should not be vulnerable to DROWN
        assert!(
            !vuln_result.vulnerable,
            "Modern server should not support SSLv2/DROWN"
        );
    }
}

/// Test RC4 cipher vulnerability
#[tokio::test]
#[ignore]
async fn test_rc4_vulnerability_async() {
    let target = create_target("www.cloudflare.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_rc4().await;

    assert!(result.is_ok(), "RC4 test should complete");

    if let Ok(vuln_result) = result {
        println!("RC4 test result: {}", vuln_result.details);
        // Modern servers should not support RC4
        assert!(
            !vuln_result.vulnerable,
            "Modern server should not support RC4 ciphers"
        );
    }
}

/// Test 3DES/SWEET32 vulnerability
#[tokio::test]
#[ignore]
async fn test_sweet32_vulnerability_async() {
    let target = create_target("www.github.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_3des().await;

    assert!(result.is_ok(), "3DES/SWEET32 test should complete");

    if let Ok(vuln_result) = result {
        println!("SWEET32 test result: {}", vuln_result.details);
        // Modern servers should not support 3DES
        assert!(
            !vuln_result.vulnerable,
            "Modern server should not support 3DES ciphers"
        );
    }
}

/// Test NULL cipher vulnerability
#[tokio::test]
#[ignore]
async fn test_null_cipher_vulnerability_async() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_null_ciphers().await;

    assert!(result.is_ok(), "NULL cipher test should complete");

    if let Ok(vuln_result) = result {
        println!("NULL cipher test result: {}", vuln_result.details);
        // No server should support NULL ciphers
        assert!(
            !vuln_result.vulnerable,
            "Server should NEVER support NULL ciphers"
        );
    }
}

/// Test EXPORT cipher vulnerability (FREAK/LOGJAM)
#[tokio::test]
#[ignore]
async fn test_export_cipher_vulnerability_async() {
    let target = create_target("www.cloudflare.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_export_ciphers().await;

    assert!(result.is_ok(), "EXPORT cipher test should complete");

    if let Ok(vuln_result) = result {
        println!("EXPORT cipher test result: {}", vuln_result.details);
        // Modern servers should not support EXPORT ciphers
        assert!(
            !vuln_result.vulnerable,
            "Modern server should not support EXPORT ciphers (FREAK/LOGJAM)"
        );
    }
}

/// Test POODLE vulnerability (SSLv3)
#[tokio::test]
#[ignore]
async fn test_poodle_vulnerability_async() {
    let target = create_target("www.github.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_poodle_ssl().await;

    assert!(result.is_ok(), "POODLE test should complete");

    if let Ok(vuln_result) = result {
        println!("POODLE test result: {}", vuln_result.details);
        // Modern servers should not support SSLv3
        assert!(
            !vuln_result.vulnerable,
            "Modern server should not support SSLv3/POODLE"
        );
    }
}

/// Test BEAST vulnerability (TLS 1.0 with CBC)
#[tokio::test]
#[ignore]
async fn test_beast_vulnerability_async() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_beast().await;

    assert!(result.is_ok(), "BEAST test should complete");

    if let Ok(vuln_result) = result {
        println!("BEAST test result: {}", vuln_result.details);
        // Modern servers should not be vulnerable to BEAST
        // (either no TLS 1.0 or no CBC ciphers with TLS 1.0)
        println!("BEAST vulnerable: {}", vuln_result.vulnerable);
    }
}

/// Test Heartbleed vulnerability
#[tokio::test]
#[ignore]
async fn test_heartbleed_vulnerability_async() {
    let target = create_target("www.google.com", 443).await;
    let tester = HeartbleedTester::new(target);

    let result = tester.test().await;

    match result {
        Ok(is_vulnerable) => {
            println!("Heartbleed test result: vulnerable={}", is_vulnerable);
            // Modern servers should not be vulnerable to Heartbleed
            assert!(
                !is_vulnerable,
                "Modern server should not be vulnerable to Heartbleed"
            );
        }
        Err(e) => {
            println!("Heartbleed test error (may be expected): {}", e);
        }
    }
}

/// Test vulnerability scan against multiple servers in parallel
#[tokio::test]
#[ignore]
async fn test_parallel_vulnerability_scans() {
    let target1 = create_target("www.google.com", 443).await;
    let target2 = create_target("www.github.com", 443).await;
    let target3 = create_target("www.cloudflare.com", 443).await;

    let targets = vec![target1, target2, target3];

    let mut handles = Vec::new();

    for target in targets {
        let handle = tokio::spawn(async move {
            let scanner = VulnerabilityScanner::new(target.clone());
            let start = Instant::now();
            let result = scanner.test_all().await;
            let elapsed = start.elapsed();
            (target.hostname.clone(), result, elapsed)
        });
        handles.push(handle);
    }

    // Wait for all scans to complete
    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(scan_result) => results.push(scan_result),
            Err(e) => println!("Task join error: {}", e),
        }
    }

    // All scans should complete
    assert_eq!(results.len(), 3, "All 3 scans should complete");

    for (hostname, result, elapsed) in results {
        match result {
            Ok(vuln_results) => {
                let summary = VulnerabilityScanner::summarize_results(&vuln_results);
                println!("✓ {} completed in {:?}", hostname, elapsed);
                println!("  {}", summary);
            }
            Err(e) => {
                println!("✗ {} failed: {}", hostname, e);
            }
        }
    }
}

/// Test vulnerability scan performance (sequential)
#[tokio::test]
#[ignore]
async fn test_vulnerability_scan_performance_sequential() {
    let target = create_target("www.google.com", 443).await;

    let mut times = Vec::new();

    // Run 5 sequential scans
    for i in 0..5 {
        let scanner = VulnerabilityScanner::new(target.clone());
        let start = Instant::now();
        let result = scanner.test_all().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "Scan {} should complete", i + 1);
        times.push(elapsed);
        println!("Scan {} completed in {:?}", i + 1, elapsed);
    }

    // Calculate average time
    let total: std::time::Duration = times.iter().sum();
    let avg = total / 5;

    println!("Average scan time: {:?}", avg);
    println!(
        "Min: {:?}, Max: {:?}",
        times.iter().min().unwrap(),
        times.iter().max().unwrap()
    );

    // Scans should be reasonably fast (< 30 seconds on average)
    assert!(
        avg.as_secs() < 30,
        "Average scan time should be under 30 seconds"
    );
}

/// Test all vulnerabilities against known vulnerable server (badssl.com)
#[tokio::test]
#[ignore]
async fn test_vulnerabilities_against_badssl() {
    let target = create_target("badssl.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_all().await;

    assert!(result.is_ok(), "Vulnerability scan should complete");

    if let Ok(vuln_results) = result {
        let summary = VulnerabilityScanner::summarize_results(&vuln_results);
        println!("badssl.com vulnerability scan summary:");
        println!("{}", summary);

        // badssl.com should be secure (it's just a test site, not vulnerable)
        println!("Total vulnerabilities found: {}", summary.total_vulnerable);

        for result in &vuln_results {
            if result.vulnerable {
                println!("  ⚠️  {:?}: {}", result.vuln_type, result.details);
            }
        }
    }
}

/// Test renegotiation vulnerability detection
#[tokio::test]
#[ignore]
async fn test_renegotiation_vulnerability_async() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_renegotiation().await;

    assert!(result.is_ok(), "Renegotiation test should complete");

    if let Ok(vuln_result) = result {
        println!("Renegotiation test result: {}", vuln_result.details);
        // Note: This test is not fully implemented yet
        println!("Vulnerable: {}", vuln_result.vulnerable);
    }
}

/// Test TLS fallback SCSV support
#[tokio::test]
#[ignore]
async fn test_tls_fallback_scsv_async() {
    let target = create_target("www.cloudflare.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let result = scanner.test_tls_fallback().await;

    assert!(result.is_ok(), "TLS Fallback test should complete");

    if let Ok(vuln_result) = result {
        println!("TLS Fallback SCSV test result: {}", vuln_result.details);
        // Note: This test is not fully implemented yet
        println!("Vulnerable: {}", vuln_result.vulnerable);
    }
}

/// Test vulnerability detection timeout handling
#[tokio::test]
#[ignore]
async fn test_vulnerability_scan_timeout() {
    // Use non-routable IP to force timeout
    let target = Target::parse("10.255.255.1:443")
        .await
        .expect("Failed to create target");

    let scanner = VulnerabilityScanner::new(target);

    let start = Instant::now();
    let result = scanner.test_drown().await;
    let elapsed = start.elapsed();

    // Should fail or timeout quickly
    match result {
        Ok(_) => {
            println!("Test completed (unexpectedly) in {:?}", elapsed);
        }
        Err(e) => {
            println!("Expected timeout/error in {:?}: {}", elapsed, e);
        }
    }

    // Should timeout within reasonable time (< 30s)
    assert!(
        elapsed.as_secs() < 30,
        "Timeout should occur within 30 seconds"
    );
}

/// Test vulnerability scan against different ports
#[tokio::test]
#[ignore]
async fn test_vulnerability_scan_different_ports() {
    let ports = vec![443, 8443];

    for port in ports {
        let target_str = format!("badssl.com:{}", port);
        let target = match Target::parse(&target_str).await {
            Ok(t) => t,
            Err(e) => {
                println!("Failed to resolve {}: {}", target_str, e);
                continue;
            }
        };

        let scanner = VulnerabilityScanner::new(target);
        let result = scanner.test_all().await;

        match result {
            Ok(vuln_results) => {
                let summary = VulnerabilityScanner::summarize_results(&vuln_results);
                println!("Port {} results:", port);
                println!("  {}", summary);
            }
            Err(e) => {
                println!("Port {} error: {}", port, e);
            }
        }
    }
}

/// Test vulnerability summary formatting
#[tokio::test]
#[ignore]
async fn test_vulnerability_summary_output() {
    let target = create_target("www.google.com", 443).await;
    let scanner = VulnerabilityScanner::new(target);

    let results = scanner.test_all().await;

    assert!(results.is_ok(), "Vulnerability scan should complete");

    if let Ok(vuln_results) = results {
        let summary = VulnerabilityScanner::summarize_results(&vuln_results);

        // Test summary formatting
        let output = summary.to_string();
        assert!(output.contains("Vulnerability Scan Summary"));
        assert!(output.contains("Total Tests:"));
        assert!(output.contains("Vulnerabilities Found:"));

        println!("{}", output);
    }
}

/// Test concurrent vulnerability detection on same target
#[tokio::test]
#[ignore]
async fn test_concurrent_vulnerability_tests() {
    let target = create_target("www.google.com", 443).await;

    // Create multiple scanners concurrently
    let scanner1 = VulnerabilityScanner::new(target.clone());
    let scanner2 = VulnerabilityScanner::new(target.clone());
    let scanner3 = VulnerabilityScanner::new(target.clone());

    // Run tests concurrently
    let (result1, result2, result3) = tokio::join!(
        scanner1.test_drown(),
        scanner2.test_rc4(),
        scanner3.test_poodle_ssl()
    );

    // All should complete
    assert!(result1.is_ok(), "DROWN test should complete");
    assert!(result2.is_ok(), "RC4 test should complete");
    assert!(result3.is_ok(), "POODLE test should complete");

    println!("Concurrent tests completed successfully");
}
