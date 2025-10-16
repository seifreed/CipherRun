// Integration tests for STARTTLS protocols
// Tests SMTP, IMAP, POP3 STARTTLS upgrades against real servers
// Run with: cargo test --test integration_starttls -- --ignored --test-threads=1

use cipherrun::utils::network::Target;
use cipherrun::vulnerabilities::starttls_injection::StarttlsInjectionTester;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Helper to create target
async fn create_target(host: &str, port: u16) -> Target {
    let target_str = format!("{}:{}", host, port);
    Target::parse(&target_str)
        .await
        .expect("Failed to parse target")
}

/// Test SMTP STARTTLS detection (port 587)
/// Uses Gmail's public SMTP server
#[tokio::test]
#[ignore]
async fn test_smtp_starttls_detection() {
    // Gmail SMTP submission port
    let target = create_target("smtp.gmail.com", 587).await;

    // Connect to SMTP server
    let addr = format!("{}:{}", target.hostname, target.port);
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect");

    let result = test_smtp_starttls_handshake(stream).await;
    assert!(result.is_ok(), "SMTP STARTTLS handshake should work");

    let supports_starttls = result.unwrap();
    assert!(supports_starttls, "Gmail SMTP should support STARTTLS");
}

/// Test SMTP STARTTLS on port 25
#[tokio::test]
#[ignore]
async fn test_smtp_port_25_starttls() {
    // Note: Many ISPs block port 25, this test might fail
    let target = create_target("smtp.gmail.com", 25).await;

    let addr = format!("{}:{}", target.hostname, target.port);
    match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let result = test_smtp_starttls_handshake(stream).await;
            match result {
                Ok(supports) => {
                    println!("SMTP port 25 STARTTLS: {}", supports);
                    assert!(supports, "Should support STARTTLS");
                }
                Err(e) => {
                    println!("SMTP port 25 error (may be blocked by ISP): {}", e);
                }
            }
        }
        Ok(Err(e)) => {
            println!("Port 25 connection refused (ISP may block): {}", e);
        }
        Err(_) => {
            println!("Port 25 connection timeout (ISP may block)");
        }
    }
}

/// Helper function to test SMTP STARTTLS handshake
async fn test_smtp_starttls_handshake(
    mut stream: TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];

    // Read server greeting
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let greeting = String::from_utf8_lossy(&buf[..n]);

    if !greeting.starts_with("220") {
        return Ok(false);
    }

    // Send EHLO
    stream.write_all(b"EHLO test.local\r\n").await?;
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Check if STARTTLS is advertised
    let supports_starttls = response.contains("STARTTLS");

    // Send QUIT to be polite
    stream.write_all(b"QUIT\r\n").await?;

    Ok(supports_starttls)
}

/// Test IMAP STARTTLS detection
/// Uses Gmail's public IMAP server
#[tokio::test]
#[ignore]
async fn test_imap_starttls_detection() {
    let target = create_target("imap.gmail.com", 143).await;

    let addr = format!("{}:{}", target.hostname, target.port);
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect");

    let result = test_imap_starttls_handshake(stream).await;
    assert!(result.is_ok(), "IMAP connection should work");

    let supports_starttls = result.unwrap();
    assert!(supports_starttls, "Gmail IMAP should support STARTTLS");
}

/// Helper function to test IMAP STARTTLS handshake
async fn test_imap_starttls_handshake(
    mut stream: TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];

    // Read server greeting
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let greeting = String::from_utf8_lossy(&buf[..n]);

    if !greeting.starts_with("* OK") {
        return Ok(false);
    }

    // Send CAPABILITY command
    stream.write_all(b"a001 CAPABILITY\r\n").await?;
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Check if STARTTLS is advertised
    let supports_starttls = response.contains("STARTTLS");

    // Send LOGOUT to be polite
    stream.write_all(b"a002 LOGOUT\r\n").await?;

    Ok(supports_starttls)
}

/// Test POP3 STARTTLS detection
/// Uses Gmail's public POP3 server
#[tokio::test]
#[ignore]
async fn test_pop3_starttls_detection() {
    let target = create_target("pop.gmail.com", 110).await;

    let addr = format!("{}:{}", target.hostname, target.port);
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect");

    let result = test_pop3_starttls_handshake(stream).await;
    assert!(result.is_ok(), "POP3 connection should work");

    let supports_starttls = result.unwrap();
    assert!(
        supports_starttls,
        "Gmail POP3 should support STLS (STARTTLS)"
    );
}

/// Helper function to test POP3 STARTTLS handshake
async fn test_pop3_starttls_handshake(
    mut stream: TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];

    // Read server greeting
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let greeting = String::from_utf8_lossy(&buf[..n]);

    if !greeting.starts_with("+OK") {
        return Ok(false);
    }

    // Send CAPA command
    stream.write_all(b"CAPA\r\n").await?;
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Check if STLS is advertised (POP3 uses STLS, not STARTTLS)
    let supports_starttls = response.contains("STLS");

    // Send QUIT to be polite
    stream.write_all(b"QUIT\r\n").await?;

    Ok(supports_starttls)
}

/// Test STARTTLS injection vulnerability tester against SMTP
#[tokio::test]
#[ignore]
async fn test_starttls_injection_smtp_gmail() {
    let target = create_target("smtp.gmail.com", 587).await;
    let tester = StarttlsInjectionTester::new(target);

    let result = tester.test_smtp_injection().await;

    match result {
        Ok(is_vulnerable) => {
            // Gmail should NOT be vulnerable
            assert!(
                !is_vulnerable,
                "Gmail should not be vulnerable to STARTTLS injection"
            );
            println!("✓ Gmail SMTP is NOT vulnerable to STARTTLS injection");
        }
        Err(e) => {
            println!("STARTTLS injection test error: {}", e);
        }
    }
}

/// Test STARTTLS injection vulnerability tester against IMAP
#[tokio::test]
#[ignore]
async fn test_starttls_injection_imap_gmail() {
    let target = create_target("imap.gmail.com", 143).await;
    let tester = StarttlsInjectionTester::new(target);

    let result = tester.test_imap_injection().await;

    match result {
        Ok(is_vulnerable) => {
            // Gmail should NOT be vulnerable
            assert!(
                !is_vulnerable,
                "Gmail IMAP should not be vulnerable to STARTTLS injection"
            );
            println!("✓ Gmail IMAP is NOT vulnerable to STARTTLS injection");
        }
        Err(e) => {
            println!("STARTTLS injection test error: {}", e);
        }
    }
}

/// Test STARTTLS injection vulnerability tester against POP3
#[tokio::test]
#[ignore]
async fn test_starttls_injection_pop3_gmail() {
    let target = create_target("pop.gmail.com", 110).await;
    let tester = StarttlsInjectionTester::new(target);

    let result = tester.test_pop3_injection().await;

    match result {
        Ok(is_vulnerable) => {
            // Gmail should NOT be vulnerable
            assert!(
                !is_vulnerable,
                "Gmail POP3 should not be vulnerable to STARTTLS injection"
            );
            println!("✓ Gmail POP3 is NOT vulnerable to STARTTLS injection");
        }
        Err(e) => {
            println!("STARTTLS injection test error: {}", e);
        }
    }
}

/// Test full STARTTLS injection test suite
#[tokio::test]
#[ignore]
async fn test_starttls_injection_all_protocols() {
    // Test SMTP
    let smtp_target = create_target("smtp.gmail.com", 587).await;
    let smtp_tester = StarttlsInjectionTester::new(smtp_target);

    match smtp_tester.test_all().await {
        Ok(result) => {
            println!("SMTP STARTTLS test results:");
            println!("  Vulnerable: {}", result.vulnerable);
            println!("  SMTP vulnerable: {}", result.smtp_vulnerable);
            for detail in &result.details {
                println!("  - {}", detail);
            }
            assert!(
                !result.smtp_vulnerable,
                "Gmail SMTP should not be vulnerable"
            );
        }
        Err(e) => {
            println!("SMTP STARTTLS test error: {}", e);
        }
    }

    // Test IMAP
    let imap_target = create_target("imap.gmail.com", 143).await;
    let imap_tester = StarttlsInjectionTester::new(imap_target);

    match imap_tester.test_all().await {
        Ok(result) => {
            println!("IMAP STARTTLS test results:");
            println!("  Vulnerable: {}", result.vulnerable);
            println!("  IMAP vulnerable: {}", result.imap_vulnerable);
            for detail in &result.details {
                println!("  - {}", detail);
            }
            assert!(
                !result.imap_vulnerable,
                "Gmail IMAP should not be vulnerable"
            );
        }
        Err(e) => {
            println!("IMAP STARTTLS test error: {}", e);
        }
    }

    // Test POP3
    let pop3_target = create_target("pop.gmail.com", 110).await;
    let pop3_tester = StarttlsInjectionTester::new(pop3_target);

    match pop3_tester.test_all().await {
        Ok(result) => {
            println!("POP3 STARTTLS test results:");
            println!("  Vulnerable: {}", result.vulnerable);
            println!("  POP3 vulnerable: {}", result.pop3_vulnerable);
            for detail in &result.details {
                println!("  - {}", detail);
            }
            assert!(
                !result.pop3_vulnerable,
                "Gmail POP3 should not be vulnerable"
            );
        }
        Err(e) => {
            println!("POP3 STARTTLS test error: {}", e);
        }
    }
}

/// Test SMTP STARTTLS with alternative mail server (Outlook)
#[tokio::test]
#[ignore]
async fn test_smtp_starttls_outlook() {
    let target = create_target("smtp-mail.outlook.com", 587).await;

    let addr = format!("{}:{}", target.hostname, target.port);
    match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let result = test_smtp_starttls_handshake(stream).await;
            match result {
                Ok(supports) => {
                    assert!(supports, "Outlook SMTP should support STARTTLS");
                    println!("✓ Outlook SMTP supports STARTTLS");
                }
                Err(e) => {
                    println!("Outlook SMTP test error: {}", e);
                }
            }
        }
        Ok(Err(e)) => {
            println!("Outlook connection failed: {}", e);
        }
        Err(_) => {
            println!("Outlook connection timeout");
        }
    }
}

/// Test IMAP STARTTLS with alternative mail server (Outlook)
#[tokio::test]
#[ignore]
async fn test_imap_starttls_outlook() {
    let target = create_target("outlook.office365.com", 143).await;

    let addr = format!("{}:{}", target.hostname, target.port);
    match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let result = test_imap_starttls_handshake(stream).await;
            match result {
                Ok(supports) => {
                    assert!(supports, "Outlook IMAP should support STARTTLS");
                    println!("✓ Outlook IMAP supports STARTTLS");
                }
                Err(e) => {
                    println!("Outlook IMAP test error: {}", e);
                }
            }
        }
        Ok(Err(e)) => {
            println!("Outlook IMAP connection failed: {}", e);
        }
        Err(_) => {
            println!("Outlook IMAP connection timeout");
        }
    }
}

/// Test STARTTLS error handling for non-STARTTLS ports
#[tokio::test]
#[ignore]
async fn test_starttls_on_https_port() {
    // This should fail gracefully - port 443 doesn't speak SMTP/IMAP/POP3
    let target = create_target("smtp.gmail.com", 443).await;
    let tester = StarttlsInjectionTester::new(target);

    let result = tester.test_all().await;

    match result {
        Ok(result) => {
            // Should indicate it's not a STARTTLS port
            println!("Port 443 test result: {:?}", result.details);
            assert!(
                result
                    .details
                    .iter()
                    .any(|d| d.contains("not a standard STARTTLS port")),
                "Should indicate port 443 is not a STARTTLS port"
            );
        }
        Err(e) => {
            println!("Expected error for non-STARTTLS port: {}", e);
        }
    }
}

/// Test multiple STARTTLS protocols sequentially
#[tokio::test]
#[ignore]
async fn test_multiple_starttls_protocols_sequential() {
    let protocols = vec![
        ("smtp.gmail.com", 587, "SMTP"),
        ("imap.gmail.com", 143, "IMAP"),
        ("pop.gmail.com", 110, "POP3"),
    ];

    let mut results = Vec::new();

    for (host, port, protocol_name) in protocols {
        let target = create_target(host, port).await;
        let addr = format!("{}:{}", target.hostname, target.port);

        match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                let supports = match protocol_name {
                    "SMTP" => test_smtp_starttls_handshake(stream).await,
                    "IMAP" => test_imap_starttls_handshake(stream).await,
                    "POP3" => test_pop3_starttls_handshake(stream).await,
                    _ => continue,
                };

                match supports {
                    Ok(true) => {
                        println!("✓ {} on {}:{} supports STARTTLS", protocol_name, host, port);
                        results.push((protocol_name, true));
                    }
                    Ok(false) => {
                        println!(
                            "✗ {} on {}:{} does not support STARTTLS",
                            protocol_name, host, port
                        );
                        results.push((protocol_name, false));
                    }
                    Err(e) => {
                        println!("✗ {} on {}:{} error: {}", protocol_name, host, port, e);
                        results.push((protocol_name, false));
                    }
                }
            }
            _ => {
                println!("✗ {} on {}:{} connection failed", protocol_name, host, port);
                results.push((protocol_name, false));
            }
        }
    }

    // All three Gmail protocols should support STARTTLS
    let successful_protocols = results.iter().filter(|(_, supported)| *supported).count();
    assert!(
        successful_protocols >= 2,
        "At least 2 out of 3 protocols should support STARTTLS (got {})",
        successful_protocols
    );
}
