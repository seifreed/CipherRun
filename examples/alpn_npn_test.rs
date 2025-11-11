// ALPN/NPN Protocol Negotiation Test
//
// This example demonstrates how to test for ALPN (Application-Layer Protocol
// Negotiation) and NPN (Next Protocol Negotiation) support on a target server.
//
// Usage:
//   cargo run --example alpn_npn_test -- <hostname>
//
// Example:
//   cargo run --example alpn_npn_test -- www.google.com

use cipherrun::protocols::alpn::AlpnTester;
use cipherrun::protocols::npn::NpnTester;
use cipherrun::utils::network::Target;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get hostname from command line arguments
    let args: Vec<String> = env::args().collect();
    let hostname = if args.len() > 1 {
        args[1].clone()
    } else {
        println!("Usage: {} <hostname>", args[0]);
        println!("Example: {} www.google.com", args[0]);
        return Ok(());
    };

    let port = 443;
    println!("Testing ALPN/NPN on {}:{}", hostname, port);
    println!("{}", "=".repeat(60));

    // Parse target
    let target_str = format!("{}:{}", hostname, port);
    let target = Target::parse(&target_str).await?;

    // Test ALPN
    println!(
        "\n{}",
        "Testing ALPN (Application-Layer Protocol Negotiation)..."
    );
    let alpn_tester = AlpnTester::new(target.clone());

    match alpn_tester.get_comprehensive_report().await {
        Ok(report) => {
            println!("ALPN Enabled: {}", report.alpn_enabled);

            if report.alpn_enabled {
                println!("\nSupported Protocols:");
                for proto in &report.alpn_result.supported_protocols {
                    println!("  - {}", proto);
                }

                if let Some(ref negotiated) = report.alpn_result.negotiated_protocol {
                    println!("\nPreferred Protocol: {}", negotiated);
                }

                println!("\nHTTP/2 Support: {}", report.alpn_result.http2_supported);
                println!("SPDY Support: {}", report.spdy_supported);

                if !report.recommendations.is_empty() {
                    println!("\nRecommendations:");
                    for rec in &report.recommendations {
                        println!("  {}", rec);
                    }
                }
            } else {
                println!("ALPN is not enabled on this server");
            }
        }
        Err(e) => {
            println!("Failed to test ALPN: {}", e);
        }
    }

    // Test NPN
    println!("\n{}", "=".repeat(60));
    println!(
        "\n{}",
        "Testing NPN (Next Protocol Negotiation - Deprecated)..."
    );
    let npn_tester = NpnTester::new(target);

    match npn_tester.test().await {
        Ok(result) => {
            println!("NPN Supported: {}", result.supported);

            if result.supported {
                println!("Protocols: {:?}", result.protocols);
                println!("\n⚠ WARNING: NPN is deprecated. Server should use ALPN instead.");
            } else {
                println!("✓ Good: NPN is not supported (ALPN should be used instead)");
            }

            println!("\nDetails: {}", result.details);
        }
        Err(e) => {
            println!("Failed to test NPN: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("\nSSL Labs comparison:");
    println!("  ALPN: Check if output matches SSL Labs 'ALPN' field");
    println!("  NPN:  Check if output matches SSL Labs 'NPN' field");

    Ok(())
}
