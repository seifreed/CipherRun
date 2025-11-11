// Example: HSTS Preload List Verification
//
// This example demonstrates how to use the HSTS preload checker
// to verify if a domain is in browser preload lists.
//
// Usage:
//   cargo run --example hsts_preload_check -- google.com

use std::collections::HashMap;

#[tokio::main]
async fn main() {
    // Get domain from command line arguments
    let args: Vec<String> = std::env::args().collect();
    let domain = if args.len() > 1 {
        &args[1]
    } else {
        "google.com"
    };

    println!("HSTS Preload Status Check");
    println!("=========================\n");
    println!("Checking domain: {}\n", domain);

    // Example 1: Direct preload status check
    println!("1. Direct Preload Status Check:");
    println!("--------------------------------");

    use cipherrun::http::hsts_preload::HstsPreloadChecker;

    let checker = HstsPreloadChecker::new();

    match checker.check_preload_status(domain).await {
        Ok(status) => {
            println!(
                "   Chrome:   {}",
                if status.in_chrome {
                    "✓ In list"
                } else {
                    "✗ Not in list"
                }
            );
            println!(
                "   Firefox:  {}",
                if status.in_firefox {
                    "✓ In list"
                } else {
                    "✗ Not in list"
                }
            );
            println!(
                "   Edge:     {}",
                if status.in_edge {
                    "✓ In list"
                } else {
                    "✗ Not in list"
                }
            );
            println!(
                "   Safari:   {}",
                if status.in_safari {
                    "✓ In list"
                } else {
                    "✗ Not in list"
                }
            );
            println!("   Status:   {:?}", status.chromium_status);
            println!("   Source:   {:?}", status.source);
        }
        Err(e) => {
            println!("   Error: {}", e);
        }
    }

    println!();

    // Example 2: Checking with headers
    println!("2. Full Header Analysis:");
    println!("------------------------");

    use cipherrun::http::headers::SecurityHeaderChecker;

    // Simulate HSTS headers
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains; preload".to_string(),
    );

    // Check headers
    let issues = SecurityHeaderChecker::check_all_headers(&headers);

    if issues.is_empty() {
        println!("   ✓ No issues found!");
    } else {
        for (i, issue) in issues.iter().enumerate() {
            println!("   Issue {}: {}", i + 1, issue.header_name);
            println!("   Severity: {:?}", issue.severity);
            println!("   Type: {:?}", issue.issue_type);
            println!("   Description: {}", issue.description);
            println!("   Recommendation: {}", issue.recommendation);
            println!();
        }
    }

    // Example 3: Cache statistics
    println!("3. Cache Statistics:");
    println!("-------------------");
    let (total, valid) = checker.cache_stats();
    println!("   Total entries: {}", total);
    println!("   Valid entries: {}", valid);

    println!();
    println!("✓ Examples completed successfully!");
}
