// Test CLI validation for Phase 1 multi-IP flags
//
// This example demonstrates the CLI validation logic for conflicting flags

use cipherrun::Args;
use clap::Parser;

fn test_case(args_str: &str, should_fail: bool) {
    println!("\n Testing: {}", args_str);

    let args_vec: Vec<&str> = args_str.split_whitespace().collect();

    match Args::try_parse_from(args_vec) {
        Ok(args) => match args.validate() {
            Ok(_) => {
                if should_fail {
                    println!("  ✗ FAILED: Expected validation error but got success");
                } else {
                    println!("  ✓ PASSED: Validation succeeded as expected");
                }
            }
            Err(e) => {
                if should_fail {
                    println!("  ✓ PASSED: Got expected validation error: {}", e);
                } else {
                    println!("  ✗ FAILED: Unexpected validation error: {}", e);
                }
            }
        },
        Err(e) => {
            println!("  ! Parsing failed: {}", e);
        }
    }
}

fn main() {
    println!("=".repeat(80));
    println!("Phase 1 CLI Validation Tests");
    println!("=".repeat(80));

    // Valid cases
    println!("\n Valid Cases (should pass):");
    test_case("cipherrun example.com", false);
    test_case("cipherrun example.com --first-ip-only", false);
    test_case("cipherrun example.com --test-all-ips", false);
    test_case("cipherrun example.com --ip 1.2.3.4", false);

    // Invalid cases
    println!("\n Invalid Cases (should fail):");
    test_case("cipherrun example.com --test-all-ips --first-ip-only", true);
    test_case("cipherrun example.com --ip 1.2.3.4 --test-all-ips", true);
    test_case("cipherrun example.com --ip 1.2.3.4 --first-ip-only", true);

    println!("\n{}", "=".repeat(80));
    println!("All tests completed");
    println!("=".repeat(80));
}
