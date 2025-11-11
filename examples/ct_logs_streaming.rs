// Example: Certificate Transparency Logs Streaming
//
// This example demonstrates how to use CipherRun's CT logs streaming
// functionality to monitor certificate issuance in real-time.
//
// Run with:
// cargo run --example ct_logs_streaming

#![allow(clippy::field_reassign_with_default)]

use cipherrun::ct_logs::CtConfig;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== Certificate Transparency Logs Streaming Example ===\n");

    // Example 1: Stream from current position (default - "now" mode)
    println!("Example 1: Streaming from current position");
    println!("This will start streaming new certificates as they are added to CT logs.\n");

    let _config = CtConfig {
        start_from_beginning: false, // Start from current tree size
        custom_indices: Default::default(),
        poll_interval: Duration::from_secs(60),
        batch_size: 1000,
        json_output: false,
        silent: false,
    };

    // Note: This will run indefinitely. Press Ctrl+C to stop.
    // Uncomment to run:
    // let mut streamer = CtStreamer::new(config).await?;
    // streamer.start().await?;

    // Example 2: Stream from beginning with JSON output
    println!("\nExample 2: Streaming from beginning with JSON output");
    println!("This will replay all certificates from the beginning of the logs.\n");

    let _config_beginning = CtConfig {
        start_from_beginning: true, // Start from index 0
        custom_indices: Default::default(),
        poll_interval: Duration::from_secs(60),
        batch_size: 1000,
        json_output: true, // Output as JSON (one entry per line)
        silent: true,      // No stats output
    };

    // Uncomment to run:
    // let mut streamer = CtStreamer::new(config_beginning).await?;
    // streamer.start().await?;

    // Example 3: Extract unique domains from certificates
    println!("\nExample 3: Extract unique domains");
    println!("Use this with command-line piping:");
    println!(
        "  cipherrun --ct-logs --ct-json --ct-silent | jq -r '.certificate.subject_an[]' | sort -u"
    );

    // Example 4: Start from custom index for specific log
    println!("\nExample 4: Start from custom index");
    println!("Use this to resume from a specific position:");
    println!("  cipherrun --ct-logs --ct-index google_xenon2025h2=12345");

    // Example 5: Monitor specific domains in CT logs
    println!("\nExample 5: Monitor for specific domains");
    println!("Use grep to filter for specific domains:");
    println!(
        "  cipherrun --ct-logs --ct-json --ct-silent | jq -r '.certificate.subject_an[]' | grep 'example.com'"
    );

    // Example 6: Performance tuning
    println!("\nExample 6: Performance tuning");
    println!("Adjust batch size and bloom filter for large datasets:");
    println!("  cipherrun --ct-logs --ct-batch-size 1000 --ct-expected-certs 10000000");

    println!("\n=== Common Use Cases ===\n");

    println!("1. Subdomain Discovery:");
    println!(
        "   cipherrun --ct-logs --ct-json --ct-silent | jq -r '.certificate.subject_an[]' | grep '\\.example\\.com$' | sort -u\n"
    );

    println!("2. New Certificate Monitoring:");
    println!("   cipherrun --ct-logs | grep 'example.com'\n");

    println!("3. Certificate Intelligence Gathering:");
    println!("   cipherrun --ct-logs --ct-json > certificates.jsonl\n");

    println!("4. Real-time Security Monitoring:");
    println!("   cipherrun --ct-logs --ct-json --ct-silent | while read line; do");
    println!(
        "     echo \"$line\" | jq -r '.certificate.subject_an[]' | grep -i 'malicious' && alert"
    );
    println!("   done\n");

    println!("=== Statistics Output ===\n");
    println!("Without --ct-silent flag, you'll see periodic statistics:");
    println!("  - Total certificates processed");
    println!("  - Unique certificates (after deduplication)");
    println!("  - Duplicates filtered");
    println!("  - Processing rate (certs/sec)");
    println!("  - Per-source statistics\n");

    Ok(())
}
