// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

use anyhow::Result;
use cipherrun::{Args, Scanner};
use clap::Parser;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging - respect RUST_LOG environment variable
    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Level>().ok())
        .unwrap_or(Level::INFO);

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    // Parse command line arguments
    let mut args = Args::parse();

    // Handle --version (display version and exit)
    if args.version {
        println!("CipherRun v{}", env!("CARGO_PKG_VERSION"));
        println!("Fast, Modular TLS/SSL Security Scanner");
        println!("Copyright (C) 2025 Marc Rivero (@seifreed)");
        println!("Licensed under GPL-3.0");
        return Ok(());
    }

    // Handle --no-colour / --no-color (disable colored output)
    if args.no_colour || args.no_color {
        args.color = 0;
    }

    // Handle --show-ciphers (list ciphers and exit)
    if args.show_ciphers {
        use cipherrun::data::CIPHER_DB;
        println!(
            "CipherRun v{} - Supported Cipher Suites\n",
            env!("CARGO_PKG_VERSION")
        );

        let all_ciphers = CIPHER_DB.get_all_ciphers();
        println!("Total: {} cipher suites\n", all_ciphers.len());

        for cipher in all_ciphers {
            println!(
                "  0x{} - {} / {}",
                cipher.hexcode, cipher.openssl_name, cipher.iana_name
            );
        }

        return Ok(());
    }

    // Display banner
    display_banner(&args);

    // Check for MX record testing
    if let Some(mx_domain) = &args.mx_domain {
        use cipherrun::utils::mx::MxTester;

        let mx_tester = MxTester::new(mx_domain.clone());
        let results = mx_tester.scan_all_mx(args.clone()).await?;

        // Display summary
        println!("{}", MxTester::generate_mx_summary(&results));

        // Export if requested
        if let Some(json_file) = &args.json {
            use serde_json::json;
            let json_data = json!({
                "scan_type": "mx_records",
                "domain": mx_domain,
                "total_mx_servers": results.len(),
                "results": results.iter().map(|(mx, result)| {
                    json!({
                        "priority": mx.priority,
                        "hostname": mx.hostname,
                        "success": result.is_ok(),
                        "scan_results": result.as_ref().ok(),
                        "error": result.as_ref().err().map(|e| e.to_string()),
                    })
                }).collect::<Vec<_>>(),
            });

            let json_string = if args.json_pretty {
                serde_json::to_string_pretty(&json_data)?
            } else {
                serde_json::to_string(&json_data)?
            };

            std::fs::write(json_file, json_string)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        return Ok(());
    }

    // Check if we're doing mass scanning or single target scanning
    if let Some(input_file) = &args.input_file {
        // Mass scanning mode
        use cipherrun::scanner::mass::MassScanner;

        let mass_scanner = MassScanner::from_file(
            args.clone(),
            input_file
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?,
        )?;

        info!(
            "Loaded {} targets from {}",
            mass_scanner.targets.len(),
            input_file.display()
        );

        let results = if args.parallel {
            mass_scanner.scan_parallel().await?
        } else {
            mass_scanner.scan_serial().await?
        };

        // Display summary
        println!("{}", MassScanner::generate_summary(&results));

        // Export if requested
        if let Some(json_file) = &args.json {
            MassScanner::export_all_json(
                &results,
                json_file
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?,
                args.json_pretty,
            )?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        if args.csv.is_some() || args.html.is_some() {
            println!(
                "Note: CSV and HTML export for mass scans will export individual results per target"
            );
        }
    } else {
        // Single target scanning mode
        let mut scanner = Scanner::new(args.clone())?;

        // Run the scan
        let results = scanner.run().await?;

        // Output results
        results.display()?;

        // Export results if requested
        if let Some(json_file) = &args.json {
            let json = results.to_json(args.json_pretty)?;
            std::fs::write(json_file, &json)?;
            println!("✓ Results exported to JSON: {}", json_file.display());
        }

        if let Some(csv_file) = &args.csv {
            let csv = results.to_csv()?;
            std::fs::write(csv_file, &csv)?;
            println!("✓ Results exported to CSV: {}", csv_file.display());
        }

        if let Some(html_file) = &args.html {
            use cipherrun::output::html;
            let html_content = html::generate_html_report(&results)?;
            std::fs::write(html_file, &html_content)?;
            println!("✓ Results exported to HTML: {}", html_file.display());
        }

        if let Some(xml_file) = &args.xml {
            use cipherrun::output::xml;
            let xml_content = xml::generate_xml_report(&results)?;
            std::fs::write(xml_file, &xml_content)?;
            println!("✓ Results exported to XML: {}", xml_file.display());
        }
    }

    Ok(())
}

fn display_banner(args: &Args) {
    if !args.quiet {
        println!(
            r#"
    ╔═══════════════════════════════════════════════════════════╗
    ║                     CipherRun v0.1.0                      ║
    ║      Fast, Modular TLS/SSL Security Scanner (Rust)       ║
    ║                                                           ║
    ║              Author: Marc Rivero | @seifreed              ║
    ╚═══════════════════════════════════════════════════════════╝

    Licensed under GPL-3.0 | Use at your own risk
    "#
        );
    }
}
