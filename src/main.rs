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

    // Handle --db-config-example (generate example config and exit)
    if let Some(config_path) = &args.db_config_example {
        use cipherrun::db::DatabaseConfig;
        DatabaseConfig::create_example_config(
            config_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?,
        )?;
        println!("✓ Example database configuration saved to: {}", config_path.display());
        return Ok(());
    }

    // Handle database operations
    if args.db_init || args.cleanup_days.is_some() || args.history.is_some() {
        use cipherrun::db::CipherRunDatabase;

        let db_config_path = args
            .db_config
            .as_ref()
            .map(|p| p.to_str().unwrap_or("database.toml"))
            .unwrap_or("database.toml");

        let db = CipherRunDatabase::from_config_file(db_config_path).await?;

        // Initialize database
        if args.db_init {
            println!("✓ Database initialized successfully");
        }

        // Cleanup old scans
        if let Some(days) = args.cleanup_days {
            let deleted = db.cleanup_old_scans(days).await?;
            println!("✓ Deleted {} old scan(s) (older than {} days)", deleted, days);
        }

        // Query scan history
        if let Some(history_target) = &args.history {
            let parts: Vec<&str> = history_target.split(':').collect();
            let hostname = parts.first().unwrap_or(&"").to_string();
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

            let scans = db.get_scan_history(&hostname, port, args.history_limit).await?;

            println!("\nScan History for {}:{}", hostname, port);
            println!("{}", "=".repeat(80));

            if scans.is_empty() {
                println!("No scan history found");
            } else {
                for scan in scans {
                    println!(
                        "  {} - Grade: {} | Score: {} | Duration: {}ms",
                        scan.scan_timestamp.format("%Y-%m-%d %H:%M:%S"),
                        scan.overall_grade.as_deref().unwrap_or("N/A"),
                        scan.overall_score.unwrap_or(0),
                        scan.scan_duration_ms.unwrap_or(0)
                    );
                }
            }
        }

        db.close().await;

        // Exit if only database operations were requested
        if args.target.is_none() && args.input_file.is_none() && args.mx_domain.is_none() {
            return Ok(());
        }
    }

    // Handle monitoring operations
    if args.test_alert || args.monitor {
        use cipherrun::monitor::{MonitorDaemon, MonitorConfig, MonitoredDomain};

        // Load or create monitoring configuration
        let monitor_config = if let Some(config_path) = &args.monitor_config {
            let config_str = std::fs::read_to_string(config_path)?;
            toml::from_str(&config_str)?
        } else {
            // Create default configuration
            MonitorConfig::default()
        };

        // Handle test alert
        if args.test_alert {
            info!("Testing alert channels...");
            let daemon = MonitorDaemon::new(monitor_config).await?;
            let results = daemon.test_alerts().await;

            println!("\nAlert Channel Tests:");
            println!("{}", "=".repeat(80));

            if results.is_empty() {
                println!("No alert channels configured");
            } else {
                for (channel_name, result) in results {
                    let status = if result.is_ok() { "✓" } else { "✗" };
                    let message = result
                        .as_ref()
                        .map(|_| "Success".to_string())
                        .unwrap_or_else(|e| format!("Failed: {}", e));
                    println!("  {} {} - {}", status, channel_name, message);
                }
            }
            println!();

            return Ok(());
        }

        // Handle monitor daemon start
        if args.monitor {
            info!("Starting certificate monitoring daemon");

            let daemon = MonitorDaemon::new(monitor_config).await?;

            // Load domains from file
            if let Some(domains_file) = &args.monitor_domains {
                let path_str = domains_file
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid domains file path"))?;
                daemon.load_domains(path_str).await?;
            }

            // Add single domain if specified
            if let Some(domain_str) = &args.monitor_domain {
                let parts: Vec<&str> = domain_str.split(':').collect();
                let hostname = parts.first().copied().unwrap_or("localhost");
                let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

                let domain = MonitoredDomain::new(
                    hostname.to_string(),
                    port,
                );

                daemon.add_domain(domain).await?;
            }

            // Start the monitoring daemon
            daemon.start().await?;

            return Ok(());
        }
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

        // Store results in database if requested
        if args.store_results && args.db_config.is_some() {
            use cipherrun::db::CipherRunDatabase;

            let db_config_path = args
                .db_config
                .as_ref()
                .unwrap()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid database config path"))?;

            let db = CipherRunDatabase::from_config_file(db_config_path).await?;
            let scan_id = db.store_scan(&results).await?;
            println!("\n✓ Scan results stored in database (scan_id: {})", scan_id);
            db.close().await;
        }

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
