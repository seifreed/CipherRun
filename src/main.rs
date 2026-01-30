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
use cipherrun::Args;
use cipherrun::commands::CommandRouter;
use cipherrun::utils::PathExt;
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

    // Validate CLI arguments for conflicting flags
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Handle --version (display version and exit)
    if args.version {
        println!("CipherRun v{}", env!("CARGO_PKG_VERSION"));
        println!("Fast, Modular TLS/SSL Security Scanner");
        println!("Copyright (C) 2025 Marc Rivero (@seifreed)");
        println!("Licensed under GPL-3.0");
        return Ok(());
    }

    // Handle --api-config-example (generate API config example and exit)
    if let Some(config_path) = &args.api_server.config_example {
        use cipherrun::api::ApiConfig;
        ApiConfig::create_example(config_path.to_str_anyhow()?)?;
        println!(
            "✓ Example API configuration saved to: {}",
            config_path.display()
        );
        return Ok(());
    }

    // Handle --list-compliance (list available frameworks and exit)
    if args.compliance.list_frameworks {
        use cipherrun::compliance::FrameworkLoader;

        println!("Available Compliance Frameworks:\n");
        let frameworks = FrameworkLoader::list_builtin_frameworks();

        for (id, description) in frameworks {
            println!("  {} - {}", id, description);
        }

        println!("\nUsage: cipherrun --compliance <FRAMEWORK_ID> <TARGET>");
        println!("Example: cipherrun --compliance pci-dss-v4 example.com:443");
        return Ok(());
    }

    // Handle --db-config-example (generate example config and exit)
    if let Some(config_path) = &args.database.config_example {
        use cipherrun::db::DatabaseConfig;
        DatabaseConfig::create_example_config(config_path.to_str_anyhow()?)?;
        println!(
            "✓ Example database configuration saved to: {}",
            config_path.display()
        );
        return Ok(());
    }

    // Handle --no-colour / --no-color (disable colored output)
    if args.output.no_colour || args.output.no_color {
        args.output.color = 0;
    }

    // Handle --show-ciphers (list ciphers and exit)
    if args.scan.show_ciphers {
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

    // Validate routing before creating command
    if let Err(e) = CommandRouter::validate_routing(&args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Route to appropriate command and execute
    let command = CommandRouter::route(args)?;

    info!("Executing command: {}", command.name());
    command.execute().await?;

    Ok(())
}
