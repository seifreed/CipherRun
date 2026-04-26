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

use cipherrun::Args;
use cipherrun::commands::{CommandExit, CommandRouter};
use cipherrun::external::openssl_client::OpenSslClient;
use cipherrun::utils::PathExt;
use clap::CommandFactory;
use colored::control;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};

#[tokio::main]
async fn main() -> ExitCode {
    match run_cli().await {
        Ok(exit) => {
            let code = exit.code();
            let u8_code = if code < 0 { 1 } else { code.clamp(0, 255) as u8 };
            ExitCode::from(u8_code)
        }
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::from(1)
        }
    }
}

async fn run_cli() -> anyhow::Result<CommandExit> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let raw_arg_count = std::env::args_os().count();

    // Parse command line arguments
    let mut args = Args::parse_with_sources()?;

    if raw_arg_count == 1 {
        let mut command = Args::command();
        command.print_help()?;
        println!();
        return Ok(CommandExit::success());
    }

    // Handle --no-colour / --no-color (disable colored output)
    if args.output.no_colour || args.output.no_color {
        args.output.color = 0;
    }

    // Validate CLI arguments for conflicting flags
    args.validate()?;

    apply_output_preferences(&args);
    initialize_logging(&args)?;

    // Handle --version (display version and exit)
    if args.version {
        println!("CipherRun v{}", env!("CARGO_PKG_VERSION"));
        println!("Fast, Modular TLS/SSL Security Scanner");
        println!("Copyright (C) 2025 Marc Rivero (@seifreed)");
        println!("Licensed under GPL-3.0");
        return Ok(CommandExit::success());
    }

    // Handle --api-config-example (generate API config example and exit)
    if let Some(config_path) = &args.api_server.config_example {
        use cipherrun::api::ApiConfig;
        ApiConfig::create_example(config_path.to_str_anyhow()?)?;
        println!(
            "✓ Example API configuration saved to: {}",
            config_path.display()
        );
        return Ok(CommandExit::success());
    }

    // Handle --list-compliance (list available frameworks and exit)
    if args.compliance.list_frameworks {
        use cipherrun::compliance::BuiltinFrameworkSource;

        println!("Available Compliance Frameworks:\n");
        let frameworks = BuiltinFrameworkSource::list_frameworks();

        for (id, description) in frameworks {
            println!("  {} - {}", id, description);
        }

        println!("\nUsage: cipherrun --compliance <FRAMEWORK_ID> <TARGET>");
        println!("Example: cipherrun --compliance pci-dss-v4 example.com:443");
        return Ok(CommandExit::success());
    }

    // Handle --db-config-example (generate example config and exit)
    if let Some(config_path) = &args.database.config_example {
        use cipherrun::db::DatabaseConfig;
        DatabaseConfig::create_example_config(config_path.to_str_anyhow()?)?;
        println!(
            "✓ Example database configuration saved to: {}",
            config_path.display()
        );
        return Ok(CommandExit::success());
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

        return Ok(CommandExit::success());
    }

    // Handle --local (list local OpenSSL ciphers and exit)
    if args.tls.local {
        let openssl = if let Some(path) = &args.tls.openssl_path {
            OpenSslClient::with_path(path.to_str_anyhow()?.to_string())
        } else {
            OpenSslClient::new()
        };

        println!("OpenSSL: {}", openssl.get_version()?);
        for cipher in openssl.list_local_ciphers()? {
            println!("{}", cipher);
        }

        return Ok(CommandExit::success());
    }

    // Validate routing before creating command
    CommandRouter::validate_routing(&args)?;

    // Route to appropriate command and execute
    let command = CommandRouter::route(args)?;

    info!("Executing command: {}", command.name());
    command.execute().await.map_err(Into::into)
}

fn initialize_logging(args: &Args) -> anyhow::Result<()> {
    let log_level = resolve_log_level(
        std::env::var("RUST_LOG").ok().as_deref(),
        args.output.verbose,
    );

    let writer: BoxMakeWriter = if let Some(path) = &args.output.logfile {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let file_writer = SharedFileWriter::new(file);
        BoxMakeWriter::new(std::io::stderr.and(file_writer))
    } else {
        BoxMakeWriter::new(std::io::stderr)
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_writer(writer)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    Ok(())
}

fn resolve_log_level(rust_log: Option<&str>, verbose: u8) -> Level {
    rust_log
        .and_then(|value| value.parse::<Level>().ok())
        .unwrap_or(match verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        })
}

fn color_output_enabled(mode: u8) -> bool {
    mode != 0
}

fn apply_output_preferences(args: &Args) {
    control::set_override(color_output_enabled(args.output.color));
}

#[derive(Clone)]
struct SharedFileWriter {
    file: Arc<Mutex<std::fs::File>>,
}

impl SharedFileWriter {
    fn new(file: std::fs::File) -> Self {
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }
}

struct SharedFileGuard {
    file: Arc<Mutex<std::fs::File>>,
}

impl<'a> MakeWriter<'a> for SharedFileWriter {
    type Writer = SharedFileGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedFileGuard {
            file: Arc::clone(&self.file),
        }
    }
}

impl std::io::Write for SharedFileGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut file = self.file.lock().expect("logfile mutex poisoned");
        std::io::Write::write(&mut *file, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut file = self.file.lock().expect("logfile mutex poisoned");
        std::io::Write::flush(&mut *file)
    }
}

#[cfg(test)]
mod tests {
    use super::{color_output_enabled, resolve_log_level};
    use tracing::Level;

    #[test]
    fn test_resolve_log_level_defaults_to_info() {
        assert_eq!(resolve_log_level(None, 0), Level::INFO);
    }

    #[test]
    fn test_resolve_log_level_uses_verbose_when_env_missing() {
        assert_eq!(resolve_log_level(None, 1), Level::DEBUG);
        assert_eq!(resolve_log_level(None, 2), Level::TRACE);
        assert_eq!(resolve_log_level(None, 5), Level::TRACE);
    }

    #[test]
    fn test_resolve_log_level_prefers_rust_log() {
        assert_eq!(resolve_log_level(Some("ERROR"), 2), Level::ERROR);
    }

    #[test]
    fn test_resolve_log_level_falls_back_on_invalid_rust_log() {
        assert_eq!(resolve_log_level(Some("not-a-level"), 1), Level::DEBUG);
    }

    #[test]
    fn test_color_output_enabled() {
        assert!(!color_output_enabled(0));
        assert!(color_output_enabled(1));
        assert!(color_output_enabled(2));
        assert!(color_output_enabled(3));
    }
}
