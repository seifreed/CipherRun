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
use clap::CommandFactory;
use colored::control;
use std::process::ExitCode;
use tracing::Instrument;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    match run_cli().await {
        Ok(exit) => {
            let code = exit.code();
            let u8_code = if code < 0 {
                1
            } else {
                code.clamp(0, 255) as u8
            };
            ExitCode::from(u8_code)
        }
        Err(error) => {
            if tracing::dispatcher::has_been_set() {
                tracing::error!(
                    event_name = "cli.command.failed",
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    "CLI command failed"
                );
            } else {
                eprintln!(
                    "Error: CipherRun failed before logging was initialized (error_code={})",
                    error.observability_code()
                );
            }
            ExitCode::from(1)
        }
    }
}

async fn run_cli() -> cipherrun::Result<CommandExit> {
    // Install rustls crypto provider (required for rustls 0.23+)
    cipherrun::utils::rustls_provider::install_default().map_err(|_| {
        cipherrun::TlsError::Other(
            "Failed to install rustls crypto provider (already installed?)".to_string(),
        )
    })?;

    let raw_arg_count = std::env::args_os().count();

    // Parse command line arguments
    let mut args =
        Args::parse_with_sources().map_err(|e| cipherrun::TlsError::Other(e.to_string()))?;

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

    let _logging_guard = cipherrun::logging::initialize(&args)?;

    let mut command_failure_logged = false;
    let result = async {
        // Validate CLI arguments for conflicting flags
        args.validate()?;

        apply_output_preferences(&args);

        // Handle --version (display version and exit)
        if args.version {
            println!("CipherRun v{}", env!("CARGO_PKG_VERSION"));
            println!("Fast, Modular TLS/SSL Security Scanner");
            println!("Copyright (C) 2025 Marc Rivero (@seifreed)");
            println!("Licensed under GPL-3.0");
            return Ok(CommandExit::success());
        }

        if args.starttls.only {
            let started = std::time::Instant::now();
            let result = run_starttls_only(&args).await;
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match &result {
                Ok(exit) => info!(
                    event_name = "cli.starttls_only.completed",
                    operation = "starttls_only",
                    duration_ms,
                    exit_code = exit.code(),
                    supported = exit.is_success(),
                    outcome = "complete",
                    "STARTTLS-only operation completed"
                ),
                Err(error) => {
                    command_failure_logged = true;
                    tracing::error!(
                        event_name = "cli.starttls_only.failed",
                        operation = "starttls_only",
                        duration_ms,
                        error_type = "TlsError",
                        error_code = error.observability_code(),
                        outcome = "error",
                        "STARTTLS-only operation failed"
                    );
                }
            }
            return result;
        }

        // Handle --api-config-example (generate API config example and exit)
        if let Some(config_path) = &args.api_server.config_example {
            #[cfg(feature = "api")]
            {
                use cipherrun::api::ApiConfig;
                let started = std::time::Instant::now();
                let result = ApiConfig::create_example(config_path);
                command_failure_logged |= log_cli_operation(
                    "create_api_config_example",
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    &result,
                );
                let token_path = result?;
                println!(
                    "✓ Example API configuration saved to: {}",
                    config_path.display()
                );
                println!("✓ Bootstrap token saved to: {}", token_path.display());
                return Ok(CommandExit::success());
            }

            #[cfg(not(feature = "api"))]
            {
                let _ = config_path;
                return Err(cipherrun::TlsError::ConfigError {
                    message: "API configuration requires the `api` feature".to_string(),
                });
            }
        }

        // Handle --list-compliance (list available frameworks and exit)
        if args.compliance.list_frameworks {
            use cipherrun::compliance::BuiltinFrameworkSource;

            println!("Available Compliance Frameworks:\n");
            let frameworks = BuiltinFrameworkSource::list_frameworks();

            for (id, description) in frameworks {
                println!("  {} - {}", id, description);
                let metadata = BuiltinFrameworkSource::metadata(id)?;
                println!(
                    "    rule pack {} | source {} | sha256 {}",
                    metadata.version, metadata.source.version, metadata.content_sha256
                );
                println!("    {}", metadata.source.url);
            }

            println!("\nUsage: cipherrun --compliance <FRAMEWORK_ID> <TARGET>");
            println!("Example: cipherrun --compliance pci-dss-v4 example.com:443");
            return Ok(CommandExit::success());
        }

        // Handle --db-config-example (generate example config and exit)
        if let Some(config_path) = &args.database.config_example {
            use cipherrun::db::DatabaseConfig;
            let started = std::time::Instant::now();
            let result = DatabaseConfig::create_example_config(config_path);
            command_failure_logged |= log_cli_operation(
                "create_database_config_example",
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                &result,
            );
            result?;
            println!(
                "✓ Example database configuration saved to: {}",
                config_path.display()
            );
            return Ok(CommandExit::success());
        }

        // Handle --show-ciphers (list ciphers and exit)
        if args.scan.show_ciphers {
            use cipherrun::data::cipher_db;
            println!(
                "CipherRun v{} - Supported Cipher Suites\n",
                env!("CARGO_PKG_VERSION")
            );

            let all_ciphers = cipher_db()?.get_all_ciphers();
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
            let started = std::time::Instant::now();
            let result = (|| {
                let openssl = if let Some(path) = &args.tls.openssl_path {
                    OpenSslClient::with_path(path.as_os_str())
                } else {
                    OpenSslClient::new()
                };

                println!("OpenSSL: {}", openssl.get_version()?);
                for cipher in openssl.list_local_ciphers()? {
                    println!("{}", cipher);
                }

                Ok(CommandExit::success())
            })();
            command_failure_logged |= log_cli_operation(
                "list_local_openssl_ciphers",
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                &result,
            );
            return result;
        }

        // Validate routing before creating command
        CommandRouter::validate_routing(&args)?;

        // Route to appropriate command and execute
        let command = CommandRouter::route(args)?;
        let operation = command.name();
        let start = std::time::Instant::now();
        let command_span = tracing::info_span!("cli.command", operation);
        let result = command.execute().instrument(command_span).await;
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(exit) => info!(
                event_name = "cli.command.finished",
                operation,
                duration_ms,
                exit_code = exit.code(),
                outcome = "complete",
            ),
            Err(error) => {
                command_failure_logged = true;
                tracing::error!(
                    event_name = "cli.command.failed",
                    operation,
                    duration_ms,
                    error_type = "TlsError",
                    error_code = error.observability_code(),
                    outcome = "error",
                );
            }
        }
        result
    }
    .await;
    if let Err(error) = &result
        && !command_failure_logged
    {
        tracing::error!(
            event_name = "cli.failed",
            error_type = "TlsError",
            error_code = error.observability_code(),
            "CLI command failed"
        );
    }
    result
}

fn log_cli_operation<T>(
    operation: &'static str,
    duration_ms: u64,
    result: &cipherrun::Result<T>,
) -> bool {
    match result {
        Ok(_) => {
            info!(
                event_name = "cli.operation.completed",
                operation,
                duration_ms,
                outcome = "success",
                "CLI operation completed"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                event_name = "cli.operation.failed",
                operation,
                duration_ms,
                error_type = "TlsError",
                error_code = error.observability_code(),
                outcome = "error",
                "CLI operation failed"
            );
            true
        }
    }
}

async fn run_starttls_only(args: &Args) -> cipherrun::Result<CommandExit> {
    use cipherrun::starttls::StarttlsTester;
    use cipherrun::utils::network::{Target, split_target_host_port};

    let request = args.to_scan_request()?;
    let protocol =
        request
            .starttls_protocol()
            .ok_or_else(|| cipherrun::TlsError::InvalidInput {
                message: "--starttls-only requires a STARTTLS protocol".to_string(),
            })?;
    let target_input =
        request
            .target
            .as_deref()
            .ok_or_else(|| cipherrun::TlsError::InvalidInput {
                message: "--starttls-only requires a target".to_string(),
            })?;
    let (hostname, embedded_port) = split_target_host_port(target_input)?;
    let port = request
        .port
        .or(embedded_port)
        .or_else(|| request.starttls_port());
    let target = if let Some(ip_override) = request.ip.as_deref() {
        let ip = ip_override
            .parse()
            .map_err(|_| cipherrun::TlsError::InvalidInput {
                message: format!("Invalid IP override: {ip_override}"),
            })?;
        Target::with_ips(hostname, port.unwrap_or(protocol.default_port()), vec![ip])?
    } else {
        Target::parse_with_port_override_and_private(
            target_input,
            port,
            request.network.permits_private_resolution(),
        )
        .await?
    };
    request
        .network
        .validate_resolved_ips(&target.ip_addresses)?;

    let result = StarttlsTester::new(target)
        .with_server_mode(request.starttls_server_mode())
        .test_protocol(protocol)
        .await;
    let encoded = if args.output.json_pretty {
        serde_json::to_string_pretty(&result)?
    } else {
        serde_json::to_string(&result)?
    };
    if let Some(path) = &args.output.json {
        std::fs::write(path, format!("{encoded}\n"))?;
    } else {
        println!("{encoded}");
    }

    Ok(if result.starttls_supported {
        CommandExit::success()
    } else {
        CommandExit::failure(CommandExit::OPERATIONAL_FAILURE)
    })
}

fn color_output_enabled(mode: u8) -> bool {
    mode != 0
}

fn apply_output_preferences(args: &Args) {
    control::set_override(color_output_enabled(args.output.color));
}

#[cfg(test)]
mod tests {
    use super::color_output_enabled;

    #[test]
    fn test_color_output_enabled() {
        assert!(!color_output_enabled(0));
        assert!(color_output_enabled(1));
        assert!(color_output_enabled(2));
        assert!(color_output_enabled(3));
    }
}
