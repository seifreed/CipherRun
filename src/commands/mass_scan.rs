// MassScanCommand - Mass scanning from input file
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use super::scan_exporter::{ExportKind, ScanExporter};
use super::{Command, CommandExit};
use crate::application::ScanRequest;
use crate::input::AsnCidrParser;
use crate::scanner::mass::{MassScanConfig, MassScanner};
use crate::{Args, Result, TlsError};
use async_trait::async_trait;
use colored::Colorize;
use std::net::IpAddr;
use tracing::info;

/// Upper bound on the number of hosts a single `--asn`/`--cidr` expansion may
/// produce. This guards against accidentally launching millions of TLS
/// handshakes (e.g. `--cidr 10.0.0.0/8`). Narrow the range or split the run to
/// scan beyond this limit.
const MAX_EXPANDED_TARGETS: u64 = 65_536;

/// MassScanCommand handles mass scanning from an input file
///
/// This command is responsible for:
/// - Loading targets from an input file
/// - Scanning multiple targets in parallel or serial mode
/// - Applying certificate validation filters
/// - Generating summary reports
/// - Exporting collection results to JSON
pub struct MassScanCommand {
    args: Args,
}

impl MassScanCommand {
    /// Create a new MassScanCommand with the given arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    /// Port applied to expanded CIDR/ASN host addresses.
    fn scan_port(&self) -> u16 {
        self.args.port.unwrap_or(crate::constants::PORT_HTTPS)
    }

    /// Format an expanded host address as a scan target, bracketing IPv6.
    fn format_ip_target(ip: IpAddr, port: u16) -> String {
        match ip {
            IpAddr::V4(_) => format!("{ip}:{port}"),
            IpAddr::V6(_) => format!("[{ip}]:{port}"),
        }
    }

    /// Reject empty or oversized range expansions before scanning.
    fn guard_target_count(total: u64) -> Result<()> {
        if total == 0 {
            return Err(TlsError::InvalidInput {
                message: "Range expansion produced no targets to scan".to_string(),
            });
        }
        if total > MAX_EXPANDED_TARGETS {
            return Err(TlsError::InvalidInput {
                message: format!(
                    "Range expands to {total} hosts, above the safety limit of {MAX_EXPANDED_TARGETS}. Use a smaller CIDR prefix or split the scan across runs."
                ),
            });
        }
        Ok(())
    }

    /// Build the mass scanner from the active target source (--file, --cidr, or
    /// --asn) and return it alongside a human-readable source label.
    async fn build_mass_scanner(
        &self,
        request: ScanRequest,
        config: MassScanConfig,
    ) -> Result<(MassScanner, String)> {
        if let Some(input_file) = self.args.input_file.as_ref() {
            let input_file_str = input_file.to_str().ok_or_else(|| TlsError::InvalidInput {
                message: "Invalid input file path".to_string(),
            })?;
            let scanner = MassScanner::from_file(request, config, input_file_str)?;
            return Ok((scanner, format!("file {}", input_file.display())));
        }

        if let Some(cidr) = self.args.cidr.as_deref() {
            let expansion = AsnCidrParser::expand_cidr(cidr)?;
            Self::guard_target_count(expansion.total_ips())?;
            let port = self.scan_port();
            let targets = expansion
                .iter()
                .map(|ip| Self::format_ip_target(ip, port))
                .collect();
            return Ok((
                MassScanner::new(request, config, targets),
                format!("CIDR {cidr}"),
            ));
        }

        if let Some(asn) = self.args.asn.as_deref() {
            let networks = AsnCidrParser::expand_asn(asn).await?;
            // Re-expand each announced prefix through the shared CIDR logic so
            // the per-prefix host count and iteration stay consistent.
            let expansions = networks
                .iter()
                .map(|network| AsnCidrParser::expand_cidr(&network.to_string()))
                .collect::<Result<Vec<_>>>()?;
            let total = expansions.iter().fold(0u64, |acc, expansion| {
                acc.saturating_add(expansion.total_ips())
            });
            Self::guard_target_count(total)?;
            let port = self.scan_port();
            let targets = expansions
                .iter()
                .flat_map(|expansion| expansion.iter())
                .map(|ip| Self::format_ip_target(ip, port))
                .collect();
            return Ok((
                MassScanner::new(request, config, targets),
                format!("{} ({} announced prefixes)", asn, networks.len()),
            ));
        }

        Err(TlsError::InvalidInput {
            message: "Mass scanning requires --file, --asn, or --cidr".to_string(),
        })
    }
}

#[async_trait]
impl Command for MassScanCommand {
    async fn execute(&self) -> Result<CommandExit> {
        let scan_request = self.args.to_scan_request();
        let certificate_filters = self.args.to_certificate_filters();
        let config = MassScanConfig {
            max_parallel: self.args.network.max_parallel,
            certificate_filters: certificate_filters.clone(),
        };

        let (mass_scanner, source) = self.build_mass_scanner(scan_request, config).await?;

        info!(
            "Loaded {} targets from {}",
            mass_scanner.targets.len(),
            source
        );

        let results = if self.args.network.parallel {
            mass_scanner.scan_parallel().await?
        } else {
            mass_scanner.scan_serial().await?
        };

        // Apply certificate filters if active
        let filtered_results = MassScanner::filter_results(&certificate_filters, results);

        // Display filter status if filters were applied
        if certificate_filters.has_filters() && !self.args.output.quiet {
            println!(
                "\n{} Applied certificate filters: {}",
                "".cyan(),
                certificate_filters.active_filter_names().join(", ")
            );
            println!(
                "{} Showing {} of {} targets that match filter criteria\n",
                "".cyan(),
                filtered_results.len(),
                mass_scanner.targets.len()
            );
        }

        if !self.args.output.quiet {
            println!("{}", MassScanner::generate_summary(&filtered_results));
        }

        // Export if requested (use filtered results)
        let exporter = ScanExporter::new(&self.args);
        if let Some(json_file) = exporter.collection_json_output_path() {
            use serde_json::json;

            let json_results: Vec<_> = filtered_results
                .iter()
                .map(|(target, result)| {
                    json!({
                        "target": target,
                        "success": result.is_ok(),
                        "results": result.as_ref().ok(),
                        "error": result.as_ref().err().map(|e| e.to_string()),
                    })
                })
                .collect();

            let json_data = json!({
                "scan_type": "mass_scan",
                "total_targets": filtered_results.len(),
                "successful_scans": filtered_results.iter().filter(|(_, r)| r.is_ok()).count(),
                "failed_scans": filtered_results.iter().filter(|(_, r)| r.is_err()).count(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "results": json_results,
            });

            let json = if self.args.output.json_pretty {
                serde_json::to_string_pretty(&json_data)?
            } else {
                serde_json::to_string(&json_data)?
            };
            exporter.write_text_file(&json_file, &json, "JSON", ExportKind::Json)?;
        }

        Ok(CommandExit::success())
    }

    fn name(&self) -> &'static str {
        "MassScanCommand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mass_scan_command_name() {
        let cmd = MassScanCommand::new(Args::default());
        assert_eq!(cmd.name(), "MassScanCommand");
    }

    #[tokio::test]
    async fn test_mass_scan_requires_a_target_source() {
        let args = Args::default();
        let cmd = MassScanCommand::new(args);
        let err = cmd.execute().await.unwrap_err();
        assert!(format!("{err}").contains("requires --file, --asn, or --cidr"));
    }

    #[test]
    fn test_format_ip_target_brackets_ipv6_only() {
        let v4: IpAddr = "192.0.2.7".parse().expect("valid v4");
        let v6: IpAddr = "2001:db8::1".parse().expect("valid v6");
        assert_eq!(MassScanCommand::format_ip_target(v4, 443), "192.0.2.7:443");
        assert_eq!(
            MassScanCommand::format_ip_target(v6, 8443),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn test_guard_target_count_rejects_empty_and_oversized() {
        assert!(MassScanCommand::guard_target_count(0).is_err());
        assert!(MassScanCommand::guard_target_count(MAX_EXPANDED_TARGETS).is_ok());
        assert!(MassScanCommand::guard_target_count(MAX_EXPANDED_TARGETS + 1).is_err());
    }

    #[tokio::test]
    async fn test_build_mass_scanner_expands_cidr_to_host_targets() {
        let args = Args {
            cidr: Some("192.0.2.0/30".to_string()),
            ..Default::default()
        };
        let cmd = MassScanCommand::new(args);

        let (scanner, source) = match cmd
            .build_mass_scanner(ScanRequest::default(), MassScanConfig::default())
            .await
        {
            Ok(built) => built,
            Err(e) => panic!("CIDR expansion should succeed: {e}"),
        };

        assert_eq!(source, "CIDR 192.0.2.0/30");
        assert_eq!(scanner.targets.len(), 4);
        assert!(scanner.targets.contains(&"192.0.2.0:443".to_string()));
        assert!(scanner.targets.contains(&"192.0.2.3:443".to_string()));
    }

    #[tokio::test]
    async fn test_build_mass_scanner_honors_port_override_for_cidr() {
        let args = Args {
            cidr: Some("198.51.100.5/32".to_string()),
            port: Some(8443),
            ..Default::default()
        };
        let cmd = MassScanCommand::new(args);

        let (scanner, _) = match cmd
            .build_mass_scanner(ScanRequest::default(), MassScanConfig::default())
            .await
        {
            Ok(built) => built,
            Err(e) => panic!("CIDR expansion should succeed: {e}"),
        };

        assert_eq!(scanner.targets, vec!["198.51.100.5:8443".to_string()]);
    }

    #[tokio::test]
    async fn test_build_mass_scanner_rejects_oversized_cidr() {
        let args = Args {
            cidr: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let cmd = MassScanCommand::new(args);

        let err = match cmd
            .build_mass_scanner(ScanRequest::default(), MassScanConfig::default())
            .await
        {
            Ok(_) => panic!("oversized CIDR must be rejected"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("safety limit"));
    }
}
