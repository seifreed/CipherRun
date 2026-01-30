// Compliance framework configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

/// Compliance framework evaluation options
///
/// This struct contains all arguments related to compliance framework
/// evaluation (PCI-DSS, NIST, HIPAA, SOC2, Mozilla, GDPR) and
/// policy-as-code enforcement.
#[derive(Args, Debug, Clone, Default)]
pub struct ComplianceArgs {
    /// Compliance framework to evaluate against (pci-dss-v4, nist-sp800-52r2, hipaa, soc2, mozilla-modern, mozilla-intermediate, gdpr)
    #[arg(long = "compliance", value_name = "FRAMEWORK")]
    pub framework: Option<String>,

    /// Compliance report output format (terminal, json, csv, html)
    #[arg(
        long = "compliance-format",
        value_name = "FORMAT",
        default_value = "terminal"
    )]
    pub format: String,

    /// List available compliance frameworks and exit
    #[arg(long = "list-compliance")]
    pub list_frameworks: bool,

    /// Policy file to enforce (YAML format)
    #[arg(long = "policy", value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Exit with non-zero code if policy violations found (for CI/CD)
    #[arg(long = "enforce")]
    pub enforce: bool,

    /// Policy output format (terminal, json, csv)
    #[arg(
        long = "policy-format",
        value_name = "FORMAT",
        default_value = "terminal"
    )]
    pub policy_format: String,

    /// Filter findings by minimum severity (low, medium, high, critical)
    #[arg(long = "severity", value_name = "LEVEL")]
    pub severity: Option<String>,
}
