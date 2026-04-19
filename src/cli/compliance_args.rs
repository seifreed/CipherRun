// Compliance framework configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;
use std::path::PathBuf;

use crate::TlsError;
use crate::compliance::Severity;

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

    /// Filter compliance output by minimum requirement severity (low, medium, high, critical)
    #[arg(long = "severity", value_name = "LEVEL")]
    pub severity: Option<String>,
}

impl ComplianceArgs {
    pub const COMPLIANCE_OUTPUT_FORMATS: [&'static str; 4] = ["terminal", "json", "csv", "html"];
    pub const POLICY_OUTPUT_FORMATS: [&'static str; 3] = ["terminal", "json", "csv"];

    pub fn validate(&self) -> crate::Result<()> {
        Self::validate_format(
            "compliance format",
            &self.format,
            &Self::COMPLIANCE_OUTPUT_FORMATS,
        )?;
        Self::validate_format(
            "policy format",
            &self.policy_format,
            &Self::POLICY_OUTPUT_FORMATS,
        )?;
        let _ = self.minimum_severity()?;
        Ok(())
    }

    pub fn minimum_severity(&self) -> crate::Result<Option<Severity>> {
        self.severity
            .as_deref()
            .map(Self::parse_minimum_severity)
            .transpose()
    }

    fn parse_minimum_severity(value: &str) -> crate::Result<Severity> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(TlsError::InvalidInput {
                message: format!(
                    "Invalid compliance severity '{}'. Supported values: low, medium, high, critical",
                    other
                ),
            }),
        }
    }

    fn validate_format(label: &str, value: &str, allowed: &[&str]) -> crate::Result<()> {
        let normalized = value.trim().to_ascii_lowercase();
        if allowed.contains(&normalized.as_str()) {
            Ok(())
        } else {
            Err(TlsError::InvalidInput {
                message: format!(
                    "Invalid {} '{}'. Supported values: {}",
                    label,
                    value,
                    allowed.join(", ")
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ComplianceArgs,
    }

    #[test]
    fn test_compliance_args_defaults_from_clap() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(args.framework.is_none());
        assert_eq!(args.format, "terminal");
        assert!(!args.list_frameworks);
        assert!(args.policy.is_none());
        assert!(!args.enforce);
        assert_eq!(args.policy_format, "terminal");
        assert!(args.severity.is_none());
    }

    #[test]
    fn test_compliance_args_custom_values() {
        let parsed = TestCli::parse_from([
            "test",
            "--compliance",
            "pci-dss-v4",
            "--policy-format",
            "json",
            "--severity",
            "high",
        ]);
        let args = parsed.args;

        assert_eq!(args.framework.as_deref(), Some("pci-dss-v4"));
        assert_eq!(args.policy_format, "json");
        assert_eq!(args.severity.as_deref(), Some("high"));
    }

    #[test]
    fn test_validate_accepts_supported_formats_and_severity() {
        let args = ComplianceArgs {
            format: "JSON".to_string(),
            policy_format: "csv".to_string(),
            severity: Some("critical".to_string()),
            ..Default::default()
        };

        args.validate().expect("validation should succeed");
        assert_eq!(
            args.minimum_severity().expect("severity should parse"),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_validate_rejects_unknown_compliance_format() {
        let args = ComplianceArgs {
            format: "yaml".to_string(),
            ..Default::default()
        };

        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_unknown_policy_format() {
        let args = ComplianceArgs {
            policy_format: "xml".to_string(),
            ..Default::default()
        };

        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_unknown_severity() {
        let args = ComplianceArgs {
            severity: Some("info".to_string()),
            ..Default::default()
        };

        assert!(args.validate().is_err());
    }
}
