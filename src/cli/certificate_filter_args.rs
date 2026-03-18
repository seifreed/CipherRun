// Certificate filter configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// Certificate validation filter options
///
/// This struct contains all arguments related to filtering scan results
/// based on certificate validation status. These filters are useful for
/// identifying specific certificate issues in mass scanning scenarios.
#[derive(Args, Debug, Clone, Default)]
pub struct CertificateFilterArgs {
    /// Filter: Show only expired certificates
    #[arg(long = "expired", short = 'x')]
    pub filter_expired: bool,

    /// Filter: Show only self-signed certificates
    #[arg(long = "self-signed")]
    pub filter_self_signed: bool,

    /// Filter: Show only hostname mismatched certificates
    #[arg(long = "mismatched", short = 'm')]
    pub filter_mismatched: bool,

    /// Filter: Show only revoked certificates
    #[arg(long = "revoked", short = 'r')]
    pub filter_revoked: bool,

    /// Filter: Show only untrusted certificates
    #[arg(long = "untrusted", short = 'u')]
    pub filter_untrusted: bool,

    /// Output only unique domain names from certificates
    #[arg(long = "dns", alias = "dns-only")]
    pub dns_only: bool,

    /// Output response data only (no host:port prefix)
    #[arg(long = "response-only", alias = "ro")]
    pub response_only: bool,
}

impl CertificateFilterArgs {
    /// Check if any certificate validation filters are active
    ///
    /// Returns true if at least one certificate filter flag is set,
    /// indicating that scan results should be filtered based on certificate validation status
    pub fn has_filters(&self) -> bool {
        self.filter_expired
            || self.filter_self_signed
            || self.filter_mismatched
            || self.filter_revoked
            || self.filter_untrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: CertificateFilterArgs,
    }

    #[test]
    fn test_certificate_filter_args_has_filters() {
        let parsed = TestCli::parse_from(["test"]);
        let args = parsed.args;

        assert!(!args.has_filters());

        let parsed = TestCli::parse_from(["test", "--expired"]);
        let args = parsed.args;
        assert!(args.has_filters());
        assert!(args.filter_expired);
    }

    #[test]
    fn test_certificate_filter_args_response_only() {
        let parsed = TestCli::parse_from(["test", "--response-only"]);
        let args = parsed.args;

        assert!(args.response_only);
        assert!(!args.dns_only);
    }

    #[test]
    fn test_certificate_filter_args_dns_only() {
        let parsed = TestCli::parse_from(["test", "--dns-only"]);
        let args = parsed.args;

        assert!(args.dns_only);
        assert!(!args.response_only);
    }
}
