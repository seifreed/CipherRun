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
    #[arg(long = "self-signed", short = 's')]
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
