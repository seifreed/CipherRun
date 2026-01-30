// Vulnerabilities module - Vulnerability checks

pub mod aggregation;

pub use aggregation::merge_vulnerability_result;

use serde::{Deserialize, Serialize};

/// Vulnerability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityType {
    Heartbleed,
    CCSInjection,
    Ticketbleed,
    ROBOT,
    POODLE,
    POODLEtls,
    BEAST,
    CRIME,
    BREACH,
    SWEET32,
    FREAK,
    LOGJAM,
    DROWN,
    LUCKY13,
    Renegotiation,
    TLSFallback,
    RC4,
    Winshock,
    StarttlsInjection,
    Opossum,
    EarlyDataReplay,
    PaddingOracle2016, // CVE-2016-2107
    ZombiePoodle,      // CVE-2019-5592 - Observable MAC validity oracle
    GoldenDoodle,      // CVE-2019-5592 - Padding oracle via error differentiation
    SleepingPoodle,    // CVE-2019-5592 - Timing-based padding oracle
    OpenSsl0Length,    // CVE-2011-4576 - Zero-length TLS fragment vulnerability
}

/// Vulnerability test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    pub vuln_type: VulnerabilityType,
    pub vulnerable: bool,
    pub details: String,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub severity: Severity,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns a colored string representation for terminal display
    pub fn colored_display(&self) -> colored::ColoredString {
        use colored::Colorize;
        match self {
            Self::Critical => "CRITICAL".red().bold(),
            Self::High => "HIGH".red(),
            Self::Medium => "MEDIUM".yellow(),
            Self::Low => "LOW".normal(),
            Self::Info => "INFO".cyan(),
        }
    }
}

pub mod beast;
pub mod breach;
pub mod ccs;
pub mod crime;
pub mod debian_keys;
pub mod drown;
pub mod early_data;
pub mod freak;
pub mod grease;
pub mod heartbleed;
pub mod logjam;
pub mod lucky13;
pub mod opossum;
pub mod padding_oracle_2016;
pub mod poodle;
pub mod robot;
pub mod starttls_injection;
pub mod sweet32;
pub mod tester;
pub mod ticketbleed;
pub mod winshock;
