// Vulnerabilities module - Vulnerability checks

pub mod aggregation;

pub use aggregation::merge_vulnerability_result;

use serde::{Deserialize, Serialize};

/// Vulnerability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    NullCipher,
    Winshock,
    StarttlsInjection,
    Opossum,
    EarlyDataReplay,
    PaddingOracle2016, // CVE-2016-2107
    ZombiePoodle,      // CVE-2019-5592 - Observable MAC validity oracle
    GoldenDoodle,      // CVE-2019-5592 - Padding oracle via error differentiation
    SleepingPoodle,    // CVE-2019-5592 - Timing-based padding oracle
    OpenSsl0Length,    // CVE-2011-4576 - Zero-length TLS fragment vulnerability
    GREASE,
}

/// Vulnerability test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    pub vuln_type: VulnerabilityType,
    pub vulnerable: bool,
    #[serde(default)]
    pub inconclusive: bool,
    pub details: String,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub severity: Severity,
}

impl VulnerabilityResult {
    pub fn status_label(&self) -> &'static str {
        if self.vulnerable {
            "Vulnerable"
        } else if self.inconclusive {
            "Inconclusive"
        } else {
            "Not Vulnerable"
        }
    }

    pub fn status_csv_value(&self) -> &'static str {
        if self.vulnerable {
            "vulnerable"
        } else if self.inconclusive {
            "inconclusive"
        } else {
            "not_vulnerable"
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_type_display_like() {
        let v = VulnerabilityType::Heartbleed;
        let serialized = serde_json::to_string(&v).expect("test assertion should succeed");
        assert!(serialized.contains("Heartbleed"));
    }

    #[test]
    fn test_severity_colored_display() {
        let display = Severity::High.colored_display().to_string();
        assert!(display.contains("HIGH"));
    }

    #[test]
    fn test_vulnerability_result_serialization() {
        let result = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: false,
            details: "details".to_string(),
            cve: Some("CVE-2014-0160".to_string()),
            cwe: None,
            severity: Severity::Critical,
        };

        let json = serde_json::to_string(&result).expect("test assertion should succeed");
        assert!(json.contains("Heartbleed"));
        assert!(json.contains("CVE-2014-0160"));
    }

    #[test]
    fn test_severity_display_info() {
        let display = Severity::Info.colored_display().to_string();
        assert!(display.contains("INFO"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
    }
}
