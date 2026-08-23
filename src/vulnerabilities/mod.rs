// Vulnerabilities module - Vulnerability checks

pub mod aggregation;
pub(crate) mod handshake_read;

pub use aggregation::merge_vulnerability_result;
pub use aggregation::merge_vulnerability_result_with_error;

use serde::{Deserialize, Serialize};

/// Explicit verdict for a published security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    ConfirmedVulnerable,
    PotentialExposure,
    NotVulnerable,
    Inconclusive,
    NotApplicable,
    NotExecuted,
}

impl FindingStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConfirmedVulnerable => "Confirmed Vulnerable",
            Self::PotentialExposure => "Potential Exposure",
            Self::NotVulnerable => "Not Vulnerable",
            Self::Inconclusive => "Inconclusive",
            Self::NotApplicable => "Not Applicable",
            Self::NotExecuted => "Not Executed",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedVulnerable => "confirmed_vulnerable",
            Self::PotentialExposure => "potential_exposure",
            Self::NotVulnerable => "not_vulnerable",
            Self::Inconclusive => "inconclusive",
            Self::NotApplicable => "not_applicable",
            Self::NotExecuted => "not_executed",
        }
    }
}

/// How CipherRun obtained a finding verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    ActiveProbe,
    ProtocolNegotiation,
    ConfigurationInference,
    TimingAnalysis,
    Heuristic,
}

/// Confidence in a finding verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    Low,
    Medium,
    High,
}

/// Vulnerability types ordered by severity (most critical first)
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

impl VulnerabilityType {
    /// Returns a sort key for deterministic ordering by severity.
    /// Lower values = higher severity/criticality.
    pub fn sort_key(&self) -> u8 {
        match self {
            // Critical - Remote code execution / info disclosure
            VulnerabilityType::Heartbleed => 0,
            VulnerabilityType::CCSInjection => 1,
            // High - Authentication bypass / session hijacking
            VulnerabilityType::POODLE => 10,
            VulnerabilityType::POODLEtls => 11,
            VulnerabilityType::DROWN => 12,
            VulnerabilityType::ROBOT => 13,
            VulnerabilityType::FREAK => 14,
            VulnerabilityType::LOGJAM => 15,
            VulnerabilityType::Ticketbleed => 16,
            VulnerabilityType::LUCKY13 => 17,
            VulnerabilityType::PaddingOracle2016 => 18,
            VulnerabilityType::ZombiePoodle => 19,
            VulnerabilityType::GoldenDoodle => 20,
            VulnerabilityType::SleepingPoodle => 21,
            VulnerabilityType::OpenSsl0Length => 22,
            // Medium - Compression attacks
            VulnerabilityType::CRIME => 30,
            VulnerabilityType::BREACH => 31,
            // Medium - Protocol issues
            VulnerabilityType::BEAST => 40,
            VulnerabilityType::Renegotiation => 41,
            VulnerabilityType::TLSFallback => 42,
            VulnerabilityType::EarlyDataReplay => 43,
            // Low - Weak ciphers
            VulnerabilityType::RC4 => 50,
            VulnerabilityType::SWEET32 => 51,
            VulnerabilityType::NullCipher => 52,
            // Info - Configuration issues
            VulnerabilityType::Winshock => 60,
            VulnerabilityType::StarttlsInjection => 61,
            VulnerabilityType::Opossum => 62,
            VulnerabilityType::GREASE => 70,
        }
    }
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
    /// Returns the normalized finding verdict while legacy boolean producers
    /// are migrated to the explicit model.
    pub const fn status(&self) -> FindingStatus {
        match (self.vulnerable, self.inconclusive) {
            (true, false) => FindingStatus::ConfirmedVulnerable,
            (true, true) => FindingStatus::PotentialExposure,
            (false, true) => FindingStatus::Inconclusive,
            (false, false) if matches!(self.vuln_type, VulnerabilityType::GREASE) => {
                FindingStatus::NotApplicable
            }
            (false, false) => FindingStatus::NotVulnerable,
        }
    }

    pub const fn finding_id(&self) -> &'static str {
        match self.vuln_type {
            VulnerabilityType::Heartbleed => "CR-TLS-HEARTBLEED-001",
            VulnerabilityType::CCSInjection => "CR-TLS-CCS-INJECTION-001",
            VulnerabilityType::Ticketbleed => "CR-TLS-TICKETBLEED-001",
            VulnerabilityType::ROBOT => "CR-TLS-ROBOT-001",
            VulnerabilityType::POODLE => "CR-TLS-POODLE-001",
            VulnerabilityType::POODLEtls => "CR-TLS-POODLE-TLS-001",
            VulnerabilityType::BEAST => "CR-TLS-BEAST-001",
            VulnerabilityType::CRIME => "CR-TLS-CRIME-001",
            VulnerabilityType::BREACH => "CR-TLS-BREACH-001",
            VulnerabilityType::SWEET32 => "CR-TLS-SWEET32-001",
            VulnerabilityType::FREAK => "CR-TLS-FREAK-001",
            VulnerabilityType::LOGJAM => "CR-TLS-LOGJAM-001",
            VulnerabilityType::DROWN => "CR-TLS-DROWN-001",
            VulnerabilityType::LUCKY13 => "CR-TLS-LUCKY13-001",
            VulnerabilityType::Renegotiation => "CR-TLS-RENEGOTIATION-001",
            VulnerabilityType::TLSFallback => "CR-TLS-FALLBACK-SCSV-001",
            VulnerabilityType::RC4 => "CR-TLS-RC4-001",
            VulnerabilityType::NullCipher => "CR-TLS-NULL-CIPHER-001",
            VulnerabilityType::Winshock => "CR-TLS-WINSHOCK-001",
            VulnerabilityType::StarttlsInjection => "CR-TLS-STARTTLS-INJECTION-001",
            VulnerabilityType::Opossum => "CR-TLS-OPOSSUM-001",
            VulnerabilityType::EarlyDataReplay => "CR-TLS-EARLY-DATA-REPLAY-001",
            VulnerabilityType::PaddingOracle2016 => "CR-TLS-PADDING-ORACLE-2016-001",
            VulnerabilityType::ZombiePoodle => "CR-TLS-ZOMBIE-POODLE-001",
            VulnerabilityType::GoldenDoodle => "CR-TLS-GOLDEN-DOODLE-001",
            VulnerabilityType::SleepingPoodle => "CR-TLS-SLEEPING-POODLE-001",
            VulnerabilityType::OpenSsl0Length => "CR-TLS-OPENSSL-ZERO-LENGTH-001",
            VulnerabilityType::GREASE => "CR-TLS-GREASE-INTOLERANCE-001",
        }
    }

    pub const fn detection_method(&self) -> DetectionMethod {
        match self.vuln_type {
            VulnerabilityType::LUCKY13 | VulnerabilityType::SleepingPoodle => {
                DetectionMethod::TimingAnalysis
            }
            VulnerabilityType::BREACH => DetectionMethod::Heuristic,
            VulnerabilityType::BEAST
            | VulnerabilityType::CRIME
            | VulnerabilityType::SWEET32
            | VulnerabilityType::FREAK
            | VulnerabilityType::LOGJAM
            | VulnerabilityType::Renegotiation
            | VulnerabilityType::TLSFallback
            | VulnerabilityType::RC4
            | VulnerabilityType::NullCipher
            | VulnerabilityType::GREASE => DetectionMethod::ProtocolNegotiation,
            VulnerabilityType::EarlyDataReplay => DetectionMethod::ConfigurationInference,
            _ => DetectionMethod::ActiveProbe,
        }
    }

    pub const fn confidence(&self) -> FindingConfidence {
        match self.status() {
            FindingStatus::Inconclusive | FindingStatus::NotExecuted => FindingConfidence::Low,
            FindingStatus::PotentialExposure => FindingConfidence::Medium,
            FindingStatus::ConfirmedVulnerable | FindingStatus::NotVulnerable => {
                match self.detection_method() {
                    DetectionMethod::ActiveProbe | DetectionMethod::ProtocolNegotiation => {
                        FindingConfidence::High
                    }
                    DetectionMethod::ConfigurationInference
                    | DetectionMethod::TimingAnalysis
                    | DetectionMethod::Heuristic => FindingConfidence::Medium,
                }
            }
            FindingStatus::NotApplicable => FindingConfidence::High,
        }
    }

    pub fn status_label(&self) -> &'static str {
        self.status().label()
    }

    pub fn status_csv_value(&self) -> &'static str {
        self.status().as_str()
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
mod cipher_probe;
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
#[cfg(test)]
pub(crate) mod test_support;
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
    fn finding_status_distinguishes_potential_exposure() {
        let result = VulnerabilityResult {
            vuln_type: VulnerabilityType::BREACH,
            vulnerable: true,
            inconclusive: true,
            details: "prerequisites observed".to_string(),
            cve: Some("CVE-2013-3587".to_string()),
            cwe: Some("CWE-200".to_string()),
            severity: Severity::Medium,
        };

        assert_eq!(result.status(), FindingStatus::PotentialExposure);
        assert_eq!(result.status_csv_value(), "potential_exposure");
        assert_eq!(result.finding_id(), "CR-TLS-BREACH-001");
        assert_eq!(result.detection_method(), DetectionMethod::Heuristic);
        assert_eq!(result.confidence(), FindingConfidence::Medium);
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
