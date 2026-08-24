// Vulnerabilities module - Vulnerability checks

pub mod aggregation;
pub(crate) mod handshake_read;

pub use aggregation::merge_vulnerability_result;
pub use aggregation::merge_vulnerability_result_with_error;

use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

// Keep the public contract source-linked so the root package remains publishable
// before the independent cipherrun-core crate is released to crates.io.
#[path = "../core_contract.rs"]
mod cipherrun_core;

pub use cipherrun_core::{
    DetectionMethod, FindingConfidence, FindingEvidence, FindingStatus, VulnerabilityType,
};

/// Vulnerability test result
#[derive(Debug, Clone, Deserialize)]
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
        self.vuln_type.finding_id()
    }

    pub const fn detection_method(&self) -> DetectionMethod {
        self.vuln_type.detection_method()
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

    pub fn evidence(&self) -> FindingEvidence {
        let hint = crate::utils::hints::get_vulnerability_hint(&format!("{:?}", self.vuln_type))
            .unwrap_or_else(|| crate::utils::hints::get_severity_hint(self.severity));
        let mut references = hint.references;

        if let Some(cve) = &self.cve {
            let reference = format!("https://nvd.nist.gov/vuln/detail/{cve}");
            if !references.contains(&reference) {
                references.push(reference);
            }
        }
        if let Some(cwe) = self
            .cwe
            .as_deref()
            .and_then(|value| value.strip_prefix("CWE-"))
        {
            let reference = format!("https://cwe.mitre.org/data/definitions/{cwe}.html");
            if !references.contains(&reference) {
                references.push(reference);
            }
        }

        FindingEvidence {
            affected_ip: None,
            port: None,
            sni: None,
            protocol: None,
            cipher_suite: None,
            observed: self.details.clone(),
            expected_result: "No vulnerable behavior or exposure prerequisites observed."
                .to_string(),
            attempts: None,
            probe_version: env!("CARGO_PKG_VERSION").to_string(),
            limitations: vec![self.detection_limitation().to_string()],
            references,
            remediation: hint.remediation,
            potentially_intrusive: matches!(self.detection_method(), DetectionMethod::ActiveProbe),
        }
    }

    const fn detection_limitation(&self) -> &'static str {
        match self.detection_method() {
            DetectionMethod::ActiveProbe => {
                "The verdict applies only to the tested endpoint and probe version."
            }
            DetectionMethod::ProtocolNegotiation => {
                "Negotiated support does not identify the server implementation."
            }
            DetectionMethod::ConfigurationInference => {
                "Configuration exposure does not prove practical exploitability."
            }
            DetectionMethod::TimingAnalysis => {
                "Remote timing analysis is sensitive to latency and network jitter."
            }
            DetectionMethod::Heuristic => {
                "Observed prerequisites do not demonstrate practical exploitability."
            }
        }
    }

    pub fn status_label(&self) -> &'static str {
        self.status().label()
    }

    pub fn status_csv_value(&self) -> &'static str {
        self.status().as_str()
    }
}

impl Serialize for VulnerabilityResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("VulnerabilityResult", 12)?;
        state.serialize_field("finding_id", self.finding_id())?;
        state.serialize_field("status", &self.status())?;
        state.serialize_field("detection_method", &self.detection_method())?;
        state.serialize_field("confidence", &self.confidence())?;
        state.serialize_field("evidence", &self.evidence())?;
        state.serialize_field("vuln_type", &self.vuln_type)?;
        state.serialize_field("vulnerable", &self.vulnerable)?;
        state.serialize_field("inconclusive", &self.inconclusive)?;
        state.serialize_field("details", &self.details)?;
        state.serialize_field("cve", &self.cve)?;
        state.serialize_field("cwe", &self.cwe)?;
        state.serialize_field("severity", &self.severity)?;
        state.end()
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
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("serialized finding should be valid JSON");
        assert_eq!(value["finding_id"], "CR-TLS-HEARTBLEED-001");
        assert_eq!(value["status"], "confirmed_vulnerable");
        assert_eq!(value["detection_method"], "active_probe");
        assert_eq!(value["confidence"], "high");
        assert_eq!(
            value["evidence"]["probe_version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(value["evidence"]["attempts"], serde_json::Value::Null);
        assert_eq!(value["evidence"]["potentially_intrusive"], true);

        let round_trip: VulnerabilityResult =
            serde_json::from_str(&json).expect("enriched finding JSON should remain readable");
        assert_eq!(round_trip.status(), FindingStatus::ConfirmedVulnerable);
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
