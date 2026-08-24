//! Stable, dependency-light contracts shared by CipherRun consumers.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    ActiveProbe,
    ProtocolNegotiation,
    ConfigurationInference,
    TimingAnalysis,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    Low,
    Medium,
    High,
}

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
    PaddingOracle2016,
    ZombiePoodle,
    GoldenDoodle,
    SleepingPoodle,
    OpenSsl0Length,
    GREASE,
}

impl VulnerabilityType {
    pub const fn sort_key(self) -> u8 {
        match self {
            Self::Heartbleed => 0,
            Self::CCSInjection => 1,
            Self::POODLE => 10,
            Self::POODLEtls => 11,
            Self::DROWN => 12,
            Self::ROBOT => 13,
            Self::FREAK => 14,
            Self::LOGJAM => 15,
            Self::Ticketbleed => 16,
            Self::LUCKY13 => 17,
            Self::PaddingOracle2016 => 18,
            Self::ZombiePoodle => 19,
            Self::GoldenDoodle => 20,
            Self::SleepingPoodle => 21,
            Self::OpenSsl0Length => 22,
            Self::CRIME => 30,
            Self::BREACH => 31,
            Self::BEAST => 40,
            Self::Renegotiation => 41,
            Self::TLSFallback => 42,
            Self::EarlyDataReplay => 43,
            Self::RC4 => 50,
            Self::SWEET32 => 51,
            Self::NullCipher => 52,
            Self::Winshock => 60,
            Self::StarttlsInjection => 61,
            Self::Opossum => 62,
            Self::GREASE => 70,
        }
    }

    pub const fn finding_id(self) -> &'static str {
        match self {
            Self::Heartbleed => "CR-TLS-HEARTBLEED-001",
            Self::CCSInjection => "CR-TLS-CCS-INJECTION-001",
            Self::Ticketbleed => "CR-TLS-TICKETBLEED-001",
            Self::ROBOT => "CR-TLS-ROBOT-001",
            Self::POODLE => "CR-TLS-POODLE-001",
            Self::POODLEtls => "CR-TLS-POODLE-TLS-001",
            Self::BEAST => "CR-TLS-BEAST-001",
            Self::CRIME => "CR-TLS-CRIME-001",
            Self::BREACH => "CR-TLS-BREACH-001",
            Self::SWEET32 => "CR-TLS-SWEET32-001",
            Self::FREAK => "CR-TLS-FREAK-001",
            Self::LOGJAM => "CR-TLS-LOGJAM-001",
            Self::DROWN => "CR-TLS-DROWN-001",
            Self::LUCKY13 => "CR-TLS-LUCKY13-001",
            Self::Renegotiation => "CR-TLS-RENEGOTIATION-001",
            Self::TLSFallback => "CR-TLS-FALLBACK-SCSV-001",
            Self::RC4 => "CR-TLS-RC4-001",
            Self::NullCipher => "CR-TLS-NULL-CIPHER-001",
            Self::Winshock => "CR-TLS-WINSHOCK-001",
            Self::StarttlsInjection => "CR-TLS-STARTTLS-INJECTION-001",
            Self::Opossum => "CR-TLS-OPOSSUM-001",
            Self::EarlyDataReplay => "CR-TLS-EARLY-DATA-REPLAY-001",
            Self::PaddingOracle2016 => "CR-TLS-PADDING-ORACLE-2016-001",
            Self::ZombiePoodle => "CR-TLS-ZOMBIE-POODLE-001",
            Self::GoldenDoodle => "CR-TLS-GOLDEN-DOODLE-001",
            Self::SleepingPoodle => "CR-TLS-SLEEPING-POODLE-001",
            Self::OpenSsl0Length => "CR-TLS-OPENSSL-ZERO-LENGTH-001",
            Self::GREASE => "CR-TLS-GREASE-INTOLERANCE-001",
        }
    }

    pub const fn detection_method(self) -> DetectionMethod {
        match self {
            Self::LUCKY13 | Self::SleepingPoodle => DetectionMethod::TimingAnalysis,
            Self::BREACH => DetectionMethod::Heuristic,
            Self::BEAST
            | Self::CRIME
            | Self::SWEET32
            | Self::FREAK
            | Self::LOGJAM
            | Self::Renegotiation
            | Self::TLSFallback
            | Self::RC4
            | Self::NullCipher
            | Self::GREASE => DetectionMethod::ProtocolNegotiation,
            Self::EarlyDataReplay => DetectionMethod::ConfigurationInference,
            _ => DetectionMethod::ActiveProbe,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub affected_ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub sni: Option<String>,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub observed: String,
    pub expected_result: String,
    pub attempts: Option<u32>,
    pub probe_version: String,
    pub limitations: Vec<String>,
    pub references: Vec<String>,
    pub remediation: String,
    pub potentially_intrusive: bool,
}

#[cfg(test)]
mod tests {
    use super::VulnerabilityType;
    use std::collections::HashSet;

    #[test]
    fn finding_ids_are_stable_and_unique() {
        let types = [
            VulnerabilityType::Heartbleed,
            VulnerabilityType::CCSInjection,
            VulnerabilityType::Ticketbleed,
            VulnerabilityType::ROBOT,
            VulnerabilityType::POODLE,
            VulnerabilityType::POODLEtls,
            VulnerabilityType::BEAST,
            VulnerabilityType::CRIME,
            VulnerabilityType::BREACH,
            VulnerabilityType::SWEET32,
            VulnerabilityType::FREAK,
            VulnerabilityType::LOGJAM,
            VulnerabilityType::DROWN,
            VulnerabilityType::LUCKY13,
            VulnerabilityType::Renegotiation,
            VulnerabilityType::TLSFallback,
            VulnerabilityType::RC4,
            VulnerabilityType::NullCipher,
            VulnerabilityType::Winshock,
            VulnerabilityType::StarttlsInjection,
            VulnerabilityType::Opossum,
            VulnerabilityType::EarlyDataReplay,
            VulnerabilityType::PaddingOracle2016,
            VulnerabilityType::ZombiePoodle,
            VulnerabilityType::GoldenDoodle,
            VulnerabilityType::SleepingPoodle,
            VulnerabilityType::OpenSsl0Length,
            VulnerabilityType::GREASE,
        ];
        let ids: HashSet<_> = types
            .into_iter()
            .map(VulnerabilityType::finding_id)
            .collect();
        assert_eq!(ids.len(), types.len());
        assert!(ids.iter().all(|id| id.starts_with("CR-TLS-")));
    }
}
