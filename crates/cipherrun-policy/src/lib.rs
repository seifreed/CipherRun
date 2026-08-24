//! Dependency-light policy contracts shared by CipherRun consumers.

use serde::{Deserialize, Serialize};

/// Policy action to take when a rule is violated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "INFO")]
    Info,
}

impl PolicyAction {
    pub fn is_failure(&self) -> bool {
        matches!(self, PolicyAction::Fail)
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, PolicyAction::Warn)
    }
}

/// Complete policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<ProtocolPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<CipherPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<CertificatePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<VulnerabilityPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating: Option<RatingPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<CompliancePolicy>,
    #[serde(default)]
    pub exceptions: Vec<PolicyException>,
}

/// Protocol policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Cipher suite policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_strength: Option<String>, // LOW, MEDIUM, HIGH
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_forward_secrecy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_aead: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_patterns: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Certificate policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_signature_algorithms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_valid_trust_chain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_san: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_hostname_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_revocation_check: Option<bool>,
    pub action: PolicyAction,
}

/// Vulnerability policy requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_critical: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_high: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_medium: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited: Option<Vec<String>>,
    pub action: PolicyAction,
}

/// Rating policy requirements (SSL Labs style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_grade: Option<String>, // A+, A, A-, B, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score: Option<u32>,
    pub action: PolicyAction,
}

/// Compliance framework policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicy {
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub require_all: bool,
    pub action: PolicyAction,
}

/// Policy exception for specific targets or rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>, // Supports wildcards: *.example.com
    pub rules: Vec<String>, // Rule paths: "protocols.prohibited"
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>, // YYYY-MM-DD format
    pub approved_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}
