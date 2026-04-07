// Certificate Validator - Validate certificates against CA stores and check validity

mod expiration;
mod hostname_match;
mod key_strength;
mod signature;
mod trust_chain;

use super::parser::{CertificateChain, CertificateInfo};
use super::trust_stores::{TrustStoreValidator, TrustValidationResult};
use crate::Result;
use crate::data::CA_STORES;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Parse a certificate date string into a DateTime<Utc>.
/// Supports multiple date formats commonly found in certificates.
pub fn parse_cert_date(date_str: &str) -> Option<DateTime<Utc>> {
    const FORMATS: &[&str] = &[
        "%b %d %H:%M:%S %Y %Z", // e.g., "Jan 01 00:00:00 2024 GMT"
        "%Y-%m-%d %H:%M:%S %z", // e.g., "2024-01-01 00:00:00 +00:00"
    ];

    for format in FORMATS {
        if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    None
}

/// Certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub trust_chain_valid: bool,
    pub hostname_match: bool,
    pub not_expired: bool,
    pub signature_valid: bool,
    pub trusted_ca: Option<String>,
    /// Multi-platform trust validation result
    pub platform_trust: Option<TrustValidationResult>,
}

/// Validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub issue_type: IssueType,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl IssueSeverity {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueType {
    Expired,
    NotYetValid,
    HostnameMismatch,
    SelfSigned,
    UntrustedCA,
    ChainIncomplete,
    WeakSignature,
    ShortKeyLength,
    MissingExtension,
}

/// Certificate validator
pub struct CertificateValidator {
    hostname: String,
    skip_warnings: bool,
    /// Optional trust store validator for multi-platform validation
    trust_validator: Option<TrustStoreValidator>,
}

impl CertificateValidator {
    /// Create new validator for a hostname
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            skip_warnings: false,
            trust_validator: None,
        }
    }

    /// Create validator with warning skip option
    pub fn with_skip_warnings(hostname: String, skip: bool) -> Self {
        Self {
            hostname,
            skip_warnings: skip,
            trust_validator: None,
        }
    }

    /// Create validator with multi-platform trust validation enabled
    pub fn with_platform_trust(hostname: String) -> Result<Self> {
        Ok(Self {
            hostname,
            skip_warnings: false,
            trust_validator: Some(TrustStoreValidator::new()?),
        })
    }

    /// Create validator with full configuration
    pub fn with_config(
        hostname: String,
        skip_warnings: bool,
        enable_platform_trust: bool,
    ) -> Result<Self> {
        Ok(Self {
            hostname,
            skip_warnings,
            trust_validator: if enable_platform_trust {
                Some(TrustStoreValidator::new()?)
            } else {
                None
            },
        })
    }

    /// Validate certificate chain
    pub fn validate_chain(&self, chain: &CertificateChain) -> Result<ValidationResult> {
        let mut issues = Vec::new();
        let mut valid = true;

        // Get leaf certificate
        let leaf = match chain.leaf() {
            Some(cert) => cert,
            None => {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Critical,
                    issue_type: IssueType::ChainIncomplete,
                    description: "No leaf certificate found".to_string(),
                });
                return Ok(ValidationResult {
                    valid: false,
                    issues,
                    trust_chain_valid: false,
                    hostname_match: false,
                    not_expired: false,
                    signature_valid: false,
                    trusted_ca: None,
                    platform_trust: None,
                });
            }
        };

        // 1. Check expiration
        let not_expired = self.check_expiration(leaf, &mut issues);
        valid &= not_expired;

        // 2. Check hostname
        let hostname_match = self.check_hostname(leaf, &mut issues);
        valid &= hostname_match;

        // 3. Check key strength
        self.check_key_strength(leaf, &mut issues);

        // 4. Check signature algorithm
        self.check_signature_algorithm(leaf, &mut issues);

        // 5. Validate trust chain
        let (trust_chain_valid, trusted_ca) = self.validate_trust_chain(chain, &mut issues);
        valid &= trust_chain_valid;

        // 6. Check chain completeness
        if !chain.is_complete() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::ChainIncomplete,
                description: "Certificate chain may be incomplete (no root CA)".to_string(),
            });
        }

        // 7. Perform multi-platform trust validation if enabled
        let platform_trust = if let Some(ref validator) = self.trust_validator {
            match validator.validate_chain(chain) {
                Ok(result) => Some(result),
                Err(e) => {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Info,
                        issue_type: IssueType::UntrustedCA,
                        description: format!("Platform trust validation failed: {}", e),
                    });
                    None
                }
            }
        } else {
            None
        };

        Ok(ValidationResult {
            valid,
            issues,
            trust_chain_valid,
            hostname_match,
            not_expired,
            signature_valid: true, // Simplified for now
            trusted_ca,
            platform_trust,
        })
    }
}

impl ValidationResult {
    /// Get summary text
    pub fn summary(&self) -> String {
        if self.valid {
            "Certificate is valid and trusted".to_string()
        } else {
            format!(
                "Certificate validation failed ({} issues)",
                self.issues.len()
            )
        }
    }

    /// Get critical issues
    pub fn critical_issues(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, IssueSeverity::Critical))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert_date_formats() {
        assert!(parse_cert_date("2024-01-01 00:00:00 +0000").is_some());
        assert!(parse_cert_date("not a date").is_none());
    }

    #[test]
    fn test_validation_result_summary_and_critical() {
        let result = ValidationResult {
            valid: false,
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: "expired".to_string(),
            }],
            trust_chain_valid: false,
            hostname_match: false,
            not_expired: false,
            signature_valid: false,
            trusted_ca: None,
            platform_trust: None,
        };
        assert!(result.summary().contains("1 issues"));
        assert_eq!(result.critical_issues().len(), 1);
    }
}
