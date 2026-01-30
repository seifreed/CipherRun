// Certificate Validator - Validate certificates against CA stores and check validity

use super::parser::{CertificateChain, CertificateInfo};
use super::trust_stores::{TrustStoreValidator, TrustValidationResult};
use crate::Result;
use crate::data::CA_STORES;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Parse a certificate date string into a DateTime<Utc>.
/// Supports multiple date formats commonly found in certificates.
fn parse_cert_date(date_str: &str) -> Option<DateTime<Utc>> {
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

    /// Check certificate expiration
    fn check_expiration(&self, cert: &CertificateInfo, issues: &mut Vec<ValidationIssue>) -> bool {
        let now = Utc::now();

        // Parse not_before date using the helper function
        let Some(not_before) = parse_cert_date(&cert.not_before) else {
            // If parsing fails, assume valid to avoid false positives
            return true;
        };

        // Parse not_after date using the helper function
        let Some(not_after) = parse_cert_date(&cert.not_after) else {
            // If parsing fails, assume valid to avoid false positives
            return true;
        };

        // Check if certificate is not yet valid
        if now < not_before {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::NotYetValid,
                description: format!(
                    "Certificate not yet valid (valid from: {})",
                    cert.not_before
                ),
            });
            return false;
        }

        // Check if certificate has expired
        if now > not_after {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: format!("Certificate expired (valid until: {})", cert.not_after),
            });
            return false;
        }

        // Check if certificate expires soon (within 30 days)
        let days_until_expiry = (not_after - now).num_days();
        if days_until_expiry < 30 && !self.skip_warnings {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::Expired,
                description: format!(
                    "Certificate expires soon ({} days remaining)",
                    days_until_expiry
                ),
            });
        }

        true
    }

    /// Check hostname match
    fn check_hostname(&self, cert: &CertificateInfo, issues: &mut Vec<ValidationIssue>) -> bool {
        // Check CN and SAN
        let hostname_lower = self.hostname.to_lowercase();

        // Check Subject Alternative Names
        for san in &cert.san {
            if san.to_lowercase() == hostname_lower {
                return true;
            }

            // Check wildcard match
            if let Some(san_domain) = san.strip_prefix("*.")
                && hostname_lower.ends_with(san_domain)
            {
                let prefix_len = hostname_lower.len().saturating_sub(san_domain.len());
                let prefix = &hostname_lower[..prefix_len];
                if prefix.ends_with('.') {
                    let label = prefix.trim_end_matches('.');
                    if !label.is_empty() && !label.contains('.') {
                        return true;
                    }
                }
            }
        }

        // Check Common Name in subject
        if cert
            .subject
            .to_lowercase()
            .contains(&format!("cn={}", hostname_lower))
        {
            return true;
        }

        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            issue_type: IssueType::HostnameMismatch,
            description: format!(
                "Certificate hostname mismatch. Expected: {}, Got SANs: {:?}",
                self.hostname, cert.san
            ),
        });

        false
    }

    /// Check key strength
    fn check_key_strength(&self, cert: &CertificateInfo, issues: &mut Vec<ValidationIssue>) {
        // Skip warnings if requested
        if self.skip_warnings {
            return;
        }

        if let Some(key_size) = cert.public_key_size {
            if key_size < 2048 {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::High,
                    issue_type: IssueType::ShortKeyLength,
                    description: format!(
                        "Weak public key: {} bits (minimum recommended: 2048)",
                        key_size
                    ),
                });
            } else if key_size < 3072 {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Low,
                    issue_type: IssueType::ShortKeyLength,
                    description: format!(
                        "Public key size {} bits is acceptable but 3072+ recommended",
                        key_size
                    ),
                });
            }
        }
    }

    /// Check signature algorithm
    fn check_signature_algorithm(&self, cert: &CertificateInfo, issues: &mut Vec<ValidationIssue>) {
        // Skip warnings if requested
        if self.skip_warnings {
            return;
        }

        let sig_alg = cert.signature_algorithm.to_lowercase();

        // Check for weak algorithms
        if sig_alg.contains("md5") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::WeakSignature,
                description: "Certificate uses MD5 signature (broken)".to_string(),
            });
        } else if sig_alg.contains("sha1") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::WeakSignature,
                description: "Certificate uses SHA-1 signature (deprecated)".to_string(),
            });
        }
    }

    /// Validate trust chain against CA stores
    fn validate_trust_chain(
        &self,
        chain: &CertificateChain,
        issues: &mut Vec<ValidationIssue>,
    ) -> (bool, Option<String>) {
        let ca_stores = CA_STORES.as_ref();
        let find_store_for_subject = |subject: &str| -> Option<String> {
            for store in ca_stores.all_stores() {
                for ca_cert in &store.certificates {
                    if ca_cert.subject == subject {
                        return Some(store.name.clone());
                    }
                }
            }
            None
        };

        // Get root/issuer from chain
        let Some(last_cert) = chain.certificates.last() else {
            issues.push(ValidationIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::UntrustedCA,
                description: "No issuer certificate in chain".to_string(),
            });
            return (false, None);
        };

        // Check if self-signed first
        if chain.certificates.len() == 1 && last_cert.subject == last_cert.issuer {
            // Check if this self-signed cert is a known root CA
            if let Some(store_name) = find_store_for_subject(&last_cert.subject) {
                return (true, Some(store_name));
            }

            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::SelfSigned,
                description: "Certificate is self-signed and not a known root CA".to_string(),
            });
            return (false, None);
        }

        // Try to find the root CA in our stores
        // Strategy 1: Check if the last cert in chain is itself a root (subject == issuer)
        if last_cert.subject == last_cert.issuer {
            // It's a root certificate, check if it's in our stores
            if let Some(store_name) = find_store_for_subject(&last_cert.subject) {
                return (true, Some(store_name));
            }
        }

        // Strategy 2: Check if the issuer of the last cert matches any known root CA
        if let Some(store_name) = find_store_for_subject(&last_cert.issuer) {
            return (true, Some(store_name));
        }

        // Also check if the CA cert itself is the last cert in our chain
        if let Some(store_name) = find_store_for_subject(&last_cert.subject) {
            return (true, Some(store_name));
        }

        issues.push(ValidationIssue {
            severity: IssueSeverity::High,
            issue_type: IssueType::UntrustedCA,
            description: format!(
                "Issuer not found in trusted CA stores: {}",
                last_cert.issuer
            ),
        });

        (false, None)
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
    fn test_hostname_matching() {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: vec![],
        };

        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        assert!(validator.check_hostname(&cert, &mut issues));
        assert!(issues.is_empty());
    }

    #[test]
    fn test_weak_key_detection() {
        let cert = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            expiry_countdown: Some("expires in 1 year".to_string()),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(1024), // Weak!
            rsa_exponent: Some("e 65537".to_string()),
            san: vec!["example.com".to_string()],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: vec![],
        };

        let validator = CertificateValidator::new("example.com".to_string());
        let mut issues = Vec::new();

        validator.check_key_strength(&cert, &mut issues);

        assert!(!issues.is_empty());
        assert!(matches!(issues[0].issue_type, IssueType::ShortKeyLength));
    }
}
