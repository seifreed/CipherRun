// Rule definitions and types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of compliance rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleType {
    /// Check protocol versions (allowed/denied lists)
    ProtocolVersion,
    /// Check cipher suites (pattern matching)
    CipherSuite,
    /// Check certificate key sizes
    CertificateKeySize,
    /// Check signature algorithms
    SignatureAlgorithm,
    /// Check forward secrecy support
    ForwardSecrecy,
    /// Check certificate validation
    CertificateValidation,
    /// Check certificate expiration
    CertificateExpiration,
    /// Check for vulnerabilities
    Vulnerability,
}

/// A rule that defines how to check compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Type of rule
    #[serde(rename = "type")]
    pub rule_type: String,

    /// Allowed values (for allow-list rules)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,

    /// Denied values (for deny-list rules)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,

    /// Patterns to match (regex patterns for cipher names, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_patterns: Vec<String>,

    /// Patterns to deny (regex patterns for weak ciphers, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_patterns: Vec<String>,

    /// Preferred patterns (not required, but recommended)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferred_patterns: Vec<String>,

    /// Minimum RSA key size in bits
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rsa_bits: Option<u32>,

    /// Minimum ECC key size in bits
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ecc_bits: Option<u32>,

    /// Whether forward secrecy is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Require valid certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_valid_chain: Option<bool>,

    /// Require unexpired certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_unexpired: Option<bool>,

    /// Require hostname match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_hostname_match: Option<bool>,

    /// Require successful revocation check with a non-revoked certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_revocation_check: Option<bool>,

    /// Maximum days until expiration (for early warning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_days_until_expiration: Option<i64>,

    /// Additional custom parameters
    #[serde(flatten)]
    pub custom_params: HashMap<String, serde_json::Value>,
}

impl Rule {
    /// Check if a value is allowed by this rule
    pub fn is_allowed(&self, value: &str) -> bool {
        if !self.allowed.is_empty() {
            list_contains_normalized(&self.allowed, value)
        } else {
            false // If no allow list, deny everything (fail-closed)
        }
    }

    /// Check if a value is denied by this rule
    pub fn is_denied(&self, value: &str) -> bool {
        if !self.denied.is_empty() {
            list_contains_normalized(&self.denied, value)
        } else {
            false
        }
    }

    /// Check if a value matches allowed patterns
    pub fn matches_allowed_pattern(&self, value: &str) -> bool {
        if self.allowed_patterns.is_empty() {
            return true;
        }

        for pattern in &self.allowed_patterns {
            match compile_rule_pattern(pattern) {
                Ok(re) => {
                    if re.is_match(value) {
                        return true;
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        event_name = "compliance.pattern.invalid",
                        pattern_kind = "allowed",
                        error_code = "invalid_pattern",
                        outcome = "fail_closed",
                        "Invalid compliance pattern"
                    );
                    return false;
                }
            }
        }
        false
    }

    /// Check if a value matches denied patterns
    ///
    /// Fails closed: an invalid regex in denied_patterns is treated as a match
    /// so a misconfigured rule cannot silently allow a forbidden value.
    pub fn matches_denied_pattern(&self, value: &str) -> bool {
        for pattern in &self.denied_patterns {
            match compile_rule_pattern(pattern) {
                Ok(re) => {
                    if re.is_match(value) {
                        return true;
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        event_name = "compliance.pattern.invalid",
                        pattern_kind = "denied",
                        error_code = "invalid_pattern",
                        outcome = "fail_closed",
                        "Invalid compliance pattern"
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Check if a value matches preferred patterns
    pub fn matches_preferred_pattern(&self, value: &str) -> bool {
        for pattern in &self.preferred_patterns {
            match compile_rule_pattern(pattern) {
                Ok(re) if re.is_match(value) => return true,
                Err(_) => tracing::warn!(
                    event_name = "compliance.pattern.invalid",
                    pattern_kind = "preferred",
                    error_code = "invalid_pattern",
                    outcome = "ignored",
                    "Invalid compliance pattern"
                ),
                _ => {}
            }
        }
        false
    }
}

fn compile_rule_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
}

fn list_contains_normalized(list: &[String], value: &str) -> bool {
    let value = value.trim();
    list.iter()
        .any(|configured| configured.trim().eq_ignore_ascii_case(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::test_support::base_rule;

    #[test]
    fn test_rule_allowed_list() {
        let rule = Rule {
            allowed: vec!["TLS 1.2".to_string(), "TLS 1.3".to_string()],
            ..base_rule("ProtocolVersion")
        };

        assert!(rule.is_allowed("TLS 1.2"));
        assert!(rule.is_allowed("TLS 1.3"));
        assert!(!rule.is_allowed("TLS 1.0"));
    }

    #[test]
    fn test_rule_denied_list() {
        let rule = Rule {
            denied: vec!["SSLv2".to_string(), "SSLv3".to_string()],
            ..base_rule("ProtocolVersion")
        };

        assert!(rule.is_denied("SSLv2"));
        assert!(rule.is_denied("SSLv3"));
        assert!(!rule.is_denied("TLS 1.2"));
    }

    #[test]
    fn test_rule_pattern_matching() {
        let rule = Rule {
            denied_patterns: vec![".*_NULL_.*".to_string(), ".*_EXPORT_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_denied_pattern("TLS_RSA_WITH_NULL_SHA"));
        assert!(rule.matches_denied_pattern("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"));
        assert!(!rule.matches_denied_pattern("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    }

    #[test]
    fn test_rule_denied_patterns_are_case_insensitive() {
        let rule = Rule {
            denied_patterns: vec![".*_NULL_.*".to_string(), ".*_EXPORT_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_denied_pattern("tls_rsa_with_null_sha"));
        assert!(rule.matches_denied_pattern("tls_rsa_export_with_des40_cbc_sha"));
    }

    #[test]
    fn test_rule_allowed_patterns() {
        let rule = Rule {
            allowed_patterns: vec!["TLS_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_allowed_pattern("TLS_AES_128_GCM_SHA256"));
        assert!(!rule.matches_allowed_pattern("SSLv3"));
    }

    #[test]
    fn test_rule_allowed_patterns_are_case_insensitive() {
        let rule = Rule {
            allowed_patterns: vec!["TLS_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_allowed_pattern("tls_aes_128_gcm_sha256"));
    }

    #[test]
    fn test_rule_allowed_patterns_invalid_fails_closed() {
        let rule = Rule {
            allowed_patterns: vec!["[".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(!rule.matches_allowed_pattern("TLS_AES_128_GCM_SHA256"));
    }

    #[test]
    fn invalid_pattern_events_are_structured_and_redact_configuration() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        struct Buffer(Arc<Mutex<Vec<u8>>>);
        struct BufferWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for BufferWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for Buffer {
            type Writer = BufferWriter;

            fn make_writer(&'a self) -> Self::Writer {
                BufferWriter(self.0.clone())
            }
        }

        let sensitive_pattern = "[private.example secret=do-not-log\ninjected=true".to_string();
        let rule = Rule {
            allowed_patterns: vec![sensitive_pattern.clone()],
            denied_patterns: vec![sensitive_pattern.clone()],
            preferred_patterns: vec![sensitive_pattern],
            ..base_rule("CipherSuite")
        };
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(Buffer(output.clone()))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            assert!(!rule.matches_allowed_pattern("TLS_AES_128_GCM_SHA256"));
            assert!(rule.matches_denied_pattern("TLS_AES_128_GCM_SHA256"));
            assert!(!rule.matches_preferred_pattern("TLS_AES_128_GCM_SHA256"));
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        for (event, (pattern_kind, outcome)) in events.iter().zip([
            ("allowed", "fail_closed"),
            ("denied", "fail_closed"),
            ("preferred", "ignored"),
        ]) {
            assert_eq!(event["level"], "WARN");
            assert_eq!(event["fields"]["event_name"], "compliance.pattern.invalid");
            assert_eq!(event["fields"]["pattern_kind"], pattern_kind);
            assert_eq!(event["fields"]["error_code"], "invalid_pattern");
            assert_eq!(event["fields"]["outcome"], outcome);
        }
        assert!(!output.contains("private.example"));
        assert!(!output.contains("do-not-log"));
        assert!(!output.contains("injected=true"));
    }

    #[test]
    fn test_rule_preferred_pattern() {
        let rule = Rule {
            preferred_patterns: vec!["TLS_AES_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_preferred_pattern("TLS_AES_128_GCM_SHA256"));
        assert!(!rule.matches_preferred_pattern("TLS_CHACHA20_POLY1305_SHA256"));
    }

    #[test]
    fn test_rule_preferred_patterns_are_case_insensitive() {
        let rule = Rule {
            preferred_patterns: vec!["TLS_AES_.*".to_string()],
            ..base_rule("CipherSuite")
        };

        assert!(rule.matches_preferred_pattern("tls_aes_128_gcm_sha256"));
    }
}
