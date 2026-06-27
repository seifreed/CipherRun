// CAA (Certification Authority Authorization) DNS Records
// RFC 6844 - DNS Certification Authority Authorization

use crate::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::str;

/// CAA Record check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaCheckResult {
    pub has_caa_records: bool,
    pub records: Vec<CaaRecord>,
    pub compliant: bool,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

/// CAA Record entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

/// CAA Record checker
pub struct CaaChecker {
    domain: String,
}

impl CaaChecker {
    pub fn new(domain: String) -> Self {
        Self { domain }
    }

    /// Check CAA records for the domain
    pub fn check(&self) -> Result<CaaCheckResult> {
        let mut result = CaaCheckResult {
            has_caa_records: false,
            records: Vec::new(),
            compliant: false,
            issues: Vec::new(),
            recommendations: Vec::new(),
        };

        // Query CAA records using dig
        match self.query_caa_records() {
            Ok(records) => {
                if records.is_empty() {
                    result.has_caa_records = false;
                    result.issues.push(
                        "No CAA records found - any CA can issue certificates for this domain"
                            .to_string(),
                    );
                    result.recommendations.push(
                        "Add CAA records to restrict which CAs can issue certificates".to_string(),
                    );
                    result.recommendations.push(
                        "Example: example.com. IN CAA 0 issue \"letsencrypt.org\"".to_string(),
                    );
                } else {
                    result.has_caa_records = true;
                    result.records = records;
                    result.compliant = true;

                    // Analyze CAA records
                    self.analyze_caa_records(&mut result);
                }
            }
            Err(e) => {
                result
                    .issues
                    .push(format!("Failed to query CAA records: {}", e));
            }
        }

        Ok(result)
    }

    /// Query CAA records via dig
    fn query_caa_records(&self) -> Result<Vec<CaaRecord>> {
        // Try dig first
        let output = Command::new("dig")
            .args(["+short", "CAA", &self.domain])
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            return self.parse_dig_caa_output(&output.stdout);
        }

        // Fallback to host command
        let output = Command::new("host")
            .args(["-t", "CAA", &self.domain])
            .output()?;

        if output.status.success() {
            return self.parse_host_caa_output(&output.stdout);
        }

        Err(crate::TlsError::Other(format!(
            "CAA lookup failed for {}",
            self.domain
        )))
    }

    /// Parse dig CAA output
    fn parse_dig_caa_output(&self, output: &[u8]) -> Result<Vec<CaaRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if line.trim().is_empty() {
                continue;
            }

            if let Some(record) = Self::parse_caa_record_fields(line) {
                records.push(record);
            }
        }

        Ok(records)
    }

    /// Parse host CAA output
    fn parse_host_caa_output(&self, output: &[u8]) -> Result<Vec<CaaRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if let Some(record_part) = Self::split_after_case_insensitive(line, "has CAA record")
                && let Some(record) = Self::parse_caa_record_fields(record_part)
            {
                records.push(record);
            }
        }

        Ok(records)
    }

    fn parse_caa_record_fields(record: &str) -> Option<CaaRecord> {
        let mut parts = record.split_whitespace();
        let flags = parts.next()?.parse::<u8>().ok()?;
        let tag = parts.next()?.to_ascii_lowercase();
        let value = parts.collect::<Vec<_>>().join(" ");

        if value.is_empty() {
            return None;
        }

        Some(CaaRecord {
            flags,
            tag,
            value: Self::normalize_caa_value(&value),
        })
    }

    fn normalize_caa_value(value: &str) -> String {
        value.trim().trim_matches('"').to_string()
    }

    fn split_after_case_insensitive<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
        let line_lower = line.to_ascii_lowercase();
        let marker_lower = marker.to_ascii_lowercase();
        let index = line_lower.find(&marker_lower)?;
        line.get(index + marker.len()..)
    }

    /// Analyze CAA records for security issues
    fn analyze_caa_records(&self, result: &mut CaaCheckResult) {
        let mut has_issue = false;
        let mut has_issuewild = false;
        let mut has_iodef = false;

        for record in &result.records {
            match record.tag.to_ascii_lowercase().as_str() {
                "issue" => {
                    has_issue = true;
                    if record.value.trim() == ";" {
                        result.issues.push(
                            "CAA record explicitly forbids ALL certificate issuance".to_string(),
                        );
                    }
                }
                "issuewild" => {
                    has_issuewild = true;
                }
                "iodef" => {
                    has_iodef = true;
                }
                _ => {
                    result
                        .issues
                        .push(format!("Unknown CAA tag: {}", record.tag));
                }
            }
        }

        if !has_issue && !has_issuewild {
            result.issues.push(
                "No 'issue' or 'issuewild' CAA records - configuration may not be effective"
                    .to_string(),
            );
        }

        if !has_issuewild {
            result.recommendations.push(
                "Consider adding 'issuewild' CAA record to control wildcard certificate issuance"
                    .to_string(),
            );
        }

        if !has_iodef {
            result.recommendations.push(
                "Consider adding 'iodef' CAA record to receive notifications of unauthorized issuance attempts".to_string()
            );
        }

        // Check for common CAs
        let common_cas = vec![
            "letsencrypt.org",
            "digicert.com",
            "globalsign.com",
            "sectigo.com",
        ];
        let mut recognized_cas = Vec::new();

        for record in &result.records {
            let value = record.value.to_ascii_lowercase();
            for ca in &common_cas {
                if value.contains(ca) {
                    recognized_cas.push(*ca);
                }
            }
        }

        if !recognized_cas.is_empty() {
            result
                .recommendations
                .push(format!("Authorized CAs: {}", recognized_cas.join(", ")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caa_checker_creation() {
        let checker = CaaChecker::new("example.com".to_string());
        assert_eq!(checker.domain, "example.com");
    }

    #[test]
    fn test_caa_record() {
        let record = CaaRecord {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };

        assert_eq!(record.flags, 0);
        assert_eq!(record.tag, "issue");
    }

    #[test]
    fn test_parse_dig_caa_output() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"0 issue \"letsencrypt.org\"\n128 issuewild \"ca.example.com\"";
        let records = checker
            .parse_dig_caa_output(output)
            .expect("parse should succeed");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].flags, 0);
        assert_eq!(records[0].tag, "issue");
        assert_eq!(records[0].value, "letsencrypt.org");
        assert_eq!(records[1].flags, 128);
        assert_eq!(records[1].tag, "issuewild");
    }

    #[test]
    fn test_parse_dig_caa_output_normalizes_tags() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"0 ISSUE \"LetsEncrypt.org\"";
        let records = checker
            .parse_dig_caa_output(output)
            .expect("parse should succeed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, "issue");
        assert_eq!(records[0].value, "LetsEncrypt.org");
    }

    #[test]
    fn test_parse_dig_caa_output_skips_invalid_lines() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"bad line\n0 issue \"letsencrypt.org\"";
        let records = checker
            .parse_dig_caa_output(output)
            .expect("parse should succeed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, "issue");
    }

    #[test]
    fn test_parse_dig_caa_output_empty_means_no_records() {
        let checker = CaaChecker::new("example.com".to_string());
        let records = checker
            .parse_dig_caa_output(b"")
            .expect("empty successful dig output should parse");

        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_dig_caa_output_skips_short_records() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"0\n0 issue\n0 issue \"letsencrypt.org\"";
        let records = checker
            .parse_dig_caa_output(output)
            .expect("parse should succeed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "letsencrypt.org");
    }

    #[test]
    fn test_parse_host_caa_output() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"example.com has CAA record 0 iodef \"mailto:security@example.com\"";
        let records = checker
            .parse_host_caa_output(output)
            .expect("parse should succeed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, "iodef");
        assert_eq!(records[0].value, "mailto:security@example.com");
    }

    #[test]
    fn test_parse_host_caa_output_is_case_insensitive() {
        let checker = CaaChecker::new("example.com".to_string());
        let output = b"example.com HAS CAA RECORD 0 ISSUEWILD \"Ca.Example.com\"";
        let records = checker
            .parse_host_caa_output(output)
            .expect("parse should succeed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, "issuewild");
        assert_eq!(records[0].value, "Ca.Example.com");
    }

    #[test]
    fn test_analyze_caa_records_flags_and_unknown_tags() {
        let checker = CaaChecker::new("example.com".to_string());
        let mut result = CaaCheckResult {
            has_caa_records: true,
            records: vec![
                CaaRecord {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: ";".to_string(),
                },
                CaaRecord {
                    flags: 0,
                    tag: "unknown".to_string(),
                    value: "x".to_string(),
                },
            ],
            compliant: true,
            issues: Vec::new(),
            recommendations: Vec::new(),
        };

        checker.analyze_caa_records(&mut result);

        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("forbids ALL"))
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("Unknown CAA tag"))
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|rec| rec.contains("issuewild"))
        );
    }

    #[test]
    fn test_analyze_caa_records_treats_tags_and_ca_domains_case_insensitively() {
        let checker = CaaChecker::new("example.com".to_string());
        let mut result = CaaCheckResult {
            has_caa_records: true,
            records: vec![
                CaaRecord {
                    flags: 0,
                    tag: "ISSUE".to_string(),
                    value: "LetsEncrypt.org".to_string(),
                },
                CaaRecord {
                    flags: 0,
                    tag: "IODEF".to_string(),
                    value: "mailto:security@example.com".to_string(),
                },
            ],
            compliant: true,
            issues: Vec::new(),
            recommendations: Vec::new(),
        };

        checker.analyze_caa_records(&mut result);

        assert!(
            !result
                .issues
                .iter()
                .any(|issue| issue.contains("Unknown CAA tag"))
        );
        assert!(
            !result
                .issues
                .iter()
                .any(|issue| issue.contains("No 'issue'"))
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|rec| rec.contains("Authorized CAs: letsencrypt.org"))
        );
    }

    #[test]
    fn test_analyze_caa_records_recommends_issuewild_when_missing() {
        let checker = CaaChecker::new("example.com".to_string());
        let mut result = CaaCheckResult {
            has_caa_records: true,
            records: vec![CaaRecord {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }],
            compliant: true,
            issues: Vec::new(),
            recommendations: Vec::new(),
        };

        checker.analyze_caa_records(&mut result);
        assert!(
            result
                .recommendations
                .iter()
                .any(|rec| rec.contains("issuewild"))
        );
    }

    #[test]
    fn test_check_reports_no_records_for_empty_successful_lookup() {
        let checker = CaaChecker::new("invalid.invalid".to_string());
        let result = checker.check().expect("check should return a result");

        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("No CAA records found"))
        );
        assert!(!result.has_caa_records);
    }
}
