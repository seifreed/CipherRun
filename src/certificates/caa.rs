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
            && !output.stdout.is_empty()
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

        Ok(Vec::new())
    }

    /// Parse dig CAA output
    fn parse_dig_caa_output(&self, output: &[u8]) -> Result<Vec<CaaRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if line.is_empty() {
                continue;
            }

            // Format: 0 issue "ca.example.com"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3
                && let Ok(flags) = parts[0].parse::<u8>()
            {
                let tag = parts[1].to_string();
                let value = parts[2..].join(" ").trim_matches('"').to_string();

                records.push(CaaRecord { flags, tag, value });
            }
        }

        Ok(records)
    }

    /// Parse host CAA output
    fn parse_host_caa_output(&self, output: &[u8]) -> Result<Vec<CaaRecord>> {
        let output_str = str::from_utf8(output)?;
        let mut records = Vec::new();

        for line in output_str.lines() {
            if line.contains("has CAA record") {
                // Format: example.com has CAA record 0 issue "ca.example.com"
                if let Some(record_part) = line.split("has CAA record").nth(1) {
                    let parts: Vec<&str> = record_part.split_whitespace().collect();
                    if parts.len() >= 3
                        && let Ok(flags) = parts[0].parse::<u8>()
                    {
                        let tag = parts[1].to_string();
                        let value = parts[2..].join(" ").trim_matches('"').to_string();

                        records.push(CaaRecord { flags, tag, value });
                    }
                }
            }
        }

        Ok(records)
    }

    /// Analyze CAA records for security issues
    fn analyze_caa_records(&self, result: &mut CaaCheckResult) {
        let mut has_issue = false;
        let mut has_issuewild = false;
        let mut has_iodef = false;

        for record in &result.records {
            match record.tag.as_str() {
                "issue" => {
                    has_issue = true;
                    if record.value == ";" {
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
            for ca in &common_cas {
                if record.value.contains(ca) {
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

    /// Get parent domain for CAA lookup
    fn get_parent_domains(&self) -> Vec<String> {
        let parts: Vec<&str> = self.domain.split('.').collect();
        let mut domains = Vec::new();

        for i in 0..parts.len() {
            let domain = parts[i..].join(".");
            domains.push(domain);
        }

        domains
    }

    /// Check CAA records up the domain tree (as per RFC 6844)
    pub fn check_tree(&self) -> Result<CaaCheckResult> {
        let parent_domains = self.get_parent_domains();

        for domain in parent_domains {
            let checker = CaaChecker::new(domain.clone());
            let result = checker.check()?;

            if result.has_caa_records {
                // Found CAA records at this level
                return Ok(result);
            }
        }

        // No CAA records found anywhere in the tree
        Ok(CaaCheckResult {
            has_caa_records: false,
            records: Vec::new(),
            compliant: false,
            issues: vec![
                "No CAA records found in domain tree - any CA can issue certificates".to_string(),
            ],
            recommendations: vec!["Add CAA records to control certificate issuance".to_string()],
        })
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
    fn test_parent_domains() {
        let checker = CaaChecker::new("sub.example.com".to_string());
        let parents = checker.get_parent_domains();

        assert_eq!(parents.len(), 3);
        assert_eq!(parents[0], "sub.example.com");
        assert_eq!(parents[1], "example.com");
        assert_eq!(parents[2], "com");
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
}
