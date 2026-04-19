//! Vulnerability result aggregation utilities

use super::VulnerabilityResult;

fn detail_segments(details: &str) -> Vec<String> {
    details
        .split(';')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn merge_unique_details(existing: &mut String, new: &str) {
    let mut merged = detail_segments(existing);

    for segment in detail_segments(new) {
        if !merged.iter().any(|current| current == &segment) {
            merged.push(segment);
        }
    }

    *existing = merged.join("; ");
}

/// Merges a new vulnerability result into an existing one.
///
/// Merge rules:
/// - If new is confirmed-vulnerable and existing is not: replace existing entirely
/// - If new is inconclusive-vulnerable and existing is confirmed-not-vulnerable: keep existing
/// - If both are vulnerable: take worse severity and merge details
/// - If one is confirmed vulnerable and the other is inconclusive: confirmed result wins
/// - If new is not vulnerable: only update details if more informative (e.g., "Inconclusive")
/// - If either result came from a scan with errors, mark as inconclusive
pub fn merge_vulnerability_result(existing: &mut VulnerabilityResult, new: &VulnerabilityResult) {
    // Case 1: New result is vulnerable, existing is not
    if new.vulnerable && !existing.vulnerable {
        // Only replace if new is confirmed OR existing was also inconclusive.
        // A confirmed negative beats an inconclusive positive.
        if !new.inconclusive || existing.inconclusive {
            *existing = new.clone();
        }
        return;
    }

    // Case 2: Both are vulnerable - merge details and take worse severity
    if new.vulnerable && existing.vulnerable {
        if !new.inconclusive && existing.inconclusive {
            // New is confirmed, existing was inconclusive: use new's severity since the
            // existing severity was never actually proven — keeping it would inflate confidence.
            existing.severity = new.severity;
            existing.inconclusive = false;
        } else {
            // Both confirmed, or existing confirmed: take the worse (higher) severity.
            if new.severity > existing.severity {
                existing.severity = new.severity;
            }
            // Both inconclusive: stay inconclusive (no change needed).
        }
        merge_unique_details(&mut existing.details, &new.details);
        return;
    }

    // Case 3: Neither is vulnerable - preserve inconclusive state and more informative details
    if !new.vulnerable && !existing.vulnerable {
        // If new result is inconclusive, propagate that status
        if new.inconclusive && !existing.inconclusive {
            existing.inconclusive = true;
            merge_unique_details(&mut existing.details, &new.details);
        }
        // Note: We rely on the `inconclusive` boolean flag, not string content.
        // String checks like `details.contains("Inconclusive")` are unreliable
        // and were removed to avoid confusion between status and message content.
    }

    // Case 4: New is not vulnerable but existing is - keep existing (no action needed)
}

/// Merges a vulnerability result from a scan that encountered an error.
///
/// This function is used when a vulnerability result comes from a scan that
/// partially completed before encountering an error. The result may be incomplete
/// or missing some checks, so we mark it as inconclusive to indicate uncertainty.
///
/// The merge follows the same rules as `merge_vulnerability_result`, but also
/// adds a note about the error to the details and marks the result as inconclusive.
pub fn merge_vulnerability_result_with_error(
    existing: &mut VulnerabilityResult,
    new: &VulnerabilityResult,
    _error_msg: &str,
) {
    // When merging results from an error-prone scan, we should mark as inconclusive
    // to indicate the data may be incomplete
    let mut new_with_warning = new.clone();
    new_with_warning.inconclusive = true;

    // If this is the first result for this vulnerability type, note the error context
    if !new_with_warning.details.contains("partial scan") {
        new_with_warning.details = format!(
            "{} (from partial scan - some checks may be incomplete)",
            new_with_warning.details
        );
    }

    // Use standard merge logic with the marked result
    merge_vulnerability_result(existing, &new_with_warning);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::{Severity, VulnerabilityType};

    fn make_result(vulnerable: bool, severity: Severity, details: &str) -> VulnerabilityResult {
        VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable,
            inconclusive: details.contains("Inconclusive"),
            details: details.to_string(),
            cve: None,
            cwe: None,
            severity,
        }
    }

    #[test]
    fn test_merge_new_vulnerable_replaces_existing() {
        let mut existing = make_result(false, Severity::Info, "Not vulnerable");
        let new = make_result(true, Severity::High, "Vulnerable!");

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        assert_eq!(existing.severity, Severity::High);
        assert_eq!(existing.details, "Vulnerable!");
    }

    #[test]
    fn test_merge_both_vulnerable_takes_worse_severity() {
        let mut existing = make_result(true, Severity::Medium, "Medium issue");
        let new = make_result(true, Severity::High, "High issue");

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        assert_eq!(existing.severity, Severity::High);
        assert!(existing.details.contains("Medium issue"));
        assert!(existing.details.contains("High issue"));
    }

    #[test]
    fn test_merge_neither_vulnerable_preserves_inconclusive() {
        let mut existing = make_result(false, Severity::Info, "Not vulnerable");
        let new = make_result(false, Severity::Info, "Inconclusive - test timed out");

        merge_vulnerability_result(&mut existing, &new);

        assert!(!existing.vulnerable);
        assert!(existing.inconclusive);
        assert!(existing.details.contains("Inconclusive"));
    }

    #[test]
    fn test_merge_keeps_existing_when_new_not_vulnerable() {
        let mut existing = make_result(true, Severity::High, "Vulnerable!");
        let new = make_result(false, Severity::Info, "Not vulnerable");

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        assert_eq!(existing.severity, Severity::High);
        assert_eq!(existing.details, "Vulnerable!");
    }

    #[test]
    fn test_merge_does_not_duplicate_details() {
        let mut existing = make_result(true, Severity::High, "Same detail");
        let new = make_result(true, Severity::High, "Same detail");

        merge_vulnerability_result(&mut existing, &new);
        assert_eq!(existing.details, "Same detail");
    }

    #[test]
    fn test_merge_both_vulnerable_preserves_substring_details() {
        let mut existing = make_result(true, Severity::High, "TLS 1.2 support");
        let new = make_result(true, Severity::High, "TLS 1.2");

        merge_vulnerability_result(&mut existing, &new);

        assert_eq!(existing.details, "TLS 1.2 support; TLS 1.2");
    }

    #[test]
    fn test_merge_neither_vulnerable_keeps_existing_details() {
        let mut existing = make_result(false, Severity::Info, "Not vulnerable");
        let new = make_result(false, Severity::Info, "No issues detected");

        merge_vulnerability_result(&mut existing, &new);
        assert_eq!(existing.details, "Not vulnerable");
    }

    #[test]
    fn test_merge_both_vulnerable_preserves_inconclusive() {
        // When merging two vulnerable results, if one is inconclusive,
        // the result should remain inconclusive to indicate uncertainty
        let mut existing = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: true,
            details: "Possibly vulnerable - timing test inconclusive".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        };
        let new = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: false,
            details: "Vulnerability confirmed via direct test".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        };

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        // When we have a confirmed result (inconclusive=false), it should override
        // the inconclusive status - confirmed findings take precedence
        assert!(
            !existing.inconclusive,
            "Confirmed result should override inconclusive status"
        );
        assert!(existing.details.contains("timing test inconclusive"));
        assert!(existing.details.contains("Vulnerability confirmed"));
    }

    #[test]
    fn test_merge_confirmed_overrides_inconclusive() {
        // Test that a confirmed vulnerable result overrides an inconclusive one
        let mut existing = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: true,
            details: "Timing test was inconclusive".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        };
        let new = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: false,
            details: "Confirmed vulnerability".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        };

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        // Confirmed result should clear inconclusive status
        assert!(
            !existing.inconclusive,
            "Confirmed vulnerable should clear inconclusive"
        );
        assert_eq!(existing.severity, Severity::High);
    }

    #[test]
    fn test_merge_confirmed_lower_severity_replaces_inconclusive_higher() {
        // existing=inconclusive+High, new=confirmed+Medium
        // The confirmed Medium should win: keeping High would misrepresent confidence.
        let mut existing = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: true,
            details: "Timing inconclusive - possibly High".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::High,
        };
        let new = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: false,
            details: "Confirmed Medium".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        };

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        assert!(
            !existing.inconclusive,
            "Confirmed new should clear inconclusive"
        );
        assert_eq!(
            existing.severity,
            Severity::Medium,
            "Confirmed Medium should replace unproven High"
        );
    }

    #[test]
    fn test_merge_both_inconclusive_stays_inconclusive() {
        // When both results are inconclusive, preserve the status
        let mut existing = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: true,
            details: "First test inconclusive".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        };
        let new = VulnerabilityResult {
            vuln_type: VulnerabilityType::Heartbleed,
            vulnerable: true,
            inconclusive: true,
            details: "Second test also inconclusive".to_string(),
            cve: None,
            cwe: None,
            severity: Severity::Medium,
        };

        merge_vulnerability_result(&mut existing, &new);

        assert!(existing.vulnerable);
        // Both inconclusive = stay inconclusive
        assert!(
            existing.inconclusive,
            "Should stay inconclusive when both are inconclusive"
        );
    }
}
