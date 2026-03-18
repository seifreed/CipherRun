//! Vulnerability result aggregation utilities

use super::VulnerabilityResult;

/// Merges a new vulnerability result into an existing one.
///
/// Merge rules:
/// - If new is vulnerable but existing is not: replace existing entirely
/// - If both are vulnerable: take worse severity and merge details, preserve inconclusive if either is inconclusive
/// - If new is not vulnerable: only update details if more informative (e.g., "Inconclusive")
pub fn merge_vulnerability_result(existing: &mut VulnerabilityResult, new: &VulnerabilityResult) {
    // Case 1: New result is vulnerable, existing is not - replace entirely
    if new.vulnerable && !existing.vulnerable {
        *existing = new.clone();
        return;
    }

    // Case 2: Both are vulnerable - merge details and take worse severity
    if new.vulnerable && existing.vulnerable {
        if new.severity > existing.severity {
            existing.severity = new.severity;
        }
        // Preserve inconclusive status if either result was inconclusive
        // This indicates uncertainty about the vulnerability details
        existing.inconclusive = existing.inconclusive || new.inconclusive;
        if !existing.details.contains(&new.details) {
            existing.details = format!("{}; {}", existing.details, new.details);
        }
        return;
    }

    // Case 3: Neither is vulnerable - preserve inconclusive state and more informative details
    if !new.vulnerable && !existing.vulnerable {
        // If new result is inconclusive, preserve or update
        if new.inconclusive && !existing.inconclusive {
            existing.inconclusive = true;
            existing.details.clone_from(&new.details);
            return;
        }
        // If existing is not inconclusive but new has inconclusive info
        if new.inconclusive == existing.inconclusive
            && new.details.contains("Inconclusive")
            && !existing.details.contains("Inconclusive")
        {
            existing.details.clone_from(&new.details);
        }
    }

    // Case 4: New is not vulnerable but existing is - keep existing (no action needed)
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
        // Should preserve inconclusive status since one result was inconclusive
        assert!(
            existing.inconclusive,
            "Inconclusive status should be preserved when merging with inconclusive result"
        );
        assert!(existing.details.contains("timing test inconclusive"));
        assert!(existing.details.contains("Vulnerability confirmed"));
    }
}
