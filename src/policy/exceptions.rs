// Policy exception matching and handling

use crate::policy::PolicyException;
use chrono::{NaiveDate, Utc};
use regex::Regex;

/// Exception matcher for policy rules
pub struct ExceptionMatcher {
    exceptions: Vec<PolicyException>,
}

impl ExceptionMatcher {
    pub fn new(exceptions: Vec<PolicyException>) -> Self {
        Self { exceptions }
    }

    /// Check if a specific target and rule combination has an exception
    pub fn is_exception(&self, target: &str, rule_path: &str) -> Option<&PolicyException> {
        for exception in &self.exceptions {
            // Check if exception is expired
            if let Some(ref expires) = exception.expires {
                if self.is_expired(expires) {
                    continue;
                }
            }

            // Check if target matches (with wildcard support)
            if let Some(ref domain_pattern) = exception.domain {
                if !self.matches_domain(target, domain_pattern) {
                    continue;
                }
            }

            // Check if rule matches
            if exception.rules.contains(&rule_path.to_string()) {
                return Some(exception);
            }
        }

        None
    }

    /// Check if target matches domain pattern (supports wildcards)
    fn matches_domain(&self, target: &str, pattern: &str) -> bool {
        // Extract hostname from target if it contains port
        let hostname = if let Some(pos) = target.find(':') {
            &target[..pos]
        } else {
            target
        };

        // Convert wildcard pattern to regex
        // *.example.com -> ^.*\.example\.com$
        // example.com -> ^example\.com$
        let regex_pattern = pattern
            .replace('.', r"\.")
            .replace('*', ".*");

        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            return re.is_match(hostname);
        }

        false
    }

    /// Check if an exception has expired
    fn is_expired(&self, expires_str: &str) -> bool {
        if let Ok(expires_date) = NaiveDate::parse_from_str(expires_str, "%Y-%m-%d") {
            let today = Utc::now().date_naive();
            return today > expires_date;
        }
        // If we can't parse the date, consider it expired for safety
        true
    }

    /// Get all active exceptions for a target
    pub fn get_exceptions_for_target(&self, target: &str) -> Vec<&PolicyException> {
        let mut result = Vec::new();

        for exception in &self.exceptions {
            // Skip expired exceptions
            if let Some(ref expires) = exception.expires {
                if self.is_expired(expires) {
                    continue;
                }
            }

            // Check if target matches
            if let Some(ref domain_pattern) = exception.domain {
                if self.matches_domain(target, domain_pattern) {
                    result.push(exception);
                }
            } else {
                // No domain filter means it applies to all targets
                result.push(exception);
            }
        }

        result
    }

    /// Format exception for display
    pub fn format_exception(exception: &PolicyException) -> String {
        let mut parts = Vec::new();

        if let Some(ref domain) = exception.domain {
            parts.push(format!("Domain: {}", domain));
        }

        parts.push(format!("Rules: {}", exception.rules.join(", ")));
        parts.push(format!("Reason: {}", exception.reason));
        parts.push(format!("Approved by: {}", exception.approved_by));

        if let Some(ref ticket) = exception.ticket {
            parts.push(format!("Ticket: {}", ticket));
        }

        if let Some(ref expires) = exception.expires {
            parts.push(format!("Expires: {}", expires));
        }

        parts.join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        let exception = PolicyException {
            domain: Some("*.example.com".to_string()),
            rules: vec!["protocols.prohibited".to_string()],
            reason: "Test".to_string(),
            expires: None,
            approved_by: "Admin".to_string(),
            ticket: None,
        };

        let matcher = ExceptionMatcher::new(vec![exception]);

        assert!(matcher.matches_domain("subdomain.example.com", "*.example.com"));
        assert!(matcher.matches_domain("test.example.com", "*.example.com"));
        assert!(!matcher.matches_domain("example.com", "*.example.com"));
        assert!(!matcher.matches_domain("other.org", "*.example.com"));
    }

    #[test]
    fn test_exact_domain_matching() {
        let exception = PolicyException {
            domain: Some("example.com".to_string()),
            rules: vec!["protocols.prohibited".to_string()],
            reason: "Test".to_string(),
            expires: None,
            approved_by: "Admin".to_string(),
            ticket: None,
        };

        let matcher = ExceptionMatcher::new(vec![exception]);

        assert!(matcher.matches_domain("example.com", "example.com"));
        assert!(!matcher.matches_domain("subdomain.example.com", "example.com"));
    }

    #[test]
    fn test_exception_expiration() {
        let matcher = ExceptionMatcher::new(Vec::new());

        // Test expired date
        assert!(matcher.is_expired("2020-01-01"));

        // Test future date (will need to be updated in the future)
        assert!(!matcher.is_expired("2099-12-31"));

        // Test invalid date format
        assert!(matcher.is_expired("invalid-date"));
    }

    #[test]
    fn test_is_exception() {
        let exception = PolicyException {
            domain: Some("test.example.com".to_string()),
            rules: vec!["protocols.prohibited".to_string()],
            reason: "Legacy system".to_string(),
            expires: Some("2099-12-31".to_string()),
            approved_by: "CISO".to_string(),
            ticket: Some("SEC-1234".to_string()),
        };

        let matcher = ExceptionMatcher::new(vec![exception]);

        assert!(matcher.is_exception("test.example.com", "protocols.prohibited").is_some());
        assert!(matcher.is_exception("test.example.com:443", "protocols.prohibited").is_some());
        assert!(matcher.is_exception("test.example.com", "ciphers.prohibited").is_none());
        assert!(matcher.is_exception("other.example.com", "protocols.prohibited").is_none());
    }

    #[test]
    fn test_exception_with_port() {
        let exception = PolicyException {
            domain: Some("example.com".to_string()),
            rules: vec!["certificates.max_days_until_expiry".to_string()],
            reason: "Test".to_string(),
            expires: None,
            approved_by: "Admin".to_string(),
            ticket: None,
        };

        let matcher = ExceptionMatcher::new(vec![exception]);

        // Should match even when target includes port
        assert!(matcher.is_exception("example.com:443", "certificates.max_days_until_expiry").is_some());
        assert!(matcher.is_exception("example.com:8443", "certificates.max_days_until_expiry").is_some());
    }
}
