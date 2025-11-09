// HTTP Security Headers Checker - Validate security headers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::hsts_preload::PreloadStatus;

/// Security header issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Security header issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderIssue {
    pub header_name: String,
    pub severity: IssueSeverity,
    pub issue_type: IssueType,
    pub description: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preload_status: Option<PreloadStatus>,
}

/// Type of header issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueType {
    Missing,
    Insecure,
    Weak,
    Deprecated,
    Invalid,
}

/// HTTP security header checker
pub struct SecurityHeaderChecker;

impl SecurityHeaderChecker {
    /// Check all security headers (synchronous version without preload check)
    pub fn check_all_headers(headers: &HashMap<String, String>) -> Vec<HeaderIssue> {
        let mut issues = Vec::new();

        // Check critical security headers
        Self::check_hsts(headers, &mut issues, None);
        Self::check_csp(headers, &mut issues);
        Self::check_x_frame_options(headers, &mut issues);
        Self::check_x_content_type_options(headers, &mut issues);
        Self::check_x_xss_protection(headers, &mut issues);
        Self::check_referrer_policy(headers, &mut issues);
        Self::check_permissions_policy(headers, &mut issues);
        Self::check_expect_ct(headers, &mut issues);
        Self::check_expect_staple(headers, &mut issues);
        Self::check_cors(headers, &mut issues);

        issues
    }

    /// Check all security headers with HSTS preload verification (async version)
    pub async fn check_all_headers_with_preload(
        headers: &HashMap<String, String>,
        domain: &str,
    ) -> Vec<HeaderIssue> {
        let mut issues = Vec::new();

        // Check HSTS with preload verification
        use super::hsts_preload::HstsPreloadChecker;
        let checker = HstsPreloadChecker::new();

        // Check if HSTS has preload directive
        let has_preload = if let Some((_, value)) = Self::find_header_case_insensitive(headers, "strict-transport-security") {
            value.to_lowercase().contains("preload")
        } else {
            false
        };

        // Only check preload status if preload directive is present
        let preload_status = if has_preload {
            checker.check_preload_status(domain).await.ok()
        } else {
            None
        };

        Self::check_hsts(headers, &mut issues, preload_status);
        Self::check_csp(headers, &mut issues);
        Self::check_x_frame_options(headers, &mut issues);
        Self::check_x_content_type_options(headers, &mut issues);
        Self::check_x_xss_protection(headers, &mut issues);
        Self::check_referrer_policy(headers, &mut issues);
        Self::check_permissions_policy(headers, &mut issues);
        Self::check_expect_ct(headers, &mut issues);
        Self::check_expect_staple(headers, &mut issues);
        Self::check_cors(headers, &mut issues);

        issues
    }

    /// Check HTTP Strict Transport Security (HSTS)
    fn check_hsts(
        headers: &HashMap<String, String>,
        issues: &mut Vec<HeaderIssue>,
        preload_status: Option<PreloadStatus>,
    ) {
        let key = Self::find_header_case_insensitive(headers, "strict-transport-security");

        if let Some((_, value)) = key {
            // Parse HSTS value
            let max_age = Self::extract_directive(value, "max-age");
            let includes_subdomains = value.to_lowercase().contains("includesubdomains");
            let preload = value.to_lowercase().contains("preload");

            // Check max-age value
            if let Some(age_str) = max_age {
                if let Ok(age) = age_str.parse::<u64>() {
                    if age < 31536000 {
                        // Less than 1 year
                        issues.push(HeaderIssue {
                            header_name: "Strict-Transport-Security".to_string(),
                            severity: IssueSeverity::Medium,
                            issue_type: IssueType::Weak,
                            description: format!(
                                "HSTS max-age is {} seconds (less than 1 year)",
                                age
                            ),
                            recommendation: "Set max-age to at least 31536000 (1 year)".to_string(),
                            preload_status: None,
                        });
                    }
                } else {
                    issues.push(HeaderIssue {
                        header_name: "Strict-Transport-Security".to_string(),
                        severity: IssueSeverity::High,
                        issue_type: IssueType::Invalid,
                        description: "HSTS max-age value is invalid".to_string(),
                        recommendation: "Set a valid max-age directive".to_string(),
                        preload_status: None,
                    });
                }
            } else {
                issues.push(HeaderIssue {
                    header_name: "Strict-Transport-Security".to_string(),
                    severity: IssueSeverity::High,
                    issue_type: IssueType::Invalid,
                    description: "HSTS header missing max-age directive".to_string(),
                    recommendation: "Add max-age directive".to_string(),
                    preload_status: None,
                });
            }

            if !includes_subdomains {
                issues.push(HeaderIssue {
                    header_name: "Strict-Transport-Security".to_string(),
                    severity: IssueSeverity::Low,
                    issue_type: IssueType::Weak,
                    description: "HSTS does not include subdomains".to_string(),
                    recommendation: "Consider adding 'includeSubDomains' directive".to_string(),
                    preload_status: None,
                });
            }

            if !preload {
                issues.push(HeaderIssue {
                    header_name: "Strict-Transport-Security".to_string(),
                    severity: IssueSeverity::Info,
                    issue_type: IssueType::Weak,
                    description: "HSTS preload not enabled".to_string(),
                    recommendation: "Consider adding 'preload' directive for browser preload lists"
                        .to_string(),
                    preload_status: None,
                });
            } else if let Some(status) = &preload_status {
                // Preload directive is present, check if actually preloaded
                use super::hsts_preload::PreloadSource;

                let not_in_browsers = !status.in_chrome || !status.in_firefox || !status.in_edge;

                if not_in_browsers && !matches!(status.source, PreloadSource::Error(_)) {
                    let mut browsers_missing = Vec::new();
                    if !status.in_chrome {
                        browsers_missing.push("Chrome");
                    }
                    if !status.in_firefox {
                        browsers_missing.push("Firefox");
                    }
                    if !status.in_edge {
                        browsers_missing.push("Edge");
                    }
                    if !status.in_safari {
                        browsers_missing.push("Safari");
                    }

                    let severity = if browsers_missing.len() >= 3 {
                        IssueSeverity::Medium
                    } else {
                        IssueSeverity::Low
                    };

                    issues.push(HeaderIssue {
                        header_name: "Strict-Transport-Security".to_string(),
                        severity,
                        issue_type: IssueType::Weak,
                        description: format!(
                            "HSTS preload directive present but not in browser preload lists: {}",
                            browsers_missing.join(", ")
                        ),
                        recommendation: format!(
                            "Submit domain to https://hstspreload.org/ (Status: {})",
                            status.chromium_status.as_deref().unwrap_or("unknown")
                        ),
                        preload_status: Some(status.clone()),
                    });
                }
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "Strict-Transport-Security".to_string(),
                severity: IssueSeverity::High,
                issue_type: IssueType::Missing,
                description: "HSTS header is missing".to_string(),
                recommendation:
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
                        .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check Content Security Policy (CSP)
    fn check_csp(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "content-security-policy");

        if let Some((_, value)) = key {
            // Check for unsafe directives
            if value.contains("'unsafe-inline'") {
                issues.push(HeaderIssue {
                    header_name: "Content-Security-Policy".to_string(),
                    severity: IssueSeverity::Medium,
                    issue_type: IssueType::Insecure,
                    description: "CSP allows 'unsafe-inline' which reduces XSS protection"
                        .to_string(),
                    recommendation: "Remove 'unsafe-inline' and use nonces or hashes".to_string(),
                    preload_status: None,
                });
            }

            if value.contains("'unsafe-eval'") {
                issues.push(HeaderIssue {
                    header_name: "Content-Security-Policy".to_string(),
                    severity: IssueSeverity::Medium,
                    issue_type: IssueType::Insecure,
                    description: "CSP allows 'unsafe-eval' which can enable code injection"
                        .to_string(),
                    recommendation: "Remove 'unsafe-eval' directive".to_string(),
                    preload_status: None,
                });
            }

            if !value.contains("default-src") && !value.contains("script-src") {
                issues.push(HeaderIssue {
                    header_name: "Content-Security-Policy".to_string(),
                    severity: IssueSeverity::Medium,
                    issue_type: IssueType::Weak,
                    description: "CSP missing default-src or script-src directive".to_string(),
                    recommendation: "Add default-src or script-src directive".to_string(),
                    preload_status: None,
                });
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "Content-Security-Policy".to_string(),
                severity: IssueSeverity::Medium,
                issue_type: IssueType::Missing,
                description: "CSP header is missing".to_string(),
                recommendation: "Add Content-Security-Policy header to prevent XSS attacks"
                    .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check X-Frame-Options
    fn check_x_frame_options(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "x-frame-options");

        if let Some((_, value)) = key {
            let value_lower = value.to_lowercase();
            if value_lower != "deny"
                && value_lower != "sameorigin"
                && !value_lower.starts_with("allow-from")
            {
                issues.push(HeaderIssue {
                    header_name: "X-Frame-Options".to_string(),
                    severity: IssueSeverity::Medium,
                    issue_type: IssueType::Invalid,
                    description: format!("Invalid X-Frame-Options value: {}", value),
                    recommendation: "Use 'DENY' or 'SAMEORIGIN'".to_string(),
                    preload_status: None,
                });
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "X-Frame-Options".to_string(),
                severity: IssueSeverity::Medium,
                issue_type: IssueType::Missing,
                description: "X-Frame-Options header is missing".to_string(),
                recommendation:
                    "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking"
                        .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check X-Content-Type-Options
    fn check_x_content_type_options(
        headers: &HashMap<String, String>,
        issues: &mut Vec<HeaderIssue>,
    ) {
        let key = Self::find_header_case_insensitive(headers, "x-content-type-options");

        if let Some((_, value)) = key {
            if value.to_lowercase() != "nosniff" {
                issues.push(HeaderIssue {
                    header_name: "X-Content-Type-Options".to_string(),
                    severity: IssueSeverity::Low,
                    issue_type: IssueType::Invalid,
                    description: format!("Invalid X-Content-Type-Options value: {}", value),
                    recommendation: "Set to 'nosniff'".to_string(),
                    preload_status: None,
                });
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "X-Content-Type-Options".to_string(),
                severity: IssueSeverity::Low,
                issue_type: IssueType::Missing,
                description: "X-Content-Type-Options header is missing".to_string(),
                recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing"
                    .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check X-XSS-Protection (deprecated but still checked)
    fn check_x_xss_protection(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "x-xss-protection");

        if let Some((_, value)) = key {
            let value_lower = value.to_lowercase();
            if value_lower.starts_with('0') {
                issues.push(HeaderIssue {
                    header_name: "X-XSS-Protection".to_string(),
                    severity: IssueSeverity::Low,
                    issue_type: IssueType::Insecure,
                    description: "X-XSS-Protection is disabled".to_string(),
                    recommendation:
                        "Enable with '1; mode=block' or remove (deprecated, use CSP instead)"
                            .to_string(),
                    preload_status: None,
                });
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "X-XSS-Protection".to_string(),
                severity: IssueSeverity::Info,
                issue_type: IssueType::Missing,
                description: "X-XSS-Protection header is missing (deprecated)".to_string(),
                recommendation: "Header is deprecated. Use Content-Security-Policy instead"
                    .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check Referrer-Policy
    fn check_referrer_policy(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "referrer-policy");

        if let Some((_, value)) = key {
            let value_lower = value.to_lowercase();
            if value_lower.contains("unsafe-url") || value_lower == "no-referrer-when-downgrade" {
                issues.push(HeaderIssue {
                    header_name: "Referrer-Policy".to_string(),
                    severity: IssueSeverity::Low,
                    issue_type: IssueType::Weak,
                    description: "Referrer-Policy uses a weak setting".to_string(),
                    recommendation:
                        "Use 'no-referrer', 'strict-origin', or 'strict-origin-when-cross-origin'"
                            .to_string(),
                    preload_status: None,
                });
            }
        } else {
            issues.push(HeaderIssue {
                header_name: "Referrer-Policy".to_string(),
                severity: IssueSeverity::Low,
                issue_type: IssueType::Missing,
                description: "Referrer-Policy header is missing".to_string(),
                recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
                    .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check Permissions-Policy (formerly Feature-Policy)
    fn check_permissions_policy(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let has_permissions =
            Self::find_header_case_insensitive(headers, "permissions-policy").is_some();
        let has_feature = Self::find_header_case_insensitive(headers, "feature-policy").is_some();

        if !has_permissions && !has_feature {
            issues.push(HeaderIssue {
                header_name: "Permissions-Policy".to_string(),
                severity: IssueSeverity::Info,
                issue_type: IssueType::Missing,
                description: "Permissions-Policy header is missing".to_string(),
                recommendation: "Consider adding Permissions-Policy to control browser features"
                    .to_string(),
                preload_status: None,
            });
        }
    }

    /// Check Expect-CT (deprecated)
    fn check_expect_ct(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "expect-ct");

        if key.is_some() {
            issues.push(HeaderIssue {
                header_name: "Expect-CT".to_string(),
                severity: IssueSeverity::Info,
                issue_type: IssueType::Deprecated,
                description: "Expect-CT header is deprecated".to_string(),
                recommendation: "Header is no longer needed as CT is now mandatory".to_string(),
                preload_status: None,
            });
        }
    }

    /// Check Expect-Staple (never standardized)
    fn check_expect_staple(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "expect-staple");

        if key.is_some() {
            issues.push(HeaderIssue {
                header_name: "Expect-Staple".to_string(),
                severity: IssueSeverity::Info,
                issue_type: IssueType::Deprecated,
                description: "Expect-Staple header was never standardized".to_string(),
                recommendation: "Remove this header".to_string(),
                preload_status: None,
            });
        }
    }

    /// Check CORS headers
    fn check_cors(headers: &HashMap<String, String>, issues: &mut Vec<HeaderIssue>) {
        let key = Self::find_header_case_insensitive(headers, "access-control-allow-origin");

        if let Some((_, value)) = key
            && value == "*"
        {
            // Check if credentials are allowed
            if let Some((_, creds)) =
                Self::find_header_case_insensitive(headers, "access-control-allow-credentials")
                && creds.to_lowercase() == "true"
            {
                issues.push(HeaderIssue {
                    header_name: "Access-Control-Allow-Origin".to_string(),
                    severity: IssueSeverity::High,
                    issue_type: IssueType::Insecure,
                    description: "CORS allows credentials with wildcard origin".to_string(),
                    recommendation: "Do not use '*' with Access-Control-Allow-Credentials: true"
                        .to_string(),
                    preload_status: None,
                });
            }

            issues.push(HeaderIssue {
                header_name: "Access-Control-Allow-Origin".to_string(),
                severity: IssueSeverity::Medium,
                issue_type: IssueType::Weak,
                description: "CORS allows all origins with '*'".to_string(),
                recommendation: "Specify allowed origins explicitly".to_string(),
                preload_status: None,
            });
        }
    }

    /// Helper: Find header case-insensitively
    fn find_header_case_insensitive<'a>(
        headers: &'a HashMap<String, String>,
        name: &str,
    ) -> Option<(&'a String, &'a String)> {
        let name_lower = name.to_lowercase();
        headers.iter().find(|(k, _)| k.to_lowercase() == name_lower)
    }

    /// Helper: Extract directive value from header
    fn extract_directive<'a>(value: &'a str, directive: &str) -> Option<&'a str> {
        let directive_lower = directive.to_lowercase();
        for part in value.split(';') {
            let part = part.trim();
            if let Some((key, val)) = part.split_once('=')
                && key.trim().to_lowercase() == directive_lower
            {
                return Some(val.trim());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_hsts() {
        let headers = HashMap::new();
        let issues = SecurityHeaderChecker::check_all_headers(&headers);

        assert!(
            issues
                .iter()
                .any(|i| i.header_name == "Strict-Transport-Security")
        );
    }

    #[test]
    fn test_weak_hsts() {
        let mut headers = HashMap::new();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=3600".to_string(),
        );

        let issues = SecurityHeaderChecker::check_all_headers(&headers);
        let hsts_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.header_name == "Strict-Transport-Security")
            .collect();

        assert!(
            hsts_issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::Weak))
        );
    }

    #[test]
    fn test_unsafe_csp() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self' 'unsafe-inline'".to_string(),
        );

        let issues = SecurityHeaderChecker::check_all_headers(&headers);
        let csp_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.header_name == "Content-Security-Policy")
            .collect();

        assert!(
            csp_issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::Insecure))
        );
    }
}
