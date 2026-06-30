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

#[test]
fn test_extract_directive_case_insensitive() {
    let value = "max-age=63072000; IncludeSubDomains";
    let directive = SecurityHeaderChecker::extract_directive(value, "Max-Age");
    assert_eq!(directive, Some("63072000"));
}

#[test]
fn test_extract_directive_missing() {
    let value = "includeSubDomains; preload";
    let directive = SecurityHeaderChecker::extract_directive(value, "max-age");
    assert_eq!(directive, None);
}

#[test]
fn test_csp_missing_directives() {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Security-Policy".to_string(),
        "img-src 'self'".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Content-Security-Policy" && matches!(i.issue_type, IssueType::Weak)
    }));
}

#[test]
fn test_invalid_x_frame_options() {
    let mut headers = HashMap::new();
    headers.insert("X-Frame-Options".to_string(), "ALLOWALL".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "X-Frame-Options" && matches!(i.issue_type, IssueType::Invalid)
    }));
}

#[test]
fn test_x_content_type_options_invalid() {
    let mut headers = HashMap::new();
    headers.insert("X-Content-Type-Options".to_string(), "sniff".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "X-Content-Type-Options" && matches!(i.issue_type, IssueType::Invalid)
    }));
}

#[test]
fn test_x_xss_protection_zero_is_not_flagged_insecure() {
    // X-XSS-Protection: 0 is the OWASP-recommended value (disable the removed,
    // XS-Leak-prone legacy auditor and rely on CSP); it must not be flagged.
    let mut headers = HashMap::new();
    headers.insert("X-XSS-Protection".to_string(), "0".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(!issues.iter().any(|i| {
        i.header_name == "X-XSS-Protection" && matches!(i.issue_type, IssueType::Insecure)
    }));
}

#[test]
fn test_x_xss_protection_enabling_value_is_flagged() {
    // Enabling the legacy auditor (1; mode=block) is the weak setting under
    // current guidance.
    let mut headers = HashMap::new();
    headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "X-XSS-Protection" && matches!(i.issue_type, IssueType::Insecure)
    }));
}

#[test]
fn test_referrer_policy_weak() {
    let mut headers = HashMap::new();
    headers.insert("Referrer-Policy".to_string(), "unsafe-url".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Referrer-Policy" && matches!(i.issue_type, IssueType::Weak)
    }));
}

#[test]
fn test_permissions_policy_missing() {
    let headers = HashMap::new();
    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Permissions-Policy" && matches!(i.issue_type, IssueType::Missing)
    }));
}

#[test]
fn test_expect_ct_and_expect_staple_deprecated() {
    let mut headers = HashMap::new();
    headers.insert("Expect-CT".to_string(), "max-age=0".to_string());
    headers.insert("Expect-Staple".to_string(), "max-age=0".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Expect-CT" && matches!(i.issue_type, IssueType::Deprecated)
    }));
    assert!(issues.iter().any(|i| {
        i.header_name == "Expect-Staple" && matches!(i.issue_type, IssueType::Deprecated)
    }));
}

#[test]
fn test_cors_wildcard_with_credentials() {
    let mut headers = HashMap::new();
    headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
    headers.insert(
        "Access-Control-Allow-Credentials".to_string(),
        "true".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Access-Control-Allow-Origin"
            && matches!(i.issue_type, IssueType::Insecure)
    }));
}

#[test]
fn test_find_header_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert("x-content-type-options".to_string(), "nosniff".to_string());

    let found =
        SecurityHeaderChecker::find_header_case_insensitive(&headers, "X-Content-Type-Options");
    assert!(found.is_some());
}

#[test]
fn test_extract_directive_parses_value() {
    let value = "max-age=31536000; includeSubDomains; preload";
    let directive = SecurityHeaderChecker::extract_directive(value, "max-age");
    assert_eq!(directive, Some("31536000"));
}

#[test]
fn test_extract_directive_strips_quotes() {
    let value = "max-age=\"31536000\"; includeSubDomains";
    let directive = SecurityHeaderChecker::extract_directive(value, "max-age");
    assert_eq!(directive, Some("31536000"));
}

#[test]
fn test_hsts_quoted_max_age_is_not_invalid() {
    // A spec-valid quoted max-age must not be reported as invalid.
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=\"31536000\"; includeSubDomains; preload".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(!issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security" && matches!(i.issue_type, IssueType::Invalid)
    }));
}

#[test]
fn test_hsts_max_age_zero_is_high_severity_disabled() {
    // max-age=0 disables HSTS (RFC 6797 §6.1.1) and must be flagged as serious,
    // not as a merely-weak short max-age.
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=0".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security"
            && matches!(i.severity, IssueSeverity::High)
            && i.description.contains("disables HSTS")
    }));
}

#[test]
fn test_hsts_invalid_max_age() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=abc".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security" && matches!(i.issue_type, IssueType::Invalid)
    }));
}

#[test]
fn test_hsts_missing_max_age() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "includeSubDomains".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security" && matches!(i.issue_type, IssueType::Invalid)
    }));
}

#[test]
fn test_hsts_missing_include_subdomains() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security"
            && matches!(i.issue_type, IssueType::Weak)
            && i.description.contains("include subdomains")
    }));
}

#[test]
fn test_hsts_missing_preload() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security"
            && matches!(i.issue_type, IssueType::Weak)
            && i.description.contains("preload")
    }));
}

#[test]
fn test_hsts_preload_missing_only_from_safari_is_reported() {
    use crate::http::hsts_preload::{PreloadSource, PreloadStatus};

    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains; preload".to_string(),
    );

    // Present in Chrome/Firefox/Edge, absent only from Safari: must still produce
    // a preload-list issue naming Safari (the trigger used to ignore Safari).
    let status = PreloadStatus {
        in_chrome: true,
        in_firefox: true,
        in_edge: true,
        in_safari: false,
        chromium_status: Some("preloaded".to_string()),
        source: PreloadSource::Api,
    };

    let mut issues = Vec::new();
    SecurityHeaderChecker::check_hsts(&headers, &mut issues, Some(status));

    assert!(issues.iter().any(|i| {
        i.header_name == "Strict-Transport-Security"
            && matches!(i.issue_type, IssueType::Weak)
            && i.description.contains("Safari")
    }));
}

#[test]
fn test_hsts_preload_check_error_is_reported() {
    use crate::http::hsts_preload::{PreloadSource, PreloadStatus};

    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains; preload".to_string(),
    );

    let status = PreloadStatus {
        in_chrome: false,
        in_firefox: false,
        in_edge: false,
        in_safari: false,
        chromium_status: Some("unknown".to_string()),
        source: PreloadSource::Error("cache lock failed".to_string()),
    };

    let mut issues = Vec::new();
    SecurityHeaderChecker::check_hsts(&headers, &mut issues, Some(status));

    assert!(issues.iter().any(|issue| {
        issue.header_name == "Strict-Transport-Security"
            && matches!(issue.issue_type, IssueType::Invalid)
            && issue
                .description
                .contains("HSTS preload status check failed")
    }));
}

#[test]
fn test_hsts_directives_match_exact_tokens() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains=false; preload=false".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    let hsts_issues: Vec<_> = issues
        .iter()
        .filter(|issue| issue.header_name == "Strict-Transport-Security")
        .collect();

    assert!(hsts_issues.iter().any(|issue| {
        matches!(issue.issue_type, IssueType::Weak)
            && issue.description.contains("include subdomains")
    }));
    assert!(hsts_issues.iter().any(|issue| {
        matches!(issue.issue_type, IssueType::Weak) && issue.description.contains("preload")
    }));
}

#[test]
fn test_hsts_directives_are_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert(
        "Strict-Transport-Security".to_string(),
        "Max-Age=31536000; IncludeSubDomains; Preload".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|issue| issue.header_name == "Strict-Transport-Security")
    );
}

#[test]
fn test_cors_wildcard_without_credentials_is_weak() {
    let mut headers = HashMap::new();
    headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|i| {
        i.header_name == "Access-Control-Allow-Origin" && matches!(i.issue_type, IssueType::Weak)
    }));
}

#[test]
fn test_cors_wildcard_with_credentials_trims_values() {
    let mut headers = HashMap::new();
    headers.insert("Access-Control-Allow-Origin".to_string(), " * ".to_string());
    headers.insert(
        "Access-Control-Allow-Credentials".to_string(),
        " TRUE ".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(issues.iter().any(|issue| {
        issue.header_name == "Access-Control-Allow-Origin"
            && matches!(issue.issue_type, IssueType::Insecure)
    }));
}

#[test]
fn test_csp_directive_names_are_case_insensitive() {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Security-Policy".to_string(),
        "Default-Src 'self'".to_string(),
    );

    let issues = SecurityHeaderChecker::check_all_headers(&headers);
    assert!(!issues.iter().any(|issue| {
        issue.header_name == "Content-Security-Policy"
            && issue
                .description
                .contains("missing default-src or script-src")
    }));
}
