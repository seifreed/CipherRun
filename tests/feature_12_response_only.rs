/// Tests for Feature 12: Response-Only Output Mode
///
/// This test file verifies the response-only output mode functionality,
/// which removes host:port prefixes from output for cleaner pipeline integration.

#[cfg(test)]
mod response_only_tests {
    use cipherrun::output::response_only::ResponseOnlyFormatter;

    #[test]
    fn test_strip_bracket_format() {
        let output = "[example.com:443] TLS 1.3";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, "TLS 1.3");
    }

    #[test]
    fn test_strip_simple_format() {
        let output = "example.com:443 TLS 1.2";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, "TLS 1.2");
    }

    #[test]
    fn test_multiline_output() {
        let output = "[example.com:443] Protocol Support:\n\
                      [example.com:443]   TLS 1.2\n\
                      [example.com:443]   TLS 1.3";

        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "Protocol Support:");
        assert_eq!(lines[1], "TLS 1.2");
        assert_eq!(lines[2], "TLS 1.3");
    }

    #[test]
    fn test_preserves_content_without_prefix() {
        let output = "TLS 1.3\nTLS_AES_128_GCM_SHA256";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, output);
    }

    #[test]
    fn test_empty_output() {
        let output = "";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, "");
    }

    #[test]
    fn test_different_port() {
        let output = "[example.com:8443] Status: OK";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 8443);

        assert_eq!(result, "Status: OK");
    }

    #[test]
    fn test_whitespace_handling() {
        let output = "[example.com:443]   Data with leading spaces";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, "Data with leading spaces");
    }

    #[test]
    fn test_format_method() {
        let output = "[example.com:443] Certificate: Valid";
        let result = ResponseOnlyFormatter::format(output, "example.com", 443);

        assert_eq!(result, "Certificate: Valid");
    }

    #[test]
    fn test_mixed_format() {
        let output = "[example.com:443] Line 1\n\
                      example.com:443 Line 2\n\
                      [example.com:443] Line 3";

        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "Line 1");
        assert_eq!(lines[1], "Line 2");
        assert_eq!(lines[2], "Line 3");
    }

    #[test]
    fn test_with_dash_separator() {
        let output = "[example.com:443] - Certificate Info";
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        assert_eq!(result, "Certificate Info");
    }

    #[test]
    fn test_ipv6_address() {
        let output = "[[::1]:443] TLS 1.3";
        // Note: This is a simplified test. Real IPv6 handling may need adjustment
        let result = ResponseOnlyFormatter::strip_target_prefix(output, "[::1]", 443);

        // Should handle IPv6 addresses
        assert!(!result.contains("[::1]"));
    }

    #[test]
    fn test_preserves_output_content() {
        let original = "Important: Certificate Expires in 30 days";
        let output = format!("[example.com:443] {}", original);

        let result = ResponseOnlyFormatter::strip_target_prefix(&output, "example.com", 443);

        assert_eq!(result, original);
    }

    #[test]
    fn test_with_newlines() {
        let output = "[example.com:443] Line 1\n\
                      [example.com:443] Line 2\n\
                      [example.com:443] Line 3\n";

        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| !line.contains("example.com")));
    }
}
