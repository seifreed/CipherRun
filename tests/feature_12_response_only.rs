/// Tests for Feature 12: Response-Only Output Mode
///
/// This test file verifies the response-only output mode functionality,
/// which removes host:port prefixes from output for cleaner pipeline integration.
#[cfg(test)]
mod response_only_tests {
    use cipherrun::output::response_only::ResponseOnlyFormatter;

    #[test]
    fn test_strip_target_prefix_cases() {
        for (name, output, host, port, expected) in [
            (
                "bracket",
                "[example.com:443] TLS 1.3",
                "example.com",
                443,
                "TLS 1.3",
            ),
            (
                "simple",
                "example.com:443 TLS 1.2",
                "example.com",
                443,
                "TLS 1.2",
            ),
            (
                "multiline",
                "[example.com:443] Protocol Support:\n\
                 [example.com:443]   TLS 1.2\n\
                 [example.com:443]   TLS 1.3",
                "example.com",
                443,
                "Protocol Support:\nTLS 1.2\nTLS 1.3",
            ),
            (
                "without prefix",
                "TLS 1.3\nTLS_AES_128_GCM_SHA256",
                "example.com",
                443,
                "TLS 1.3\nTLS_AES_128_GCM_SHA256",
            ),
            ("empty", "", "example.com", 443, ""),
            (
                "different port",
                "[example.com:8443] Status: OK",
                "example.com",
                8443,
                "Status: OK",
            ),
            (
                "whitespace",
                "[example.com:443]   Data with leading spaces",
                "example.com",
                443,
                "Data with leading spaces",
            ),
            (
                "mixed",
                "[example.com:443] Line 1\n\
                 example.com:443 Line 2\n\
                 [example.com:443] Line 3",
                "example.com",
                443,
                "Line 1\nLine 2\nLine 3",
            ),
            (
                "dash separator",
                "[example.com:443] - Certificate Info",
                "example.com",
                443,
                "Certificate Info",
            ),
            ("ipv6", "[::1]:443 TLS 1.3", "::1", 443, "TLS 1.3"),
            (
                "preserves content",
                "[example.com:443] Important: Certificate Expires in 30 days",
                "example.com",
                443,
                "Important: Certificate Expires in 30 days",
            ),
            (
                "trailing newline",
                "[example.com:443] Line 1\n\
                 [example.com:443] Line 2\n\
                 [example.com:443] Line 3\n",
                "example.com",
                443,
                "Line 1\nLine 2\nLine 3",
            ),
        ] {
            assert_eq!(
                ResponseOnlyFormatter::strip_target_prefix(output, host, port),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn test_format_method() {
        let output = "[example.com:443] Certificate: Valid";
        let result = ResponseOnlyFormatter::format(output, "example.com", 443);

        assert_eq!(result, "Certificate: Valid");
    }
}
