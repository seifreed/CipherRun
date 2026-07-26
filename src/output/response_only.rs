/// Response-Only Output Mode - Output scan data without host:port prefix
///
/// This module provides functionality to format scan results as response-only
/// output, which removes the "host:port" prefix from output lines. This is useful
/// for pipeline integration where the input target is already known and adding
/// the target prefix to every line would be redundant.
///
/// # Example
/// Normal output:
/// ```text
/// example.com:443 TLS 1.3
/// example.com:443 TLS_AES_128_GCM_SHA256
/// ```
///
/// Response-only output:
/// ```text
/// TLS 1.3
/// TLS_AES_128_GCM_SHA256
/// ```
use crate::utils::network::canonical_target;

/// Response-only output formatter
pub struct ResponseOnlyFormatter;

impl ResponseOnlyFormatter {
    /// Format scan results as response-only output (no host:port prefix)
    ///
    /// This removes the "[host:port]" or "host:port" prefix from the beginning
    /// of output lines, keeping only the actual data portion.
    ///
    /// # Arguments
    /// * `normal_output` - The normally formatted output (with host:port prefix)
    /// * `hostname` - The target hostname
    /// * `port` - The target port number
    ///
    /// # Returns
    /// The formatted output without host:port prefixes
    ///
    /// # Examples
    /// ```ignore
    /// let response_only = ResponseOnlyFormatter::format(&normal_output, "example.com", 443);
    /// ```
    pub fn format(normal_output: &str, hostname: &str, port: u16) -> String {
        Self::strip_target_prefix(normal_output, hostname, port)
    }

    /// Format scan results as response-only output from plain text
    ///
    /// This is the core implementation that strips the target prefix from output.
    ///
    /// # Arguments
    /// * `output` - The original formatted output
    /// * `hostname` - The target hostname
    /// * `port` - The target port
    ///
    /// # Returns
    /// The output with all target prefixes removed
    pub fn strip_target_prefix(output: &str, hostname: &str, port: u16) -> String {
        let mut result = String::new();
        let hostname = hostname
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(hostname);
        let canonical = canonical_target(hostname, port);
        let bracketed_canonical = if canonical.starts_with('[') {
            canonical.clone()
        } else {
            format!("[{}]", canonical)
        };

        // Common prefix patterns to strip:
        // - "[hostname:port]"
        // - "hostname:port"
        // - "[hostname:443]" (with port)
        let prefix_patterns = [
            bracketed_canonical,              // [host:port] or [ipv6]:port
            canonical,                        // host:port or [ipv6]:port
            format!("{}:{}", hostname, port), // hostname:port
            format!("[{}]", hostname),        // [hostname] (no port)
            hostname.to_string(),             // just hostname
        ];

        for line in output.lines() {
            let stripped = Self::strip_line_prefix(line, &prefix_patterns);
            if !stripped.is_empty() {
                result.push_str(&stripped);
                result.push('\n');
            }
        }

        // Remove trailing newline if present
        result.trim_end().to_string()
    }

    /// Strip target prefix from a single line
    ///
    /// Removes the first matching prefix pattern, leaving only the content after it.
    /// Also trims any leading/trailing whitespace from the result.
    fn strip_line_prefix(line: &str, patterns: &[String]) -> String {
        for pattern in patterns {
            if let Some(remainder) = line.strip_prefix(pattern) {
                if !Self::has_valid_prefix_boundary(pattern, remainder) {
                    continue;
                }

                let remainder = remainder.trim();
                // Also handle cases where there might be extra separators
                let cleaned = remainder
                    .trim_start_matches('-')
                    .trim_start_matches(':')
                    .trim();
                // Return cleaned result - empty string means just a prefix with no data
                // This allows the caller to filter out lines that are just prefixes
                return cleaned.to_string();
            }
        }

        // If no prefix matched, return the line as-is (but trimmed)
        line.trim().to_string()
    }

    fn has_valid_prefix_boundary(pattern: &str, remainder: &str) -> bool {
        match remainder.chars().next() {
            None => true,
            Some(next) if pattern.contains(':') => {
                next.is_whitespace() || matches!(next, '-' | ':')
            }
            Some(next) if pattern.starts_with('[') => next.is_whitespace(),
            Some(next) => next.is_whitespace(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_line_prefix() {
        let patterns = vec![
            "[example.com:443]".to_string(),
            "example.com:443".to_string(),
            "[example.com]".to_string(),
            "example.com".to_string(),
        ];

        for (line, expected) in [
            ("[example.com:443] TLS 1.3", "TLS 1.3"),
            ("example.com:443 TLS 1.3", "TLS 1.3"),
            ("example.com:443 - TLS 1.3", "TLS 1.3"),
            ("TLS 1.3", "TLS 1.3"),
            ("example.com:443 -- TLS 1.2", "TLS 1.2"),
        ] {
            assert_eq!(
                ResponseOnlyFormatter::strip_line_prefix(line, &patterns),
                expected
            );
        }
    }

    #[test]
    fn test_strip_target_prefix_cases() {
        for (name, output, host, expected) in [
            (
                "target prefix",
                "[example.com:443] TLS 1.3\n[example.com:443] TLS_AES_128_GCM_SHA256\n",
                "example.com",
                "TLS 1.3\nTLS_AES_128_GCM_SHA256",
            ),
            ("empty output", "", "example.com", ""),
            (
                "multiline",
                "[example.com:443] Supported Protocols:\n\
                 [example.com:443]   TLS 1.2\n\
                 [example.com:443]   TLS 1.3\n",
                "example.com",
                "Supported Protocols:\nTLS 1.2\nTLS 1.3",
            ),
            ("line only prefix", "example.com:443\n", "example.com", ""),
            (
                "bracket hostname only",
                "[example.com] TLS 1.2\n",
                "example.com",
                "TLS 1.2",
            ),
            (
                "omits empty lines",
                "[example.com:443] -\n[example.com:443] TLS 1.2\n",
                "example.com",
                "TLS 1.2",
            ),
            (
                "ignores other hosts",
                "other.com:443 TLS 1.2\n[example.com:443] TLS 1.3\n",
                "example.com",
                "other.com:443 TLS 1.2\nTLS 1.3",
            ),
            (
                "hostname only",
                "example.com TLS 1.2\nexample.com:443 TLS 1.3\n",
                "example.com",
                "TLS 1.2\nTLS 1.3",
            ),
            ("ipv6", "[::1]:443 TLS 1.3\n", "::1", "TLS 1.3"),
            (
                "hostname prefix substrings",
                "example.comparison TLS 1.3\nexample.com:443comparison TLS 1.2\n",
                "example.com",
                "example.comparison TLS 1.3\nexample.com:443comparison TLS 1.2",
            ),
        ] {
            assert_eq!(
                ResponseOnlyFormatter::strip_target_prefix(output, host, 443),
                expected,
                "{name}"
            );
        }
    }
}
