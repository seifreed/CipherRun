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

        // Common prefix patterns to strip:
        // - "[hostname:port]"
        // - "hostname:port"
        // - "[hostname:443]" (with port)
        let prefix_patterns = [
            format!("[{}:{}]", hostname, port),    // [hostname:port]
            format!("{}:{}", hostname, port),      // hostname:port
            format!("[{}]", hostname),             // [hostname] (no port)
            hostname.to_string(),                   // just hostname
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
            if line.starts_with(pattern) {
                let remainder = line[pattern.len()..].trim();
                // Also handle cases where there might be extra separators
                let cleaned = remainder.trim_start_matches('-').trim_start_matches(':').trim();
                if !cleaned.is_empty() {
                    return cleaned.to_string();
                }
            }
        }

        // If no prefix matched, return the line as-is (but trimmed)
        line.trim().to_string()
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

        // Test with bracket format
        let result = ResponseOnlyFormatter::strip_line_prefix(
            "[example.com:443] TLS 1.3",
            &patterns,
        );
        assert_eq!(result, "TLS 1.3");

        // Test with simple format
        let result =
            ResponseOnlyFormatter::strip_line_prefix("example.com:443 TLS 1.3", &patterns);
        assert_eq!(result, "TLS 1.3");

        // Test with colon separator
        let result = ResponseOnlyFormatter::strip_line_prefix(
            "example.com:443 - TLS 1.3",
            &patterns,
        );
        assert_eq!(result, "TLS 1.3");

        // Test without prefix (should return as-is)
        let result =
            ResponseOnlyFormatter::strip_line_prefix("TLS 1.3", &patterns);
        assert_eq!(result, "TLS 1.3");
    }

    #[test]
    fn test_strip_target_prefix() {
        let output = "[example.com:443] TLS 1.3\n[example.com:443] TLS_AES_128_GCM_SHA256\n";

        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "TLS 1.3");
        assert_eq!(lines[1], "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn test_empty_output() {
        let result = ResponseOnlyFormatter::strip_target_prefix("", "example.com", 443);
        assert_eq!(result, "");
    }

    #[test]
    fn test_multiline_output() {
        let output = "[example.com:443] Supported Protocols:\n\
                      [example.com:443]   TLS 1.2\n\
                      [example.com:443]   TLS 1.3\n";

        let result = ResponseOnlyFormatter::strip_target_prefix(output, "example.com", 443);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines[0], "Supported Protocols:");
        assert_eq!(lines[1], "TLS 1.2");
        assert_eq!(lines[2], "TLS 1.3");
    }
}
