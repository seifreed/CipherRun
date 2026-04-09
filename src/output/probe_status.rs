pub use crate::scanner::probe_status::{ErrorType, ProbeStatus};

pub trait ProbeStatusTerminalExt {
    fn status_symbol(&self) -> &'static str;
    fn status_color(&self) -> &'static str;
    fn format_terminal(&self, target: &str) -> String;
    fn format_response_only(&self) -> String;
}

impl ProbeStatusTerminalExt for ProbeStatus {
    fn status_symbol(&self) -> &'static str {
        if self.success { "✓" } else { "✗" }
    }

    fn status_color(&self) -> &'static str {
        if self.success && matches!(self.error_type, Some(ErrorType::Warning)) {
            "yellow"
        } else if self.success {
            "green"
        } else {
            match &self.error_type {
                Some(ErrorType::Timeout) => "yellow",
                Some(ErrorType::ConnectionRefused) => "red",
                Some(ErrorType::DnsFailure) => "red",
                Some(ErrorType::TlsHandshakeFailed) => "red",
                Some(ErrorType::CertificateError) => "yellow",
                Some(ErrorType::ProtocolNotSupported) => "yellow",
                Some(ErrorType::Warning) => "yellow",
                _ => "red",
            }
        }
    }

    fn format_terminal(&self, target: &str) -> String {
        self.format_terminal_internal(Some(target))
    }

    fn format_response_only(&self) -> String {
        self.format_terminal_internal(None)
    }
}

impl ProbeStatus {
    fn format_terminal_internal(&self, target: Option<&str>) -> String {
        use colored::*;

        let symbol = self.status_symbol();
        let is_warning = self.success && matches!(self.error_type, Some(ErrorType::Warning));
        let symbol_colored = if is_warning {
            symbol.yellow()
        } else if self.success {
            symbol.green()
        } else {
            symbol.red()
        };

        if self.success {
            if is_warning {
                let warning_msg = self
                    .error
                    .as_ref()
                    .map(|e| simplify_error(e))
                    .unwrap_or_else(|| "warning".to_string());

                if let Some(time_ms) = self.connection_time_ms {
                    if let Some(target) = target {
                        format!(
                            "{} {} (connected in {}ms, warning: {})",
                            symbol_colored,
                            target.cyan(),
                            time_ms,
                            warning_msg.yellow()
                        )
                    } else {
                        format!(
                            "{} (connected in {}ms, warning: {})",
                            symbol_colored,
                            time_ms,
                            warning_msg.yellow()
                        )
                    }
                } else {
                    if let Some(target) = target {
                        format!(
                            "{} {} (warning: {})",
                            symbol_colored,
                            target.cyan(),
                            warning_msg.yellow()
                        )
                    } else {
                        format!("{} (warning: {})", symbol_colored, warning_msg.yellow())
                    }
                }
            } else if let Some(time_ms) = self.connection_time_ms {
                if let Some(target) = target {
                    format!(
                        "{} {} (connected in {}ms)",
                        symbol_colored,
                        target.cyan(),
                        time_ms
                    )
                } else {
                    format!("{} (connected in {}ms)", symbol_colored, time_ms)
                }
            } else {
                if let Some(target) = target {
                    format!("{} {}", symbol_colored, target.cyan())
                } else {
                    format!("{}", symbol_colored)
                }
            }
        } else {
            let error_msg = self
                .error
                .as_ref()
                .map(|e| simplify_error(e))
                .unwrap_or_else(|| "unknown error".to_string());

            if let Some(target) = target {
                format!("{} {} ({})", symbol_colored, target.cyan(), error_msg.red())
            } else {
                format!("{} ({})", symbol_colored, error_msg.red())
            }
        }
    }
}

fn simplify_error(error: &str) -> String {
    if error.contains("Connection timeout") {
        "connection timeout".to_string()
    } else if error.contains("Connection refused") {
        "connection refused".to_string()
    } else if error.contains("DNS resolution failed") {
        "DNS resolution failed".to_string()
    } else if error.contains("Certificate") {
        "certificate error".to_string()
    } else if error.contains("not supported") {
        "protocol not supported".to_string()
    } else if error.len() > 60 {
        format!("{}...", truncate_to_boundary(error, 57))
    } else {
        error.to_string()
    }
}

fn truncate_to_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }

    let boundary = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max_bytes)
        .last()
        .unwrap_or(0);

    &s[..boundary]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_probe_status_success() {
        let status = ProbeStatus::success(Duration::from_millis(123));
        assert!(status.success);
        assert_eq!(status.status_symbol(), "✓");
        assert!(status.format_terminal("example.com").contains("123ms"));
    }

    #[test]
    fn test_probe_status_failure() {
        let status = ProbeStatus::failure_string(
            "Connection refused".to_string(),
            ErrorType::ConnectionRefused,
        );
        assert!(!status.success);
        assert_eq!(status.status_symbol(), "✗");
        assert!(
            status
                .format_terminal("example.com")
                .contains("connection refused")
        );
    }

    #[test]
    fn test_probe_status_partial_success_warning_rendering() {
        let status = ProbeStatus::partial_success(
            Duration::from_millis(123),
            "TLS fallback used".to_string(),
        );

        assert!(status.success);
        assert_eq!(status.status_color(), "yellow");

        let output = status.format_terminal("example.com");
        assert!(output.contains("123ms"));
        assert!(output.contains("warning"));
        assert!(output.contains("TLS fallback used"));
    }

    #[test]
    fn test_probe_status_response_only_omits_target() {
        let status = ProbeStatus::partial_success(
            Duration::from_millis(42),
            "TLS fallback used".to_string(),
        );

        let output = status.format_response_only();
        assert!(output.contains("42ms"));
        assert!(output.contains("warning"));
        assert!(output.contains("TLS fallback used"));
        assert!(!output.contains("example.com"));
    }

    #[test]
    fn test_probe_status_simplify_error_truncates_utf8_safely() {
        let long_error = "错误".repeat(40);
        let simplified = simplify_error(&long_error);

        assert!(simplified.ends_with("..."));
        assert!(simplified.len() <= 60);
        assert!(simplified.is_char_boundary(simplified.len()));
    }
}
