pub use crate::scanner::probe_status::{ErrorType, ProbeStatus};

pub trait ProbeStatusTerminalExt {
    fn status_symbol(&self) -> &'static str;
    fn status_color(&self) -> &'static str;
    fn format_terminal(&self, target: &str) -> String;
}

impl ProbeStatusTerminalExt for ProbeStatus {
    fn status_symbol(&self) -> &'static str {
        if self.success { "✓" } else { "✗" }
    }

    fn status_color(&self) -> &'static str {
        if self.success {
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
        use colored::*;

        let symbol = self.status_symbol();
        let symbol_colored = if self.success {
            symbol.green()
        } else {
            symbol.red()
        };

        if self.success {
            if let Some(time_ms) = self.connection_time_ms {
                format!(
                    "{} {} (connected in {}ms)",
                    symbol_colored,
                    target.cyan(),
                    time_ms
                )
            } else {
                format!("{} {}", symbol_colored, target.cyan())
            }
        } else {
            let error_msg = self
                .error
                .as_ref()
                .map(|e| simplify_error(e))
                .unwrap_or_else(|| "unknown error".to_string());

            format!("{} {} ({})", symbol_colored, target.cyan(), error_msg.red())
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
        format!("{}...", &error[..57])
    } else {
        error.to_string()
    }
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
        assert!(status.format_terminal("example.com").contains("connection refused"));
    }
}
