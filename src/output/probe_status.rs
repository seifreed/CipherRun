// TLS Probe Status Module
// Tracks and reports connection success/failure status

use crate::error::TlsError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Probe status for connection attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStatus {
    pub success: bool,
    pub error: Option<String>,
    pub error_type: Option<ErrorType>,
    pub connection_time_ms: Option<u64>,
    pub attempts: u32,
}

impl ProbeStatus {
    /// Create successful probe status
    pub fn success(duration: Duration) -> Self {
        Self {
            success: true,
            error: None,
            error_type: None,
            connection_time_ms: Some(duration.as_millis() as u64),
            attempts: 1,
        }
    }

    /// Create failed probe status
    pub fn failure(error: TlsError) -> Self {
        let error_type = ErrorType::from_tls_error(&error);

        Self {
            success: false,
            error: Some(error.to_string()),
            error_type: Some(error_type),
            connection_time_ms: None,
            attempts: 1,
        }
    }

    /// Create failed probe status from string
    pub fn failure_string(error_msg: String, error_type: ErrorType) -> Self {
        Self {
            success: false,
            error: Some(error_msg),
            error_type: Some(error_type),
            connection_time_ms: None,
            attempts: 1,
        }
    }

    /// Create partial success (connection succeeded but scan had issues)
    pub fn partial_success(duration: Duration, warning: String) -> Self {
        Self {
            success: true,
            error: Some(warning),
            error_type: Some(ErrorType::Warning),
            connection_time_ms: Some(duration.as_millis() as u64),
            attempts: 1,
        }
    }

    /// Set number of attempts
    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    /// Get status symbol for terminal output
    pub fn status_symbol(&self) -> &'static str {
        if self.success { "✓" } else { "✗" }
    }

    /// Get status color for terminal output
    pub fn status_color(&self) -> &'static str {
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

    /// Format for terminal output
    pub fn format_terminal(&self, target: &str) -> String {
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
                .map(|e| Self::simplify_error(e))
                .unwrap_or_else(|| "unknown error".to_string());

            format!("{} {} ({})", symbol_colored, target.cyan(), error_msg.red())
        }
    }

    /// Simplify error message for display
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

    /// Get detailed error information
    pub fn detailed_error(&self) -> Option<String> {
        self.error.clone()
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        if self.success {
            return false;
        }

        matches!(
            self.error_type,
            Some(ErrorType::Timeout) | Some(ErrorType::NetworkError)
        )
    }
}

impl Default for ProbeStatus {
    fn default() -> Self {
        Self {
            success: false,
            error: Some("Not attempted".to_string()),
            error_type: Some(ErrorType::NotAttempted),
            connection_time_ms: None,
            attempts: 0,
        }
    }
}

/// Error type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    /// Connection timeout
    Timeout,
    /// Connection refused by server
    ConnectionRefused,
    /// DNS resolution failed
    DnsFailure,
    /// TLS handshake failed
    TlsHandshakeFailed,
    /// Certificate validation error
    CertificateError,
    /// Protocol not supported
    ProtocolNotSupported,
    /// Network error (temporary)
    NetworkError,
    /// Warning (partial success)
    Warning,
    /// Not yet attempted
    NotAttempted,
    /// Unknown error
    Unknown,
}

impl ErrorType {
    /// Determine error type from TlsError
    pub fn from_tls_error(error: &TlsError) -> Self {
        match error {
            TlsError::ConnectionTimeout { .. } => ErrorType::Timeout,
            TlsError::ConnectionRefused { .. } => ErrorType::ConnectionRefused,
            TlsError::DnsResolutionFailed { .. } => ErrorType::DnsFailure,
            TlsError::InvalidHandshake { .. } => ErrorType::TlsHandshakeFailed,
            TlsError::CertificateError(_) => ErrorType::CertificateError,
            TlsError::ProtocolNotSupported { .. } => ErrorType::ProtocolNotSupported,
            TlsError::Timeout { .. } => ErrorType::Timeout,
            TlsError::IoError { .. } => ErrorType::NetworkError,
            _ => ErrorType::Unknown,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ErrorType::Timeout => "Connection timeout",
            ErrorType::ConnectionRefused => "Connection refused",
            ErrorType::DnsFailure => "DNS resolution failed",
            ErrorType::TlsHandshakeFailed => "TLS handshake failed",
            ErrorType::CertificateError => "Certificate error",
            ErrorType::ProtocolNotSupported => "Protocol not supported",
            ErrorType::NetworkError => "Network error",
            ErrorType::Warning => "Warning",
            ErrorType::NotAttempted => "Not attempted",
            ErrorType::Unknown => "Unknown error",
        }
    }
}

/// Probe statistics for multiple targets
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeStatistics {
    pub total_targets: usize,
    pub successful: usize,
    pub failed: usize,
    pub timeouts: usize,
    pub connection_refused: usize,
    pub dns_failures: usize,
    pub tls_failures: usize,
    pub certificate_errors: usize,
    pub total_time_ms: u64,
    pub avg_time_ms: u64,
    pub min_time_ms: Option<u64>,
    pub max_time_ms: Option<u64>,
}

impl ProbeStatistics {
    /// Create statistics from probe results
    #[allow(clippy::field_reassign_with_default)]
    pub fn from_results(results: &[(String, ProbeStatus)]) -> Self {
        let mut stats = ProbeStatistics::default();
        stats.total_targets = results.len();

        let mut connection_times = Vec::new();

        for (_, status) in results {
            if status.success {
                stats.successful += 1;
                if let Some(time_ms) = status.connection_time_ms {
                    connection_times.push(time_ms);
                    stats.total_time_ms += time_ms;
                }
            } else {
                stats.failed += 1;

                match status.error_type {
                    Some(ErrorType::Timeout) => stats.timeouts += 1,
                    Some(ErrorType::ConnectionRefused) => stats.connection_refused += 1,
                    Some(ErrorType::DnsFailure) => stats.dns_failures += 1,
                    Some(ErrorType::TlsHandshakeFailed) => stats.tls_failures += 1,
                    Some(ErrorType::CertificateError) => stats.certificate_errors += 1,
                    _ => {}
                }
            }
        }

        if !connection_times.is_empty() {
            stats.avg_time_ms = stats.total_time_ms / connection_times.len() as u64;
            stats.min_time_ms = connection_times.iter().min().copied();
            stats.max_time_ms = connection_times.iter().max().copied();
        }

        stats
    }

    /// Display statistics summary
    pub fn display(&self) {
        use colored::*;

        println!("\n{}", "Probe Statistics:".cyan().bold());
        println!("{}", "=".repeat(50));

        println!("  Total Targets:        {}", self.total_targets);
        println!(
            "  Successful:           {} ({}%)",
            self.successful.to_string().green(),
            self.success_rate()
        );
        println!(
            "  Failed:               {} ({}%)",
            self.failed.to_string().red(),
            self.failure_rate()
        );

        if self.failed > 0 {
            println!("\n{}", "  Failure Breakdown:".yellow());
            if self.timeouts > 0 {
                println!("    Timeouts:           {}", self.timeouts);
            }
            if self.connection_refused > 0 {
                println!("    Connection Refused: {}", self.connection_refused);
            }
            if self.dns_failures > 0 {
                println!("    DNS Failures:       {}", self.dns_failures);
            }
            if self.tls_failures > 0 {
                println!("    TLS Failures:       {}", self.tls_failures);
            }
            if self.certificate_errors > 0 {
                println!("    Certificate Errors: {}", self.certificate_errors);
            }
        }

        if self.successful > 0 {
            println!("\n{}", "  Connection Times:".cyan());
            println!("    Average:            {}ms", self.avg_time_ms);
            if let Some(min) = self.min_time_ms {
                println!("    Minimum:            {}ms", min);
            }
            if let Some(max) = self.max_time_ms {
                println!("    Maximum:            {}ms", max);
            }
        }

        println!("{}", "=".repeat(50));
    }

    /// Calculate success rate percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_targets == 0 {
            0.0
        } else {
            (self.successful as f64 / self.total_targets as f64) * 100.0
        }
    }

    /// Calculate failure rate percentage
    pub fn failure_rate(&self) -> f64 {
        if self.total_targets == 0 {
            0.0
        } else {
            (self.failed as f64 / self.total_targets as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_status_success() {
        let status = ProbeStatus::success(Duration::from_millis(150));
        assert!(status.success);
        assert_eq!(status.connection_time_ms, Some(150));
        assert_eq!(status.status_symbol(), "✓");
    }

    #[test]
    fn test_probe_status_failure() {
        let error = TlsError::ConnectionTimeout {
            duration: Duration::from_secs(5),
            addr: "127.0.0.1:443".parse().unwrap(),
        };
        let status = ProbeStatus::failure(error);

        assert!(!status.success);
        assert!(status.error.is_some());
        assert_eq!(status.error_type, Some(ErrorType::Timeout));
        assert_eq!(status.status_symbol(), "✗");
    }

    #[test]
    fn test_error_type_from_tls_error() {
        let error = TlsError::ConnectionRefused {
            addr: "127.0.0.1:443".parse().unwrap(),
        };
        let error_type = ErrorType::from_tls_error(&error);
        assert_eq!(error_type, ErrorType::ConnectionRefused);
    }

    #[test]
    fn test_format_terminal() {
        let status = ProbeStatus::success(Duration::from_millis(100));
        let formatted = status.format_terminal("example.com:443");
        assert!(formatted.contains("example.com:443"));
        assert!(formatted.contains("100ms"));
    }

    #[test]
    fn test_probe_statistics() {
        let results = vec![
            (
                "host1".to_string(),
                ProbeStatus::success(Duration::from_millis(100)),
            ),
            (
                "host2".to_string(),
                ProbeStatus::success(Duration::from_millis(200)),
            ),
            (
                "host3".to_string(),
                ProbeStatus::failure(TlsError::ConnectionTimeout {
                    duration: Duration::from_secs(5),
                    addr: "127.0.0.1:443".parse().unwrap(),
                }),
            ),
        ];

        let stats = ProbeStatistics::from_results(&results);
        assert_eq!(stats.total_targets, 3);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.timeouts, 1);
        assert_eq!(stats.avg_time_ms, 150);
    }

    #[test]
    fn test_is_retryable() {
        let timeout_status = ProbeStatus::failure(TlsError::ConnectionTimeout {
            duration: Duration::from_secs(5),
            addr: "127.0.0.1:443".parse().unwrap(),
        });
        assert!(timeout_status.is_retryable());

        let refused_status = ProbeStatus::failure(TlsError::ConnectionRefused {
            addr: "127.0.0.1:443".parse().unwrap(),
        });
        assert!(!refused_status.is_retryable());
    }
}
