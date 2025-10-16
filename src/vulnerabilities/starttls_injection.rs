// STARTTLS Injection Vulnerability Test
// Tests for command injection during STARTTLS protocol upgrade

use crate::Result;
use crate::utils::network::Target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// Test for STARTTLS injection vulnerabilities
///
/// This vulnerability allows attackers to inject commands before the TLS handshake
/// completes, potentially bypassing authentication or executing arbitrary commands.
///
/// References:
/// - CVE-2011-0411 (Postfix SMTP injection)
/// - "A Real-World Analysis of the STARTTLS Vulnerabilities" (2021)
pub struct StarttlsInjectionTester {
    target: Target,
}

impl StarttlsInjectionTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test SMTP STARTTLS injection
    pub async fn test_smtp_injection(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        // Try to connect with timeout
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Test 1: Command injection before STARTTLS completes
        if self.test_command_injection_smtp(stream).await? {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test command injection in SMTP STARTTLS
    async fn test_command_injection_smtp(&self, mut stream: TcpStream) -> Result<bool> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("220") {
            return Ok(false);
        }

        // Send EHLO
        stream.write_all(b"EHLO test.local\r\n").await?;
        let _n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;

        // Send STARTTLS followed immediately by injected command
        // A vulnerable server will execute the injected command before TLS upgrade
        let injection_payload = b"STARTTLS\r\nMAIL FROM:<injection@test.com>\r\n";
        stream.write_all(injection_payload).await?;

        // Read response
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        // If server accepts the injected MAIL FROM before TLS, it's vulnerable
        // Expected: Only "220 Ready to start TLS"
        // Vulnerable: "220 Ready..." followed by "250 OK" for MAIL FROM
        if response.contains("250") && response.contains("220") {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test IMAP STARTTLS injection
    pub async fn test_imap_injection(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        self.test_command_injection_imap(stream).await
    }

    /// Test command injection in IMAP STARTTLS
    async fn test_command_injection_imap(&self, mut stream: TcpStream) -> Result<bool> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("* OK") {
            return Ok(false);
        }

        // Send CAPABILITY to check STARTTLS support
        stream.write_all(b"a001 CAPABILITY\r\n").await?;
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.contains("STARTTLS") {
            return Ok(false);
        }

        // Attempt injection: STARTTLS followed by LOGIN command
        let injection_payload = b"a002 STARTTLS\r\na003 LOGIN test test\r\n";
        stream.write_all(injection_payload).await?;

        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        // Vulnerable if server processes LOGIN before TLS upgrade
        if response.contains("a003") {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test POP3 STARTTLS injection
    pub async fn test_pop3_injection(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.target.hostname, self.target.port);

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        self.test_command_injection_pop3(stream).await
    }

    /// Test command injection in POP3 STARTTLS
    async fn test_command_injection_pop3(&self, mut stream: TcpStream) -> Result<bool> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("+OK") {
            return Ok(false);
        }

        // Check STLS support
        stream.write_all(b"CAPA\r\n").await?;
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.contains("STLS") {
            return Ok(false);
        }

        // Attempt injection: STLS followed by USER command
        let injection_payload = b"STLS\r\nUSER injection\r\n";
        stream.write_all(injection_payload).await?;

        let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
        let response = String::from_utf8_lossy(&buf[..n]);

        // Vulnerable if USER command is processed before TLS
        if response.matches("+OK").count() >= 2 {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test all STARTTLS injection vectors
    pub async fn test_all(&self) -> Result<StarttlsInjectionResult> {
        let mut result = StarttlsInjectionResult {
            vulnerable: false,
            smtp_vulnerable: false,
            imap_vulnerable: false,
            pop3_vulnerable: false,
            details: Vec::new(),
        };

        // Test SMTP injection (port 25, 587)
        if self.target.port == 25 || self.target.port == 587 {
            match self.test_smtp_injection().await {
                Ok(vuln) => {
                    result.smtp_vulnerable = vuln;
                    if vuln {
                        result.vulnerable = true;
                        result.details.push(
                            "SMTP STARTTLS injection detected - commands can be injected before TLS upgrade".to_string()
                        );
                    }
                }
                Err(e) => {
                    result.details.push(format!("SMTP test error: {}", e));
                }
            }
        }

        // Test IMAP injection (port 143)
        if self.target.port == 143 {
            match self.test_imap_injection().await {
                Ok(vuln) => {
                    result.imap_vulnerable = vuln;
                    if vuln {
                        result.vulnerable = true;
                        result.details.push(
                            "IMAP STARTTLS injection detected - commands can be injected before TLS upgrade".to_string()
                        );
                    }
                }
                Err(e) => {
                    result.details.push(format!("IMAP test error: {}", e));
                }
            }
        }

        // Test POP3 injection (port 110)
        if self.target.port == 110 {
            match self.test_pop3_injection().await {
                Ok(vuln) => {
                    result.pop3_vulnerable = vuln;
                    if vuln {
                        result.vulnerable = true;
                        result.details.push(
                            "POP3 STARTTLS injection detected - commands can be injected before TLS upgrade".to_string()
                        );
                    }
                }
                Err(e) => {
                    result.details.push(format!("POP3 test error: {}", e));
                }
            }
        }

        // If not a standard STARTTLS port, mark as not applicable
        if result.details.is_empty() {
            result.details.push(format!(
                "Port {} is not a standard STARTTLS port (25, 143, 110, 587)",
                self.target.port
            ));
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct StarttlsInjectionResult {
    pub vulnerable: bool,
    pub smtp_vulnerable: bool,
    pub imap_vulnerable: bool,
    pub pop3_vulnerable: bool,
    pub details: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starttls_injection_struct() {
        let result = StarttlsInjectionResult {
            vulnerable: true,
            smtp_vulnerable: true,
            imap_vulnerable: false,
            pop3_vulnerable: false,
            details: vec!["Test".to_string()],
        };

        assert!(result.vulnerable);
        assert!(result.smtp_vulnerable);
    }
}
