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
        // Improved detection: Check for specific response patterns
        // A vulnerable server will respond to the USER command with +OK
        // An invulnerable server will either:
        // 1. Ignore the injection (only response to STLS)
        // 2. Return an error about the unexpected command
        // 3. Close the connection
        
        // Count +OK responses that specifically indicate command processing
        let ok_responses: Vec<&str> = response.lines()
            .filter(|line| line.starts_with("+OK"))
            .collect();
        
        // Vulnerable if we got more than one +OK response
        // (one for STLS, one for the injected USER command)
        if ok_responses.len() >= 2 {
            // Verify the second +OK is related to USER command processing
            // by checking if it mentions user/authentication
            let has_user_response = response.lines()
                .skip_while(|line| !line.contains("STLS"))
                .any(|line| line.contains("+OK") && 
                    (line.to_lowercase().contains("user") || 
                     line.to_lowercase().contains("auth") ||
                     line.to_lowercase().contains("login")));
            
            return Ok(has_user_response);
        }
        
        // Check if the injected command caused any visible effect
        // (error message about unknown command confirms no injection)
        let has_error_response = response.lines()
            .any(|line| line.to_lowercase().contains("error") || 
                        line.to_lowercase().contains("unknown") ||
                        line.to_lowercase().contains("bad"));
        
        // If we got error responses, the server properly handled the injection
        Ok(false && !has_error_response)
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
    use tokio::net::TcpListener;
    use tokio::time::timeout;

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

    #[test]
    fn test_starttls_injection_debug_contains_details() {
        let result = StarttlsInjectionResult {
            vulnerable: false,
            smtp_vulnerable: false,
            imap_vulnerable: false,
            pop3_vulnerable: false,
            details: vec!["Detail A".to_string()],
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("Detail A"));
    }

    async fn start_scripted_server(greeting: &'static [u8], responses: Vec<&'static [u8]>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let port = listener
            .local_addr()
            .expect("test assertion should succeed")
            .port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(greeting).await;
                let mut buf = [0u8; 4096];

                for response in responses {
                    let _ = timeout(Duration::from_secs(2), socket.read(&mut buf)).await;
                    let _ = socket.write_all(response).await;
                }
            }
        });

        port
    }

    #[tokio::test]
    async fn test_smtp_injection_vulnerable() {
        let port = start_scripted_server(
            b"220 smtp.example\r\n",
            vec![
                b"250-smtp.example\r\n250 STARTTLS\r\n",
                b"220 Ready to start TLS\r\n250 OK\r\n",
            ],
        )
        .await;

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let vulnerable = tester
            .test_smtp_injection()
            .await
            .expect("test assertion should succeed");
        assert!(vulnerable);
    }

    #[tokio::test]
    async fn test_smtp_injection_not_vulnerable() {
        let port = start_scripted_server(
            b"220 smtp.example\r\n",
            vec![b"250-smtp.example\r\n250 STARTTLS\r\n", b"220 Ready\r\n"],
        )
        .await;

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let vulnerable = tester
            .test_smtp_injection()
            .await
            .expect("test assertion should succeed");
        assert!(!vulnerable);
    }

    #[tokio::test]
    async fn test_imap_injection_vulnerable() {
        let port = start_scripted_server(
            b"* OK IMAP4rev1\r\n",
            vec![
                b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK\r\n",
                b"a002 OK Begin TLS\r\na003 OK LOGIN\r\n",
            ],
        )
        .await;

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let vulnerable = tester
            .test_imap_injection()
            .await
            .expect("test assertion should succeed");
        assert!(vulnerable);
    }

    #[tokio::test]
    async fn test_pop3_injection_vulnerable() {
        let port = start_scripted_server(
            b"+OK POP3 server\r\n",
            vec![b"+OK CAPA\r\nSTLS\r\n.\r\n", b"+OK STLS\r\n+OK USER\r\n"],
        )
        .await;

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let vulnerable = tester
            .test_pop3_injection()
            .await
            .expect("test assertion should succeed");
        assert!(vulnerable);
    }

    #[tokio::test]
    async fn test_non_starttls_port_details() {
        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            9999,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let result = tester
            .test_all()
            .await
            .expect("test assertion should succeed");
        assert!(!result.vulnerable);
        assert!(
            result
                .details
                .iter()
                .any(|d| d.contains("not a standard STARTTLS port"))
        );
    }
}
