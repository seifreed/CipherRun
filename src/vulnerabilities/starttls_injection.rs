// STARTTLS Injection Vulnerability Test
// Tests for command injection during STARTTLS protocol upgrade

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StarttlsInjectionStatus {
    Vulnerable,
    NotVulnerable,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StarttlsInjectionProtocol {
    Smtp,
    Imap,
    Pop3,
}

impl StarttlsInjectionProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::Smtp => "SMTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
        }
    }
}

impl StarttlsInjectionTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Check if a response code appears at the start of any line in the response.
    /// This prevents false positives from codes appearing in the middle of text
    /// (e.g., in hostnames, error messages, or certificate data).
    ///
    /// SMTP/IMAP/POP3 response codes must appear at the beginning of a line
    /// per their respective RFCs.
    fn response_code_at_line_start(response: &str, code: &str) -> bool {
        response.lines().any(|line| line.starts_with(code))
    }

    /// Find the position of a response code at the start of a line.
    /// Returns the byte position if found, or None if not found.
    /// This is used to verify the order of responses in multi-line responses.
    fn find_response_code_at_line_start(response: &str, code: &str) -> Option<usize> {
        let mut pos = 0;
        for line in response.lines() {
            if let Some(after) = line.strip_prefix(code)
                && (after.is_empty() || after.starts_with(' ') || after.starts_with('-'))
            {
                return Some(pos);
            }
            // +1 for the newline character that .lines() removes
            pos += line.len() + 1;
        }
        None
    }

    fn line_has_ascii_token(line: &str, token: &str) -> bool {
        line.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| part.eq_ignore_ascii_case(token))
    }

    fn response_has_ascii_token(response: &str, token: &str) -> bool {
        response
            .lines()
            .any(|line| Self::line_has_ascii_token(line, token))
    }

    /// Test SMTP STARTTLS injection
    pub async fn test_smtp_injection(&self) -> Result<bool> {
        Ok(matches!(
            self.test_smtp_injection_status().await?,
            StarttlsInjectionStatus::Vulnerable
        ))
    }

    async fn test_smtp_injection_status(&self) -> Result<StarttlsInjectionStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // Try to connect with timeout
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(StarttlsInjectionStatus::Inconclusive),
            };

        self.test_command_injection_smtp(stream).await
    }

    /// Test command injection in SMTP STARTTLS
    async fn test_command_injection_smtp(
        &self,
        mut stream: TcpStream,
    ) -> Result<StarttlsInjectionStatus> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("220") {
            return Ok(StarttlsInjectionStatus::NotVulnerable);
        }

        // Send EHLO
        stream.write_all(b"EHLO test.local\r\n").await?;
        match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        }

        // Send STARTTLS followed immediately by injected command
        // A vulnerable server will execute the injected command before TLS upgrade
        let injection_payload = b"STARTTLS\r\nMAIL FROM:<injection@test.com>\r\n";
        stream.write_all(injection_payload).await?;

        // Read response
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        // If server accepts the injected MAIL FROM before TLS, it's vulnerable.
        // Expected: Only "220 Ready to start TLS" (no "250" at all)
        // Vulnerable: "220 Ready..." followed by "250 OK" for the injected MAIL FROM
        //
        // We verify ORDER: "250" must appear AFTER "220" to confirm the server
        // processed the injected command after acknowledging STARTTLS.
        // IMPORTANT: We check that codes appear at the START of lines to avoid
        // false positives from these strings appearing in hostnames, banners, or
        // other parts of the response.
        if let Some(pos_220) = Self::find_response_code_at_line_start(&response, "220")
            && let Some(pos_250) = Self::find_response_code_at_line_start(&response, "250")
            && pos_250 > pos_220
        {
            return Ok(StarttlsInjectionStatus::Vulnerable);
        }

        Ok(StarttlsInjectionStatus::NotVulnerable)
    }

    /// Test IMAP STARTTLS injection
    pub async fn test_imap_injection(&self) -> Result<bool> {
        Ok(matches!(
            self.test_imap_injection_status().await?,
            StarttlsInjectionStatus::Vulnerable
        ))
    }

    async fn test_imap_injection_status(&self) -> Result<StarttlsInjectionStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(StarttlsInjectionStatus::Inconclusive),
            };

        self.test_command_injection_imap(stream).await
    }

    /// Test command injection in IMAP STARTTLS
    async fn test_command_injection_imap(
        &self,
        mut stream: TcpStream,
    ) -> Result<StarttlsInjectionStatus> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("* OK") {
            return Ok(StarttlsInjectionStatus::NotVulnerable);
        }

        // Send CAPABILITY to check STARTTLS support
        stream.write_all(b"a001 CAPABILITY\r\n").await?;
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        if !Self::response_has_ascii_token(&response, "STARTTLS") {
            return Ok(StarttlsInjectionStatus::NotVulnerable);
        }

        // Attempt injection: STARTTLS followed by LOGIN command
        let injection_payload = b"a002 STARTTLS\r\na003 LOGIN test test\r\n";
        stream.write_all(injection_payload).await?;

        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        // Vulnerable if server processes LOGIN before TLS upgrade
        // IMAP responses are tagged with the command tag at the start of the line
        // Format: "a003 STATUS message" - we check for this at line start to avoid
        // false positives from the tag appearing in other parts of the response
        if Self::response_code_at_line_start(&response, "a003") {
            return Ok(StarttlsInjectionStatus::Vulnerable);
        }

        Ok(StarttlsInjectionStatus::NotVulnerable)
    }

    /// Test POP3 STARTTLS injection
    pub async fn test_pop3_injection(&self) -> Result<bool> {
        Ok(matches!(
            self.test_pop3_injection_status().await?,
            StarttlsInjectionStatus::Vulnerable
        ))
    }

    async fn test_pop3_injection_status(&self) -> Result<StarttlsInjectionStatus> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(StarttlsInjectionStatus::Inconclusive),
            };

        self.test_command_injection_pop3(stream).await
    }

    /// Test command injection in POP3 STARTTLS
    async fn test_command_injection_pop3(
        &self,
        mut stream: TcpStream,
    ) -> Result<StarttlsInjectionStatus> {
        let mut buf = vec![0u8; 4096];

        // Read server greeting
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("+OK") {
            return Ok(StarttlsInjectionStatus::NotVulnerable);
        }

        // Check STLS support
        stream.write_all(b"CAPA\r\n").await?;
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        if !Self::response_has_ascii_token(&response, "STLS") {
            return Ok(StarttlsInjectionStatus::NotVulnerable);
        }

        // Attempt injection: STLS followed by USER command
        let injection_payload = b"STLS\r\nUSER injection\r\n";
        stream.write_all(injection_payload).await?;

        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(StarttlsInjectionStatus::Inconclusive),
        };
        let response = String::from_utf8_lossy(&buf[..n]);

        // Vulnerable if USER command is processed before TLS
        // Improved detection: Check for specific response patterns
        // A vulnerable server will respond to the USER command with +OK
        // An invulnerable server will either:
        // 1. Ignore the injection (only response to STLS)
        // 2. Return an error about the unexpected command
        // 3. Close the connection

        // Count +OK responses that specifically indicate command processing
        let ok_responses: Vec<&str> = response
            .lines()
            .filter(|line| line.starts_with("+OK"))
            .collect();

        // Vulnerable if we got more than one +OK response
        // (one for STLS, one for the injected USER command)
        if ok_responses.len() >= 2 {
            // Verify the second +OK is related to USER command processing
            // by checking if it mentions user/authentication
            let has_user_response = response
                .lines()
                .skip_while(|line| !Self::line_has_ascii_token(line, "STLS"))
                .any(|line| {
                    line.contains("+OK")
                        && (line.to_lowercase().contains("user")
                            || line.to_lowercase().contains("auth")
                            || line.to_lowercase().contains("login"))
                });

            return Ok(if has_user_response {
                StarttlsInjectionStatus::Vulnerable
            } else {
                StarttlsInjectionStatus::NotVulnerable
            });
        }

        // With only one +OK and no clear evidence of command processing,
        // we cannot confirm vulnerability. The server may have silently
        // ignored the injection or closed the connection.
        // Default to not vulnerable to avoid false positives.
        Ok(StarttlsInjectionStatus::NotVulnerable)
    }

    /// Test all STARTTLS injection vectors
    pub async fn test_all(&self) -> Result<StarttlsInjectionResult> {
        let mut result = StarttlsInjectionResult {
            vulnerable: false,
            smtp_vulnerable: false,
            imap_vulnerable: false,
            pop3_vulnerable: false,
            inconclusive: false,
            details: Vec::new(),
        };
        let mut tested_standard_port = false;

        // Test SMTP injection (port 25, 587)
        if self.target.port == 25 || self.target.port == 587 {
            tested_standard_port = true;
            match self.test_smtp_injection_status().await {
                Ok(status) => {
                    Self::record_probe_status(&mut result, StarttlsInjectionProtocol::Smtp, status)
                }
                Err(e) => {
                    result.inconclusive = true;
                    result.details.push(format!("SMTP test error: {}", e));
                }
            }
        }

        // Test IMAP injection (port 143)
        if self.target.port == 143 {
            tested_standard_port = true;
            match self.test_imap_injection_status().await {
                Ok(status) => {
                    Self::record_probe_status(&mut result, StarttlsInjectionProtocol::Imap, status)
                }
                Err(e) => {
                    result.inconclusive = true;
                    result.details.push(format!("IMAP test error: {}", e));
                }
            }
        }

        // Test POP3 injection (port 110)
        if self.target.port == 110 {
            tested_standard_port = true;
            match self.test_pop3_injection_status().await {
                Ok(status) => {
                    Self::record_probe_status(&mut result, StarttlsInjectionProtocol::Pop3, status)
                }
                Err(e) => {
                    result.inconclusive = true;
                    result.details.push(format!("POP3 test error: {}", e));
                }
            }
        }

        // If not a standard STARTTLS port, mark as not applicable
        if !tested_standard_port {
            result.details.push(format!(
                "Port {} is not a standard STARTTLS port (25, 143, 110, 587)",
                self.target.port
            ));
        }

        Ok(result)
    }

    fn record_probe_status(
        result: &mut StarttlsInjectionResult,
        protocol: StarttlsInjectionProtocol,
        status: StarttlsInjectionStatus,
    ) {
        let protocol_name = protocol.name();
        match status {
            StarttlsInjectionStatus::Vulnerable => {
                result.vulnerable = true;
                match protocol {
                    StarttlsInjectionProtocol::Smtp => result.smtp_vulnerable = true,
                    StarttlsInjectionProtocol::Imap => result.imap_vulnerable = true,
                    StarttlsInjectionProtocol::Pop3 => result.pop3_vulnerable = true,
                }
                result.details.push(format!(
                    "{} STARTTLS injection detected - commands can be injected before TLS upgrade",
                    protocol_name
                ));
            }
            StarttlsInjectionStatus::NotVulnerable => {
                result
                    .details
                    .push(format!("{} STARTTLS injection not detected", protocol_name));
            }
            StarttlsInjectionStatus::Inconclusive => {
                result.inconclusive = true;
                result.details.push(format!(
                    "{} STARTTLS injection test inconclusive - unable to complete probe",
                    protocol_name
                ));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct StarttlsInjectionResult {
    pub vulnerable: bool,
    pub smtp_vulnerable: bool,
    pub imap_vulnerable: bool,
    pub pop3_vulnerable: bool,
    pub inconclusive: bool,
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
            inconclusive: false,
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
            inconclusive: false,
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
    async fn test_imap_starttls_capability_is_case_insensitive() {
        let port = start_scripted_server(
            b"* OK IMAP4rev1\r\n",
            vec![
                b"* CAPABILITY IMAP4rev1 starttls\r\na001 OK\r\n",
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
    async fn test_pop3_stls_capability_is_case_insensitive() {
        let port = start_scripted_server(
            b"+OK POP3 server\r\n",
            vec![
                b"+OK CAPA\r\nstls\r\n.\r\n",
                b"+OK stls\r\n+OK user accepted\r\n",
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

    #[tokio::test]
    async fn test_smtp_injection_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let status = tester.test_smtp_injection_status().await.unwrap();
        assert_eq!(status, StarttlsInjectionStatus::Inconclusive);
    }

    #[tokio::test]
    async fn test_imap_injection_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let status = tester.test_imap_injection_status().await.unwrap();
        assert_eq!(status, StarttlsInjectionStatus::Inconclusive);
    }

    #[tokio::test]
    async fn test_pop3_injection_inactive_target_is_inconclusive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::with_ips(
            "127.0.0.1".to_string(),
            port,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = StarttlsInjectionTester::new(target);

        let status = tester.test_pop3_injection_status().await.unwrap();
        assert_eq!(status, StarttlsInjectionStatus::Inconclusive);
    }

    #[test]
    fn test_standard_port_not_vulnerable_detail_is_not_nonstandard() {
        let mut result = StarttlsInjectionResult {
            vulnerable: false,
            smtp_vulnerable: false,
            imap_vulnerable: false,
            pop3_vulnerable: false,
            inconclusive: false,
            details: Vec::new(),
        };

        StarttlsInjectionTester::record_probe_status(
            &mut result,
            StarttlsInjectionProtocol::Smtp,
            StarttlsInjectionStatus::NotVulnerable,
        );

        assert!(!result.vulnerable);
        assert!(!result.inconclusive);
        assert!(
            result
                .details
                .iter()
                .any(|detail| detail.contains("SMTP STARTTLS injection not detected"))
        );
        assert!(
            !result
                .details
                .iter()
                .any(|detail| detail.contains("not a standard STARTTLS port"))
        );
    }
}
