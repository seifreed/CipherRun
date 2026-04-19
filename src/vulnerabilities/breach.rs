// BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
// CVE-2013-3587
//
// BREACH exploits HTTP compression to extract secrets from HTTPS responses
// by observing changes in response sizes when injecting known data.
// Similar to CRIME but targets HTTP-level compression instead of TLS compression.

use crate::Result;
use crate::constants::TLS_HANDSHAKE_TIMEOUT;
use crate::utils::network::Target;

/// BREACH vulnerability tester
pub struct BreachTester {
    target: Target,
}

impl BreachTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Test for BREACH vulnerability
    pub async fn test(&self) -> Result<BreachTestResult> {
        let compression_enabled = self.test_http_compression().await?;
        let dynamic_content = self.test_dynamic_content().await?;
        let sensitive_data = self.test_sensitive_data_reflection().await?;

        // BREACH requires all three conditions:
        // 1. HTTP compression enabled
        // 2. Dynamic content (user input reflected)
        // 3. Sensitive data in responses
        let vulnerable = compression_enabled && dynamic_content && sensitive_data;

        let details = if vulnerable {
            "Vulnerable to BREACH (CVE-2013-3587): HTTP compression enabled with dynamic content containing secrets".to_string()
        } else if compression_enabled {
            let mut reasons = Vec::new();
            if !dynamic_content {
                reasons.push("no dynamic content detected");
            }
            if !sensitive_data {
                reasons.push("no sensitive data reflection detected");
            }
            format!(
                "Partially vulnerable - HTTP compression enabled but {}",
                reasons.join(" and ")
            )
        } else {
            "Not vulnerable - HTTP compression not enabled".to_string()
        };

        Ok(BreachTestResult {
            vulnerable,
            compression_enabled,
            dynamic_content,
            sensitive_data_reflection: sensitive_data,
            details,
        })
    }

    /// Test if HTTP compression is enabled
    async fn test_http_compression(&self) -> Result<bool> {
        let addr = self
            .target
            .socket_addrs()
            .first()
            .copied()
            .ok_or(crate::TlsError::NoSocketAddresses)?;

        // First establish TLS connection
        let stream =
            match crate::utils::network::connect_with_timeout(addr, TLS_HANDSHAKE_TIMEOUT, None)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        // Establish TLS
        use openssl::ssl::{SslConnector, SslMethod};
        let connector = SslConnector::builder(SslMethod::tls())?.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(mut ssl_stream) => {
                use std::io::{Read, Write};

                // Send HTTP request with Accept-Encoding header
                let request = format!(
                    "GET / HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Accept-Encoding: gzip, deflate\r\n\
                     User-Agent: Mozilla/5.0\r\n\
                     Connection: close\r\n\
                     \r\n",
                    self.target.hostname
                );

                ssl_stream.write_all(request.as_bytes())?;

                // Read response headers
                let mut buffer = vec![0u8; 8192];
                let n = ssl_stream.read(&mut buffer)?;

                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    // Check for Content-Encoding header
                    let compressed = response.lines().any(|line| {
                        let lower = line.to_lowercase();
                        lower.starts_with("content-encoding:")
                            && (lower.contains("gzip")
                                || lower.contains("deflate")
                                || lower.contains("br")
                                || lower.contains("zstd")
                                || lower.contains("compress"))
                    });
                    Ok(compressed)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Test if server reflects user input (dynamic content)
    async fn test_dynamic_content(&self) -> Result<bool> {
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
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        use openssl::ssl::{SslConnector, SslMethod};
        let connector = SslConnector::builder(SslMethod::tls())?.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(mut ssl_stream) => {
                use std::io::{Read, Write};

                // Send request with unique marker in query string
                let marker = "BREACH_TEST_MARKER_12345";
                let request = format!(
                    "GET /?test={} HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Accept-Encoding: gzip, deflate\r\n\
                     Connection: close\r\n\
                     \r\n",
                    marker, self.target.hostname
                );

                ssl_stream.write_all(request.as_bytes())?;

                // Read response
                let mut buffer = vec![0u8; 16384];
                let n = ssl_stream.read(&mut buffer)?;

                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    // Require a 2xx response: 404/error pages that echo the URL in their
                    // body would otherwise trigger a false positive for dynamic content.
                    let is_success = response.starts_with("HTTP/")
                        && response[5..]
                            .split_once(' ')
                            .map(|x| x.1)
                            .and_then(|rest| rest.split_whitespace().next())
                            .and_then(|code| code.parse::<u16>().ok())
                            .map(|code| (200..300).contains(&code))
                            .unwrap_or(false);
                    Ok(is_success && response.contains(marker))
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Test if sensitive data might be reflected in responses
    async fn test_sensitive_data_reflection(&self) -> Result<bool> {
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
                Err(_) => return Ok(false),
            };

        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;

        use openssl::ssl::{SslConnector, SslMethod};
        let connector = SslConnector::builder(SslMethod::tls())?.build();

        match connector.connect(&self.target.hostname, std_stream) {
            Ok(mut ssl_stream) => {
                use std::io::{Read, Write};

                // Send request with Cookie header
                let request = format!(
                    "GET / HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Cookie: sessionid=test123; csrftoken=abc456\r\n\
                     Accept-Encoding: gzip, deflate\r\n\
                     Connection: close\r\n\
                     \r\n",
                    self.target.hostname
                );

                ssl_stream.write_all(request.as_bytes())?;

                // Read response
                let mut buffer = vec![0u8; 16384];
                let n = ssl_stream.read(&mut buffer)?;

                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    // Check for sensitive data with more precise matching
                    let has_sensitive = Self::detect_sensitive_patterns(&response);
                    Ok(has_sensitive)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Detect sensitive data patterns in HTTP response
    /// Uses precise matching to reduce false positives from comments/irrelevant text
    fn detect_sensitive_patterns(response: &str) -> bool {
        let response_lower = response.to_lowercase();

        // Check Set-Cookie header (definitive indicator)
        if response_lower.contains("set-cookie:") {
            return true;
        }

        // Check for CSRF tokens in HTML attributes (more precise)
        // Look for actual HTML attributes, not just the word "csrf"
        if response.contains("csrf-token=")
            || response.contains("csrf_token=")
            || response.contains("_csrf=")
            || response.contains("name=\"csrf")
            || response.contains("name='csrf")
            || response.contains("csrfmiddlewaretoken")
        {
            return true;
        }

        // Check for session tokens in specific contexts
        // Avoid matching "session" word in comments or unrelated text
        if response_lower.contains("phpsessid=")
            || response_lower.contains("jsessionid=")
            || response_lower.contains("asp.net_sessionid=")
            || response.contains("sessionId=")
            || response.contains("session_id=")
            || response.contains("name=\"session")
            || response.contains("name='session")
        {
            return true;
        }

        // Check for API tokens in headers or meta tags
        if response_lower.contains("authorization:")
            || response_lower.contains("x-auth-token:")
            || response_lower.contains("x-api-key:")
            || response.contains("api_key=")
            || response.contains("access_token=")
            || response.contains("name=\"token")
            || response.contains("name='token")
        {
            return true;
        }

        false
    }
}

/// BREACH test result
#[derive(Debug, Clone)]
pub struct BreachTestResult {
    pub vulnerable: bool,
    pub compression_enabled: bool,
    pub dynamic_content: bool,
    pub sensitive_data_reflection: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breach_result_creation() {
        let result = BreachTestResult {
            vulnerable: true,
            compression_enabled: true,
            dynamic_content: true,
            sensitive_data_reflection: true,
            details: "Test".to_string(),
        };
        assert!(result.vulnerable);
        assert!(result.compression_enabled);
        assert!(result.dynamic_content);
        assert!(result.sensitive_data_reflection);
    }

    #[test]
    fn test_breach_not_vulnerable_no_compression() {
        let result = BreachTestResult {
            vulnerable: false,
            compression_enabled: false,
            dynamic_content: true,
            sensitive_data_reflection: true,
            details: "Not vulnerable".to_string(),
        };
        assert!(!result.vulnerable);
        // Even with dynamic content and sensitive data, not vulnerable without compression
    }

    #[test]
    fn test_breach_partial_vulnerability() {
        let result = BreachTestResult {
            vulnerable: false,
            compression_enabled: true,
            dynamic_content: false,
            sensitive_data_reflection: true,
            details: "Partial".to_string(),
        };
        // Needs all three conditions for full vulnerability
        assert!(!result.vulnerable);
        assert!(result.compression_enabled);
    }
}
