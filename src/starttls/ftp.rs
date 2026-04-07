// FTP STARTTLS Negotiator (AUTH TLS)

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use super::response;
use crate::{Result, tls_bail};
use async_trait::async_trait;
use tokio::io::{AsyncWriteExt, BufReader};

/// FTP STARTTLS negotiator
pub struct FtpNegotiator;

impl FtpNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for FtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (220)
        let (code, _response) = response::read_multiline_status(&mut reader, "FTP", 100).await?;
        if code != 220 {
            tls_bail!("FTP greeting failed: expected 220, got {}", code);
        }

        // 2. Send AUTH TLS command
        reader.get_mut().write_all(b"AUTH TLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 3. Read AUTH TLS response (234)
        let (code, response) = response::read_multiline_status(&mut reader, "FTP", 100).await?;
        if code != 234 {
            // Some servers might return 502 (command not implemented)
            if code == 502 {
                tls_bail!("FTP server does not support AUTH TLS");
            }
            tls_bail!(
                "FTP AUTH TLS failed: expected 234, got {}: {}",
                code,
                response
            );
        }

        // STARTTLS negotiation successful
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::FTP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("220")
    }
}

impl Default for FtpNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_ftp_negotiator_creation() {
        let negotiator = FtpNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::FTP);
        assert_eq!(negotiator.expected_greeting(), Some("220"));
    }

    #[tokio::test]
    async fn test_read_response_multiline() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let _ = server.write_all(b"220-First line\r\n220 Ready\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let (code, response) = response::read_multiline_status(&mut reader, "FTP", 100)
            .await
            .expect("test assertion should succeed");

        assert_eq!(code, 220);
        assert!(response.contains("First line"));
        assert!(response.contains("220 Ready"));
    }

    #[tokio::test]
    async fn test_read_response_invalid() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = server.write_all(b"12\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let result = response::read_multiline_status(&mut reader, "FTP", 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_response_single_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = server.write_all(b"220 Ready\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let (code, response) = response::read_multiline_status(&mut reader, "FTP", 100)
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 220);
        assert!(response.contains("Ready"));
    }

    #[tokio::test]
    async fn test_ftp_negotiate_starttls_not_supported() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("test listener should bind to localhost");
        let addr = listener.local_addr().expect("test listener should have local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test server should accept connection");
            stream.write_all(b"220 ready\r\n").await.expect("test server should write response");

            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).await.expect("test should read data");
            stream
                .write_all(b"502 command not implemented\r\n")
                .await
                .expect("test server should write response");
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("test client should connect");
        let negotiator = FtpNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("does not support"));

        server.await.expect("test server task should complete");
    }
}
