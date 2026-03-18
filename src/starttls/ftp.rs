// FTP STARTTLS Negotiator (AUTH TLS)

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::{Result, tls_bail};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

/// FTP STARTTLS negotiator
pub struct FtpNegotiator;

impl FtpNegotiator {
    pub fn new() -> Self {
        Self
    }

    /// Read FTP response (can be multi-line)
    async fn read_response<S>(reader: &mut BufReader<&mut S>) -> Result<(u16, String)>
    where
        S: AsyncRead + Unpin,
    {
        let mut full_response = String::new();
        let mut first_code = 0u16;

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;

            if line.len() < 3 {
                tls_bail!("Invalid FTP response: too short");
            }

            let code: u16 = line[0..3]
                .parse()
                .map_err(|_| crate::error::TlsError::ParseError {
                    message: "Invalid FTP status code".to_string(),
                })?;

            if first_code == 0 {
                first_code = code;
            }

            full_response.push_str(&line);

            // Multi-line responses have a dash after code (220-...)
            // Last line has space (220 ...)
            if line.len() >= 4 && &line[3..4] == " " {
                break;
            }
        }

        Ok((first_code, full_response))
    }
}

#[async_trait]
impl StarttlsNegotiator for FtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (220)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 220 {
            tls_bail!("FTP greeting failed: expected 220, got {}", code);
        }

        // 2. Send AUTH TLS command
        reader.get_mut().write_all(b"AUTH TLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 3. Read AUTH TLS response (234)
        let (code, response) = Self::read_response(&mut reader).await?;
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
        let (code, response) = FtpNegotiator::read_response(&mut reader)
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
        let result = FtpNegotiator::read_response(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_response_single_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = server.write_all(b"220 Ready\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let (code, response) = FtpNegotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 220);
        assert!(response.contains("Ready"));
    }

    #[tokio::test]
    async fn test_ftp_negotiate_starttls_not_supported() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"220 ready\r\n").await.unwrap();

            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"502 command not implemented\r\n")
                .await
                .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let negotiator = FtpNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("does not support"));

        server.await.unwrap();
    }
}
