// SMTP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

/// SMTP STARTTLS negotiator
pub struct SmtpNegotiator {
    hostname: String,
}

impl SmtpNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    /// Read SMTP response line
    async fn read_response<S>(reader: &mut BufReader<&mut S>) -> Result<(u16, String)>
    where
        S: AsyncRead + Unpin,
    {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        if line.len() < 3 {
            return Err(crate::error::TlsError::ParseError {
                message: "Invalid SMTP response: too short".to_string(),
            });
        }

        let code: u16 = line[0..3]
            .parse()
            .map_err(|_| crate::error::TlsError::ParseError {
                message: "Invalid SMTP status code".to_string(),
            })?;

        Ok((code, line))
    }
}

#[async_trait]
impl StarttlsNegotiator for SmtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (220)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("SMTP greeting failed: expected 220, got {}", code),
            });
        }

        // 2. Send EHLO
        let ehlo_cmd = format!("EHLO {}\r\n", self.hostname);
        reader.get_mut().write_all(ehlo_cmd.as_bytes()).await?;
        reader.get_mut().flush().await?;

        // 3. Read EHLO response (250)
        // EHLO response can be multi-line (250-... and 250 ...)
        let mut starttls_supported = false;
        loop {
            let (code, line) = Self::read_response(&mut reader).await?;
            if code != 250 {
                return Err(crate::error::TlsError::UnexpectedResponse {
                    details: format!("SMTP EHLO failed: expected 250, got {}", code),
                });
            }

            // Check for STARTTLS capability
            if line.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }

            // Last line in multi-line response has space after code (250 ...)
            // Continuation lines have dash (250-...)
            if line.len() >= 4 && &line[3..4] == " " {
                break;
            }
        }

        if !starttls_supported {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "SMTP".to_string(),
                details: "Server does not support STARTTLS".to_string(),
            });
        }

        // 4. Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 5. Read STARTTLS response (220)
        let (code, _) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "SMTP".to_string(),
                details: format!("Expected 220, got {}", code),
            });
        }

        // STARTTLS negotiation successful, TLS handshake can now begin
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SMTP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("220")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_smtp_negotiator_creation() {
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SMTP);
        assert_eq!(negotiator.expected_greeting(), Some("220"));
    }

    #[tokio::test]
    async fn test_smtp_read_response_short_line() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server.write_all(b"a\n").await.unwrap();
        });

        let mut reader = BufReader::new(&mut client);
        let err = SmtpNegotiator::read_response(&mut reader)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("too short"));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_smtp_read_response_invalid_code() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server.write_all(b"xx0 Invalid\r\n").await.unwrap();
        });

        let mut reader = BufReader::new(&mut client);
        let err = SmtpNegotiator::read_response(&mut reader)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("status code"));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_smtp_read_response_valid_code() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let writer = tokio::spawn(async move {
            server.write_all(b"220 Ready\r\n").await.unwrap();
        });

        let mut reader = BufReader::new(&mut client);
        let (code, line) = SmtpNegotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 220);
        assert!(line.contains("Ready"));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_smtp_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"220 ready\r\n").await.unwrap();

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await.unwrap();

            stream
                .write_all(b"250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
                .await
                .unwrap();

            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"220 Ready to start TLS\r\n")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }
}
