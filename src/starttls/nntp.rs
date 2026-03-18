// NNTP (Network News Transfer Protocol) STARTTLS Negotiator
// RFC 4642

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// NNTP STARTTLS negotiator
pub struct NntpNegotiator;

impl Default for NntpNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl NntpNegotiator {
    pub fn new() -> Self {
        Self
    }

    async fn read_response(reader: &mut BufReader<&mut TcpStream>) -> Result<(u16, String)> {
        let mut response = String::new();
        reader.read_line(&mut response).await?;

        let code =
            response[0..3]
                .parse::<u16>()
                .map_err(|_| crate::error::TlsError::ParseError {
                    message: "Invalid NNTP response code".to_string(),
                })?;

        Ok((code, response))
    }
}

#[async_trait]
impl StarttlsNegotiator for NntpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read server greeting (200 or 201)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 200 && code != 201 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("NNTP greeting failed: expected 200/201, got {}", code),
            });
        }

        // Send CAPABILITIES to check STARTTLS support
        reader.get_mut().write_all(b"CAPABILITIES\r\n").await?;
        reader.get_mut().flush().await?;

        // Read capabilities (101 = capability list follows)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 101 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("CAPABILITIES failed: {}", code),
            });
        }

        // Read capability lines until we find STARTTLS or end marker
        let mut starttls_supported = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;

            if line.trim() == "." {
                break;
            }

            if line.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }
        }

        if !starttls_supported {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "NNTP".to_string(),
                details: "Server does not support STARTTLS".to_string(),
            });
        }

        // Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response (382 = continue with TLS negotiation)
        let (code, response) = Self::read_response(&mut reader).await?;
        if code != 382 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "NNTP".to_string(),
                details: format!("STARTTLS failed: {}", response),
            });
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::NNTP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_nntp_negotiator_creation() {
        let negotiator = NntpNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::NNTP);
    }

    #[tokio::test]
    async fn test_nntp_read_response_parse_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"abc\r\n").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut reader = BufReader::new(&mut client);
        let err = NntpNegotiator::read_response(&mut reader)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Invalid NNTP response"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_nntp_read_response_valid() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"200 ready\r\n").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut reader = BufReader::new(&mut client);
        let (code, line) = NntpNegotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert_eq!(code, 200);
        assert!(line.contains("ready"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"200 server ready\r\n").await.unwrap();

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await.unwrap();

            stream
                .write_all(b"101 Capability list follows\r\n")
                .await
                .unwrap();
            stream.write_all(b"VERSION 2\r\n").await.unwrap();
            stream.write_all(b"STARTTLS\r\n").await.unwrap();
            stream.write_all(b".\r\n").await.unwrap();

            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"382 Continue with TLS negotiation\r\n")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = NntpNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_nntp_negotiate_starttls_missing_starttls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"201 server ready\r\n").await.unwrap();

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await.unwrap();

            stream
                .write_all(b"101 Capability list follows\r\n")
                .await
                .unwrap();
            stream.write_all(b"VERSION 2\r\n").await.unwrap();
            stream.write_all(b"MODE-READER\r\n").await.unwrap();
            stream.write_all(b".\r\n").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = NntpNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_err());

        server.await.unwrap();
    }
}
