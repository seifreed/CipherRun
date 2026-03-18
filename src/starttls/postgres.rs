// PostgreSQL STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// PostgreSQL STARTTLS negotiator
pub struct PostgresNegotiator;

impl Default for PostgresNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for PostgresNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // PostgreSQL SSL request message
        // Format: Length (4 bytes) + SSL request code (80877103)
        let ssl_request: [u8; 8] = [
            0x00, 0x00, 0x00, 0x08, // Length: 8 bytes
            0x04, 0xd2, 0x16, 0x2f, // SSL request code: 80877103
        ];

        // Send SSL request
        stream.write_all(&ssl_request).await?;
        stream.flush().await?;

        // Read server response (1 byte)
        // 'S' (0x53) = SSL supported
        // 'N' (0x4E) = SSL not supported
        let mut response = [0u8; 1];
        stream.read_exact(&mut response).await?;

        if response[0] == b'S' {
            // Server supports SSL, can proceed with TLS handshake
            Ok(())
        } else {
            Err(crate::error::TlsError::StarttlsError {
                protocol: "PostgreSQL".to_string(),
                details: "Server does not support SSL".to_string(),
            })
        }
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::POSTGRES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_postgres_negotiator_creation() {
        let negotiator = PostgresNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::POSTGRES);
    }

    #[tokio::test]
    async fn test_postgres_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(b"S").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = PostgresNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_postgres_negotiate_starttls_not_supported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(b"N").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = PostgresNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Server does not support SSL"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_postgres_sends_ssl_request_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = PostgresNegotiator::new();
        let _ = negotiator.negotiate_starttls(&mut client).await;

        let sent = server.await.unwrap();
        assert_eq!(sent, [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]);
    }
}
