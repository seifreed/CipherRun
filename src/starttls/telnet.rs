// Telnet STARTTLS Negotiator
// RFC 2817 - Upgrading to TLS Within HTTP/1.1

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Telnet STARTTLS negotiator
pub struct TelnetNegotiator;

impl Default for TelnetNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl TelnetNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for TelnetNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // Telnet uses WILL/WONT/DO/DONT negotiation
        // For STARTTLS: RFC 2817

        // Send IAC WILL START_TLS
        // IAC = 0xFF, WILL = 0xFB, START_TLS = 0x2E
        let starttls_request = [0xFF, 0xFB, 0x2E];
        stream.write_all(&starttls_request).await?;
        stream.flush().await?;

        // Read response
        let mut response = [0u8; 3];
        stream.read_exact(&mut response).await?;

        // Check for IAC DO START_TLS (0xFF 0xFD 0x2E)
        if response[0] == 0xFF && response[1] == 0xFD && response[2] == 0x2E {
            // Server agrees to START_TLS
            Ok(())
        } else {
            Err(crate::error::TlsError::StarttlsError {
                protocol: "Telnet".to_string(),
                details: "STARTTLS negotiation failed".to_string(),
            })
        }
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::Telnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_telnet_negotiator_creation() {
        let negotiator = TelnetNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::Telnet);
    }

    #[test]
    fn test_telnet_negotiator_default() {
        let negotiator = TelnetNegotiator;
        assert_eq!(negotiator.protocol(), StarttlsProtocol::Telnet);
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0xFF, 0xFB, 0x2E]);
            stream.write_all(&[0xFF, 0xFD, 0x2E]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&[0xFF, 0xFE, 0x2E]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("STARTTLS negotiation failed"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_unexpected_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&[0x00, 0x00, 0x00]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("STARTTLS"));

        server.await.unwrap();
    }
}
