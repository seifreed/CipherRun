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

    #[test]
    fn test_postgres_negotiator_creation() {
        let negotiator = PostgresNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::POSTGRES);
    }
}
