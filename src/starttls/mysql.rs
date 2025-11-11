// MySQL STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// MySQL STARTTLS negotiator
pub struct MysqlNegotiator;

impl Default for MysqlNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl MysqlNegotiator {
    pub fn new() -> Self {
        Self
    }

    /// Parse MySQL packet
    async fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
        // MySQL packet format:
        // 3 bytes: payload length
        // 1 byte: sequence number
        // N bytes: payload

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;

        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        let _sequence = header[3];

        let mut payload = vec![0u8; length as usize];
        stream.read_exact(&mut payload).await?;

        Ok(payload)
    }

    /// Send MySQL packet
    async fn send_packet(stream: &mut TcpStream, payload: &[u8], sequence: u8) -> Result<()> {
        let length = payload.len() as u32;
        let header = [
            (length & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            ((length >> 16) & 0xFF) as u8,
            sequence,
        ];

        stream.write_all(&header).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;

        Ok(())
    }
}

#[async_trait]
impl StarttlsNegotiator for MysqlNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // Read initial handshake packet from server
        let handshake = Self::read_packet(stream).await?;

        // Check if server supports SSL
        // Capability flags are at offset 2-3 (2 bytes) or 2-5 (4 bytes for newer versions)
        if handshake.len() < 4 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "MySQL".to_string(),
                details: "Invalid handshake packet".to_string(),
            });
        }

        let capabilities = u16::from_le_bytes([handshake[2], handshake[3]]);
        const CLIENT_SSL: u16 = 0x0800;

        if capabilities & CLIENT_SSL == 0 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "MySQL".to_string(),
                details: "Server does not support SSL".to_string(),
            });
        }

        // Send SSL request (handshake response with CLIENT_SSL capability)
        let mut ssl_request = vec![0u8; 32];

        // Client capabilities (4 bytes) - include CLIENT_SSL
        let client_caps: u32 = 0x0000A685 | (CLIENT_SSL as u32);
        ssl_request[0..4].copy_from_slice(&client_caps.to_le_bytes());

        // Max packet size (4 bytes)
        ssl_request[4..8].copy_from_slice(&0x01000000u32.to_le_bytes());

        // Character set (1 byte) - utf8mb4
        ssl_request[8] = 45;

        // Reserved (23 bytes of zeros already in vec)

        Self::send_packet(stream, &ssl_request, 1).await?;

        // Server should now expect TLS handshake
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::MYSQL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_negotiator_creation() {
        let negotiator = MysqlNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::MYSQL);
    }
}
