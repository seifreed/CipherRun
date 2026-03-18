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

    #[tokio::test]
    async fn test_mysql_packet_roundtrip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let payload = vec![0x01, 0x02, 0x03, 0x04];
            let len = payload.len() as u32;
            let header = [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                0x00,
            ];

            socket.write_all(&header).await.unwrap();
            socket.write_all(&payload).await.unwrap();

            let mut recv_header = [0u8; 4];
            socket.read_exact(&mut recv_header).await.unwrap();
            let recv_len = u32::from_le_bytes([recv_header[0], recv_header[1], recv_header[2], 0]);
            let mut recv_payload = vec![0u8; recv_len as usize];
            socket.read_exact(&mut recv_payload).await.unwrap();

            (payload, recv_payload, recv_header[3])
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");

        let payload = MysqlNegotiator::read_packet(&mut stream)
            .await
            .expect("test assertion should succeed");
        assert_eq!(payload, vec![0x01, 0x02, 0x03, 0x04]);

        let send_payload = vec![0xaa, 0xbb, 0xcc];
        MysqlNegotiator::send_packet(&mut stream, &send_payload, 7)
            .await
            .expect("test assertion should succeed");

        let (_sent_payload, recv_payload, seq) = server.await.unwrap();
        assert_eq!(recv_payload, send_payload);
        assert_eq!(seq, 7);
    }

    #[tokio::test]
    async fn test_mysql_negotiate_starttls_success() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let handshake = vec![0x01, 0x02, 0x00, 0x08];
            let len = handshake.len() as u32;
            let header = [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                0x00,
            ];
            socket.write_all(&header).await.unwrap();
            socket.write_all(&handshake).await.unwrap();

            let mut recv_header = [0u8; 4];
            socket.read_exact(&mut recv_header).await.unwrap();
            let recv_len = u32::from_le_bytes([recv_header[0], recv_header[1], recv_header[2], 0]);
            let mut recv_payload = vec![0u8; recv_len as usize];
            socket.read_exact(&mut recv_payload).await.unwrap();

            recv_payload
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        let negotiator = MysqlNegotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");

        let payload = server.await.unwrap();
        assert!(payload.len() >= 32);
        let client_caps = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(client_caps & 0x0800, 0x0800);
    }

    #[tokio::test]
    async fn test_mysql_negotiate_starttls_no_ssl() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let handshake = vec![0x01, 0x02, 0x00, 0x00];
            let len = handshake.len() as u32;
            let header = [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                0x00,
            ];
            socket.write_all(&header).await.unwrap();
            socket.write_all(&handshake).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        let negotiator = MysqlNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_mysql_negotiate_starttls_invalid_handshake() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let handshake = vec![0x01, 0x02];
            let len = handshake.len() as u32;
            let header = [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                0x00,
            ];
            socket.write_all(&header).await.unwrap();
            socket.write_all(&handshake).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        let negotiator = MysqlNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_mysql_send_packet_zero_length() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 4];
            socket.read_exact(&mut header).await.unwrap();
            header
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        MysqlNegotiator::send_packet(&mut stream, &[], 9)
            .await
            .expect("test assertion should succeed");

        let header = server.await.unwrap();
        assert_eq!(header[0], 0x00);
        assert_eq!(header[1], 0x00);
        assert_eq!(header[2], 0x00);
        assert_eq!(header[3], 9);
    }
}
