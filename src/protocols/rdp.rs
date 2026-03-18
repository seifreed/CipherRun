// RDP Support - Send RDP preamble before TLS handshake

use crate::{Result, tls_bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// RDP preamble for TLS negotiation
/// This is sent before the TLS handshake to initiate RDP protocol
pub struct RdpPreamble;

impl RdpPreamble {
    /// Send RDP preamble to initialize RDP protocol before TLS
    pub async fn send(stream: &mut TcpStream) -> Result<()> {
        // RDP Connection Request (X.224)
        // TPKT Header + CR_TPDU (Connection Request)
        let connection_request = vec![
            0x03, 0x00, // TPKT Version 3
            0x00, 0x13, // Length: 19 bytes
            0x0E, // Length of X.224 CR_TPDU
            0xE0, // CR_TPDU code
            0x00, 0x00, // Destination reference (0)
            0x00, 0x00, // Source reference (0)
            0x00, // Class and options
            // RDP Negotiation Request (TYPE_RDP_NEG_REQ)
            0x01, // Type: RDP_NEG_REQ
            0x00, // Flags
            0x08, 0x00, // Length: 8 bytes
            0x01, 0x00, 0x00, 0x00, // Requested protocols: TLS
        ];

        stream.write_all(&connection_request).await?;
        stream.flush().await?;

        // Read RDP Connection Confirm
        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;

        if n < 11 {
            tls_bail!("RDP response too short");
        }

        // Verify TPKT header
        if response[0] != 0x03 {
            tls_bail!("Invalid RDP response: not a TPKT packet");
        }

        // Check for CC_TPDU (Connection Confirm)
        if response[5] != 0xD0 {
            tls_bail!("Invalid RDP response: expected CC_TPDU");
        }

        Ok(())
    }

    /// Check if we need to send RDP preamble based on port
    pub fn should_use_rdp(port: u16) -> bool {
        port == 3389 // Default RDP port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdp_port_detection() {
        assert!(RdpPreamble::should_use_rdp(3389));
        assert!(!RdpPreamble::should_use_rdp(443));
    }

    #[test]
    fn test_rdp_port_detection_other() {
        assert!(!RdpPreamble::should_use_rdp(0));
        assert!(!RdpPreamble::should_use_rdp(3390));
    }

    #[tokio::test]
    async fn test_rdp_preamble_send() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 64];
            let _ = socket.read(&mut buffer).await.unwrap();
            let mut response = vec![0u8; 11];
            response[0] = 0x03;
            response[5] = 0xD0;
            socket.write_all(&response).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        RdpPreamble::send(&mut stream)
            .await
            .expect("test assertion should succeed");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_rdp_preamble_short_response() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test assertion should succeed");
        let addr = listener
            .local_addr()
            .expect("test assertion should succeed");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 64];
            let _ = socket.read(&mut buffer).await.unwrap();
            socket.write_all(&[0x03, 0x00]).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("test assertion should succeed");
        let err = RdpPreamble::send(&mut stream).await.unwrap_err();
        assert!(err.to_string().contains("RDP response too short"));

        server.await.unwrap();
    }
}
