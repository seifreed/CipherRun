// RDP Support - Send RDP preamble before TLS handshake

use crate::Result;
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
            anyhow::bail!("RDP response too short");
        }

        // Verify TPKT header
        if response[0] != 0x03 {
            anyhow::bail!("Invalid RDP response: not a TPKT packet");
        }

        // Check for CC_TPDU (Connection Confirm)
        if response[5] != 0xD0 {
            anyhow::bail!("Invalid RDP response: expected CC_TPDU");
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
}
