// IRC (Internet Relay Chat) STARTTLS Negotiator
// RFC 2812 + STARTTLS extension

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// IRC STARTTLS negotiator
pub struct IrcNegotiator;

impl Default for IrcNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl IrcNegotiator {
    pub fn new() -> Self {
        Self
    }

    async fn read_response(reader: &mut BufReader<&mut TcpStream>) -> Result<String> {
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(response)
    }
}

#[async_trait]
impl StarttlsNegotiator for IrcNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Send CAP LS to list capabilities
        reader.get_mut().write_all(b"CAP LS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read capability list
        let mut starttls_supported = false;
        loop {
            let response = Self::read_response(&mut reader).await?;

            if response.contains("tls") || response.contains("TLS") {
                starttls_supported = true;
            }

            // CAP * LS :capability list
            if response.contains("CAP") && response.contains("LS") {
                break;
            }
        }

        if !starttls_supported {
            return Err(anyhow::anyhow!("IRC server does not support STARTTLS"));
        }

        // Request STARTTLS capability
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response
        // Numeric 670 = STARTTLS successful, begin TLS
        let response = Self::read_response(&mut reader).await?;
        if !response.contains("670") {
            return Err(anyhow::anyhow!("STARTTLS failed: {}", response));
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IRC
    }
}

/// IRCS is IRC with implicit TLS (not STARTTLS)
/// This is just a marker implementation
pub struct IrcsNegotiator;

impl Default for IrcsNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl IrcsNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for IrcsNegotiator {
    async fn negotiate_starttls(&self, _stream: &mut TcpStream) -> Result<()> {
        // IRCS uses implicit TLS, no STARTTLS negotiation needed
        // Connection should already be TLS from the start
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IRCS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irc_negotiator_creation() {
        let negotiator = IrcNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IRC);
    }

    #[test]
    fn test_ircs_negotiator_creation() {
        let negotiator = IrcsNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IRCS);
    }
}
