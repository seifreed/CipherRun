// Sieve (ManageSieve) STARTTLS Negotiator
// RFC 5804

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Sieve STARTTLS negotiator
pub struct SieveNegotiator;

impl Default for SieveNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl SieveNegotiator {
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
impl StarttlsNegotiator for SieveNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read server capabilities (starts with "IMPLEMENTATION")
        let mut starttls_supported = false;
        loop {
            let response = Self::read_response(&mut reader).await?;

            if response.starts_with("OK") {
                break;
            }

            if response.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }
        }

        if !starttls_supported {
            return Err(anyhow::anyhow!("Sieve server does not support STARTTLS"));
        }

        // Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response (OK = ready to start TLS)
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("OK") {
            return Err(anyhow::anyhow!("STARTTLS failed: {}", response));
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SIEVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sieve_negotiator_creation() {
        let negotiator = SieveNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SIEVE);
    }
}
