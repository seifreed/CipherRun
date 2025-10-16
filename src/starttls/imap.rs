// IMAP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

/// IMAP STARTTLS negotiator
pub struct ImapNegotiator;

impl ImapNegotiator {
    pub fn new() -> Self {
        Self
    }

    /// Read IMAP response line
    async fn read_response<S>(reader: &mut BufReader<&mut S>) -> Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        Ok(line)
    }
}

#[async_trait]
impl StarttlsNegotiator for ImapNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (* OK)
        let greeting = Self::read_response(&mut reader).await?;
        if !greeting.starts_with("* OK") {
            return Err(anyhow::anyhow!("IMAP greeting failed: {}", greeting));
        }

        // 2. Send CAPABILITY command to check STARTTLS support
        reader.get_mut().write_all(b"a001 CAPABILITY\r\n").await?;
        reader.get_mut().flush().await?;

        // 3. Read CAPABILITY response
        let mut starttls_supported = false;
        loop {
            let line = Self::read_response(&mut reader).await?;

            if line.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }

            // Command completion (a001 OK ...)
            if line.starts_with("a001 OK") {
                break;
            }

            if line.starts_with("a001 NO") || line.starts_with("a001 BAD") {
                return Err(anyhow::anyhow!("IMAP CAPABILITY command failed"));
            }
        }

        if !starttls_supported {
            return Err(anyhow::anyhow!("IMAP server does not support STARTTLS"));
        }

        // 4. Send STARTTLS command
        reader.get_mut().write_all(b"a002 STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 5. Read STARTTLS response
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("a002 OK") {
            return Err(anyhow::anyhow!("IMAP STARTTLS failed: {}", response));
        }

        // STARTTLS negotiation successful
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IMAP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("* OK")
    }
}

impl Default for ImapNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imap_negotiator_creation() {
        let negotiator = ImapNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IMAP);
        assert_eq!(negotiator.expected_greeting(), Some("* OK"));
    }
}
