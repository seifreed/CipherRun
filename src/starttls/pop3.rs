// POP3 STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

/// POP3 STARTTLS negotiator
pub struct Pop3Negotiator;

impl Pop3Negotiator {
    pub fn new() -> Self {
        Self
    }

    /// Read POP3 response line
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
impl StarttlsNegotiator for Pop3Negotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (+OK)
        let greeting = Self::read_response(&mut reader).await?;
        if !greeting.starts_with("+OK") {
            return Err(anyhow::anyhow!("POP3 greeting failed: {}", greeting));
        }

        // 2. Send CAPA command to check capabilities
        reader.get_mut().write_all(b"CAPA\r\n").await?;
        reader.get_mut().flush().await?;

        // 3. Read CAPA response
        let mut starttls_supported = false;
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("+OK") {
            return Err(anyhow::anyhow!("POP3 CAPA command failed"));
        }

        // Read capability lines until "."
        loop {
            let line = Self::read_response(&mut reader).await?;
            let line = line.trim();

            if line == "." {
                break;
            }

            if line.eq_ignore_ascii_case("STLS") {
                starttls_supported = true;
            }
        }

        if !starttls_supported {
            return Err(anyhow::anyhow!("POP3 server does not support STLS"));
        }

        // 4. Send STLS command (POP3 uses STLS not STARTTLS)
        reader.get_mut().write_all(b"STLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 5. Read STLS response
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("+OK") {
            return Err(anyhow::anyhow!("POP3 STLS failed: {}", response));
        }

        // STARTTLS negotiation successful
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::POP3
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("+OK")
    }
}

impl Default for Pop3Negotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop3_negotiator_creation() {
        let negotiator = Pop3Negotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::POP3);
        assert_eq!(negotiator.expected_greeting(), Some("+OK"));
    }
}
