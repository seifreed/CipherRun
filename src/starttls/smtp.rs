// SMTP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

/// SMTP STARTTLS negotiator
pub struct SmtpNegotiator {
    hostname: String,
}

impl SmtpNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    /// Read SMTP response line
    async fn read_response<S>(reader: &mut BufReader<&mut S>) -> Result<(u16, String)>
    where
        S: AsyncRead + Unpin,
    {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        if line.len() < 3 {
            return Err(anyhow::anyhow!("Invalid SMTP response: too short"));
        }

        let code: u16 = line[0..3]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid SMTP status code"))?;

        Ok((code, line))
    }
}

#[async_trait]
impl StarttlsNegotiator for SmtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // 1. Read server greeting (220)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(anyhow::anyhow!(
                "SMTP greeting failed: expected 220, got {}",
                code
            ));
        }

        // 2. Send EHLO
        let ehlo_cmd = format!("EHLO {}\r\n", self.hostname);
        reader.get_mut().write_all(ehlo_cmd.as_bytes()).await?;
        reader.get_mut().flush().await?;

        // 3. Read EHLO response (250)
        // EHLO response can be multi-line (250-... and 250 ...)
        let mut starttls_supported = false;
        loop {
            let (code, line) = Self::read_response(&mut reader).await?;
            if code != 250 {
                return Err(anyhow::anyhow!(
                    "SMTP EHLO failed: expected 250, got {}",
                    code
                ));
            }

            // Check for STARTTLS capability
            if line.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }

            // Last line in multi-line response has space after code (250 ...)
            // Continuation lines have dash (250-...)
            if line.len() >= 4 && &line[3..4] == " " {
                break;
            }
        }

        if !starttls_supported {
            return Err(anyhow::anyhow!("SMTP server does not support STARTTLS"));
        }

        // 4. Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 5. Read STARTTLS response (220)
        let (code, _) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(anyhow::anyhow!(
                "SMTP STARTTLS failed: expected 220, got {}",
                code
            ));
        }

        // STARTTLS negotiation successful, TLS handshake can now begin
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::SMTP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("220")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_negotiator_creation() {
        let negotiator = SmtpNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::SMTP);
        assert_eq!(negotiator.expected_greeting(), Some("220"));
    }
}
