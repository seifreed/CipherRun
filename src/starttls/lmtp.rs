// LMTP (Local Mail Transfer Protocol) STARTTLS Negotiator
// RFC 2033

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// LMTP STARTTLS negotiator (similar to SMTP)
pub struct LmtpNegotiator {
    hostname: String,
}

impl LmtpNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    async fn read_response(reader: &mut BufReader<&mut TcpStream>) -> Result<(u16, String)> {
        let mut response = String::new();
        reader.read_line(&mut response).await?;

        let code =
            response[0..3]
                .parse::<u16>()
                .map_err(|_| crate::error::TlsError::ParseError {
                    message: "Invalid LMTP response code".to_string(),
                })?;

        Ok((code, response))
    }
}

#[async_trait]
impl StarttlsNegotiator for LmtpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read server greeting (220)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("LMTP greeting failed: expected 220, got {}", code),
            });
        }

        // Send LHLO (LMTP equivalent of EHLO)
        let lhlo_cmd = format!("LHLO {}\r\n", self.hostname);
        reader.get_mut().write_all(lhlo_cmd.as_bytes()).await?;
        reader.get_mut().flush().await?;

        // Read LHLO response (can be multi-line)
        loop {
            let (code, response) = Self::read_response(&mut reader).await?;

            // 250 = success, 250- means more lines follow
            if code != 250 {
                return Err(crate::error::TlsError::StarttlsError {
                    protocol: "LMTP".to_string(),
                    details: format!("LHLO failed: {}", response),
                });
            }

            // Check if STARTTLS is supported
            if response.to_uppercase().contains("STARTTLS") {
                break;
            }

            // If line starts with "250 " (space, not dash), it's the last line
            if response.starts_with("250 ") {
                break;
            }
        }

        // Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response (220 = ready to start TLS)
        let (code, response) = Self::read_response(&mut reader).await?;
        if code != 220 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "LMTP".to_string(),
                details: format!("STARTTLS failed: {}", response),
            });
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::LMTP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lmtp_negotiator_creation() {
        let negotiator = LmtpNegotiator::new("localhost".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::LMTP);
    }
}
