// NNTP (Network News Transfer Protocol) STARTTLS Negotiator
// RFC 4642

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// NNTP STARTTLS negotiator
pub struct NntpNegotiator;

impl Default for NntpNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl NntpNegotiator {
    pub fn new() -> Self {
        Self
    }

    async fn read_response(reader: &mut BufReader<&mut TcpStream>) -> Result<(u16, String)> {
        let mut response = String::new();
        reader.read_line(&mut response).await?;

        let code =
            response[0..3]
                .parse::<u16>()
                .map_err(|_| crate::error::TlsError::ParseError {
                    message: "Invalid NNTP response code".to_string(),
                })?;

        Ok((code, response))
    }
}

#[async_trait]
impl StarttlsNegotiator for NntpNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Read server greeting (200 or 201)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 200 && code != 201 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("NNTP greeting failed: expected 200/201, got {}", code),
            });
        }

        // Send CAPABILITIES to check STARTTLS support
        reader.get_mut().write_all(b"CAPABILITIES\r\n").await?;
        reader.get_mut().flush().await?;

        // Read capabilities (101 = capability list follows)
        let (code, _response) = Self::read_response(&mut reader).await?;
        if code != 101 {
            return Err(crate::error::TlsError::UnexpectedResponse {
                details: format!("CAPABILITIES failed: {}", code),
            });
        }

        // Read capability lines until we find STARTTLS or end marker
        let mut starttls_supported = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;

            if line.trim() == "." {
                break;
            }

            if line.to_uppercase().contains("STARTTLS") {
                starttls_supported = true;
            }
        }

        if !starttls_supported {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "NNTP".to_string(),
                details: "Server does not support STARTTLS".to_string(),
            });
        }

        // Send STARTTLS command
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response (382 = continue with TLS negotiation)
        let (code, response) = Self::read_response(&mut reader).await?;
        if code != 382 {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "NNTP".to_string(),
                details: format!("STARTTLS failed: {}", response),
            });
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::NNTP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nntp_negotiator_creation() {
        let negotiator = NntpNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::NNTP);
    }
}
