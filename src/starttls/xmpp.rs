// XMPP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// XMPP STARTTLS negotiator
pub struct XmppNegotiator {
    hostname: String,
}

impl XmppNegotiator {
    pub fn new(hostname: String) -> Self {
        Self { hostname }
    }

    /// Read until we find a specific XML tag
    async fn read_until_tag<S>(stream: &mut S, tag: &str) -> Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = vec![0u8; 4096];
        let mut accumulated = String::new();

        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                return Err(crate::error::TlsError::ConnectionClosed {
                    details: "Connection closed while reading".to_string(),
                });
            }

            let chunk = String::from_utf8_lossy(&buffer[..n]);
            accumulated.push_str(&chunk);

            if accumulated.contains(tag) {
                return Ok(accumulated);
            }

            if accumulated.len() > 65536 {
                return Err(crate::error::TlsError::Other(
                    "Response too large".to_string(),
                ));
            }
        }
    }
}

#[async_trait]
impl StarttlsNegotiator for XmppNegotiator {
    async fn negotiate_starttls(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        // 1. Send XMPP stream header
        let stream_header = format!(
            "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
            self.hostname
        );
        stream.write_all(stream_header.as_bytes()).await?;
        stream.flush().await?;

        // 2. Read server stream features
        let response = Self::read_until_tag(stream, "</stream:features>").await?;

        // Check if STARTTLS is offered
        if !response.contains("<starttls") {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "XMPP".to_string(),
                details: "Server does not offer STARTTLS".to_string(),
            });
        }

        // 3. Send STARTTLS request
        let starttls_request = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
        stream.write_all(starttls_request.as_bytes()).await?;
        stream.flush().await?;

        // 4. Read STARTTLS response
        let response = Self::read_until_tag(stream, "/>").await?;

        if response.contains("<proceed") {
            // STARTTLS negotiation successful
            Ok(())
        } else if response.contains("<failure") {
            Err(crate::error::TlsError::StarttlsError {
                protocol: "XMPP".to_string(),
                details: "Server sent <failure/>".to_string(),
            })
        } else {
            Err(crate::error::TlsError::UnexpectedResponse {
                details: "XMPP STARTTLS: unexpected response".to_string(),
            })
        }
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::XMPP
    }

    fn expected_greeting(&self) -> Option<&str> {
        Some("<?xml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmpp_negotiator_creation() {
        let negotiator = XmppNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::XMPP);
        assert_eq!(negotiator.expected_greeting(), Some("<?xml"));
    }
}
