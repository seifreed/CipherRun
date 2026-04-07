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
        // Escape hostname for safe XML attribute interpolation
        let safe_hostname = self
            .hostname
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&apos;")
            .replace('"', "&quot;");
        let stream_header = format!(
            "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
            safe_hostname
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_xmpp_negotiator_creation() {
        let negotiator = XmppNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::XMPP);
        assert_eq!(negotiator.expected_greeting(), Some("<?xml"));
    }

    #[tokio::test]
    async fn test_read_until_tag_success() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            server
                .write_all(b"<stream:features><starttls/></stream:features>")
                .await
                .unwrap();
        });

        let result = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .unwrap();
        assert!(result.contains("</stream:features>"));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_until_tag_connection_closed() {
        let (mut client, server) = tokio::io::duplex(16);
        drop(server);

        let err = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Connection closed"));
    }

    #[tokio::test]
    async fn test_read_until_tag_too_large() {
        let (mut client, mut server) = tokio::io::duplex(65536);
        let writer = tokio::spawn(async move {
            let payload = vec![b'a'; 70000];
            let _ = server.write_all(&payload).await;
        });

        let err = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("Response too large"));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_xmpp_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 2048];
            let _ = stream.read(&mut buffer).await.unwrap();

            stream
                .write_all(
                    b"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
                )
                .await
                .unwrap();

            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = XmppNegotiator::new("example.com".to_string());
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_xmpp_negotiate_starttls_failure_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 2048];
            let _ = stream.read(&mut buffer).await.unwrap();

            stream
                .write_all(
                    b"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
                )
                .await
                .unwrap();

            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = XmppNegotiator::new("example.com".to_string());
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_err());

        server.await.unwrap();
    }
}
