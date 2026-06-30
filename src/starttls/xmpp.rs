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

    fn contains_xml_start_tag(response: &str, tag: &str) -> bool {
        Self::contains_xml_tag(response, &format!("<{tag}"), true)
    }

    fn contains_xml_end_tag(response: &str, tag: &str) -> bool {
        Self::contains_xml_tag(response, &format!("</{tag}>"), false)
    }

    fn contains_xml_tag(response: &str, needle: &str, require_start_tag_delimiter: bool) -> bool {
        let mut search_from = 0;

        while let Some(pos) = response[search_from..].find(needle) {
            let tag_start = search_from + pos;
            let after_tag = tag_start + needle.len();
            let delimited = !require_start_tag_delimiter
                || matches!(
                    response.as_bytes().get(after_tag).copied(),
                    None | Some(b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>')
                );

            if delimited && !Self::is_inside_xml_comment(response, tag_start) {
                return true;
            }

            search_from = after_tag;
        }

        false
    }

    fn is_inside_xml_comment(response: &str, index: usize) -> bool {
        let before = &response[..index];
        let Some(open) = before.rfind("<!--") else {
            return false;
        };

        match before.rfind("-->") {
            Some(close) => close < open,
            None => true,
        }
    }

    fn decode_utf8_response(bytes: &[u8]) -> Result<Option<&str>> {
        match std::str::from_utf8(bytes) {
            Ok(response) => Ok(Some(response)),
            Err(error) if error.error_len().is_none() => Ok(None),
            Err(error) => Err(crate::error::TlsError::ParseError {
                message: format!("XMPP STARTTLS response is not valid UTF-8: {error}"),
            }),
        }
    }

    /// Read until we find a specific XML tag
    async fn read_until_tag<S>(stream: &mut S, tag: &str) -> Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = vec![0u8; 4096];
        let mut accumulated = Vec::new();

        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                return Err(crate::error::TlsError::ConnectionClosed {
                    details: "Connection closed while reading".to_string(),
                });
            }

            let bytes = buffer
                .get(..n)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "XMPP STARTTLS response read length exceeded buffer".to_string(),
                })?;
            accumulated.extend_from_slice(bytes);
            let Some(response) = Self::decode_utf8_response(&accumulated)? else {
                continue;
            };

            if let Some(tag_name) = tag.strip_prefix("</").and_then(|tag| tag.strip_suffix('>')) {
                if Self::contains_xml_end_tag(response, tag_name) {
                    return Ok(response.to_string());
                }
            } else if response.contains(tag) {
                return Ok(response.to_string());
            }

            if accumulated.len() > 65536 {
                return Err(crate::error::TlsError::Other(
                    "Response too large".to_string(),
                ));
            }
        }
    }

    /// Read the STARTTLS response until we see either `<proceed` or `<failure`.
    async fn read_until_starttls_response<S>(stream: &mut S) -> Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = vec![0u8; 4096];
        let mut accumulated = Vec::new();

        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                return Err(crate::error::TlsError::ConnectionClosed {
                    details: "Connection closed while reading".to_string(),
                });
            }

            let bytes = buffer
                .get(..n)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "XMPP STARTTLS response read length exceeded buffer".to_string(),
                })?;
            accumulated.extend_from_slice(bytes);
            let Some(response) = Self::decode_utf8_response(&accumulated)? else {
                continue;
            };

            if Self::contains_xml_start_tag(response, "proceed")
                || Self::contains_xml_start_tag(response, "failure")
            {
                return Ok(response.to_string());
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
        if !Self::contains_xml_start_tag(&response, "starttls") {
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
        let response = Self::read_until_starttls_response(stream).await?;

        if Self::contains_xml_start_tag(&response, "proceed") {
            // STARTTLS negotiation successful
            Ok(())
        } else if Self::contains_xml_start_tag(&response, "failure") {
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
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    struct OneByteReader {
        data: Vec<u8>,
        offset: usize,
    }

    impl OneByteReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
            }
        }
    }

    impl AsyncRead for OneByteReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.offset >= self.data.len() || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&self.data[self.offset..self.offset + 1]);
            self.offset += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_xmpp_negotiator_creation() {
        let negotiator = XmppNegotiator::new("example.com".to_string());
        assert_eq!(negotiator.protocol(), StarttlsProtocol::XMPP);
        assert_eq!(negotiator.expected_greeting(), Some("<?xml"));
    }

    #[test]
    fn test_contains_xml_start_tag_ignores_comments_and_prefixes() {
        assert!(XmppNegotiator::contains_xml_start_tag(
            "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
            "starttls"
        ));
        assert!(!XmppNegotiator::contains_xml_start_tag(
            "<stream:features><!-- <starttls/> --></stream:features>",
            "starttls"
        ));
        assert!(!XmppNegotiator::contains_xml_start_tag(
            "<stream:features><starttls-required/></stream:features>",
            "starttls"
        ));
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
    async fn test_read_until_tag_ignores_tag_inside_comment() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            server
                .write_all(b"<stream:features><!-- </stream:features> -->")
                .await
                .unwrap();
            server
                .write_all(b"<starttls/></stream:features>")
                .await
                .unwrap();
        });

        let result = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .unwrap();
        assert!(result.contains("<starttls/>"));

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
    async fn test_read_until_tag_rejects_invalid_utf8() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            server.write_all(b"<stream:features>\xff").await.unwrap();
        });

        let err = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .unwrap_err();

        assert!(format!("{err}").contains("not valid UTF-8"));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_until_tag_accepts_split_utf8_character() {
        let mut client = OneByteReader::new(b"<stream:features>\xc3\xa9</stream:features>");

        let response = XmppNegotiator::read_until_tag(&mut client, "</stream:features>")
            .await
            .expect("split UTF-8 should decode after the next read");

        assert!(response.contains("\u{00e9}</stream:features>"));
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

    #[tokio::test]
    async fn test_xmpp_negotiate_starttls_ignores_unrelated_self_closing_tags() {
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
                .write_all(b"<stream:error/><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = XmppNegotiator::new("example.com".to_string());
        let result = negotiator.negotiate_starttls(&mut client).await;
        assert!(result.is_ok());

        server.await.unwrap();
    }
}
