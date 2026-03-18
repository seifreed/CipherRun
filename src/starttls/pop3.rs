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
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "POP3".to_string(),
                details: format!("Greeting failed: {}", greeting),
            });
        }

        // 2. Send CAPA command to check capabilities
        reader.get_mut().write_all(b"CAPA\r\n").await?;
        reader.get_mut().flush().await?;

        // 3. Read CAPA response
        let mut starttls_supported = false;
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("+OK") {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "POP3".to_string(),
                details: "CAPA command failed".to_string(),
            });
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
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "POP3".to_string(),
                details: "Server does not support STLS".to_string(),
            });
        }

        // 4. Send STLS command (POP3 uses STLS not STARTTLS)
        reader.get_mut().write_all(b"STLS\r\n").await?;
        reader.get_mut().flush().await?;

        // 5. Read STLS response
        let response = Self::read_response(&mut reader).await?;
        if !response.starts_with("+OK") {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "POP3".to_string(),
                details: format!("STLS failed: {}", response),
            });
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
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;

    async fn spawn_pop3_server(send_stls: bool) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut socket);
                let _ = reader.get_mut().write_all(b"+OK POP3 ready\r\n").await;
                let _ = reader.get_mut().flush().await;

                let mut buf = String::new();
                let _ = reader.read_line(&mut buf).await;

                let _ = reader
                    .get_mut()
                    .write_all(b"+OK Capability list follows\r\n")
                    .await;
                if send_stls {
                    let _ = reader.get_mut().write_all(b"STLS\r\n").await;
                } else {
                    let _ = reader.get_mut().write_all(b"TOP\r\n").await;
                }
                let _ = reader.get_mut().write_all(b".\r\n").await;
                let _ = reader.get_mut().flush().await;

                if send_stls {
                    buf.clear();
                    let _ = reader.read_line(&mut buf).await;
                    let _ = reader
                        .get_mut()
                        .write_all(b"+OK Begin TLS negotiation\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;
                }
            }
        });

        (port, handle)
    }

    #[test]
    fn test_pop3_negotiator_creation() {
        let negotiator = Pop3Negotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::POP3);
        assert_eq!(negotiator.expected_greeting(), Some("+OK"));
    }

    #[tokio::test]
    async fn test_pop3_negotiation_success() {
        let (port, handle) = spawn_pop3_server(true).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = Pop3Negotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_pop3_negotiation_missing_stls() {
        let (port, handle) = spawn_pop3_server(false).await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = Pop3Negotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_pop3_negotiation_capa_failed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut socket);
                let _ = reader.get_mut().write_all(b"+OK POP3 ready\r\n").await;
                let _ = reader.get_mut().flush().await;

                let mut buf = String::new();
                let _ = reader.read_line(&mut buf).await;
                let _ = reader.get_mut().write_all(b"-ERR not supported\r\n").await;
                let _ = reader.get_mut().flush().await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = Pop3Negotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_pop3_read_response_line() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let _ = server.write_all(b"+OK Ready\r\n").await;
        });

        let mut reader = BufReader::new(&mut client);
        let line = Pop3Negotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert!(line.starts_with("+OK"));
    }
}
