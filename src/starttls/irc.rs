// IRC (Internet Relay Chat) STARTTLS Negotiator
// RFC 2812 + STARTTLS extension

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// IRC STARTTLS negotiator
pub struct IrcNegotiator;

impl Default for IrcNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl IrcNegotiator {
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
impl StarttlsNegotiator for IrcNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);

        // Send CAP LS to list capabilities
        reader.get_mut().write_all(b"CAP LS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read capability list
        // IRC CAP LS can be multi-line: "CAP * LS * :cap1 cap2" (asterisk = more lines follow)
        // Final line: "CAP * LS :cap3 cap4" (no asterisk = last line)
        let mut starttls_supported = false;
        const MAX_CAP_LINES: usize = 50;
        let mut line_count = 0;
        loop {
            let response = Self::read_response(&mut reader).await?;
            line_count += 1;
            let response_lower = response.to_ascii_lowercase();

            if has_irc_capability(&response, "tls") {
                starttls_supported = true;
            }

            // Break on the final CAP LS line (no asterisk before the colon)
            // Multi-line continuation has "CAP * LS *" while final has "CAP * LS :"
            if response_lower.contains("cap")
                && response_lower.contains("ls")
                && !response_lower.contains("ls *")
            {
                break;
            }

            if line_count >= MAX_CAP_LINES {
                break;
            }
        }

        if !starttls_supported {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "IRC".to_string(),
                details: "Server does not support STARTTLS".to_string(),
            });
        }

        // Request STARTTLS capability
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;

        // Read STARTTLS response
        // Numeric 670 = STARTTLS successful, begin TLS
        let response = Self::read_response(&mut reader).await?;
        if !response.contains("670") {
            return Err(crate::error::TlsError::StarttlsError {
                protocol: "IRC".to_string(),
                details: format!("STARTTLS failed: {}", response),
            });
        }

        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IRC
    }
}

fn has_irc_capability(response: &str, capability: &str) -> bool {
    let capability_list = response
        .rsplit_once(':')
        .map(|(_, list)| list)
        .unwrap_or(response);

    capability_list
        .split_whitespace()
        .any(|token| token.eq_ignore_ascii_case(capability))
}

/// IRCS is IRC with implicit TLS (not STARTTLS)
/// This is just a marker implementation
pub struct IrcsNegotiator;

impl Default for IrcsNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl IrcsNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for IrcsNegotiator {
    async fn negotiate_starttls(&self, _stream: &mut TcpStream) -> Result<()> {
        // IRCS uses implicit TLS, no STARTTLS negotiation needed
        // Connection should already be TLS from the start
        Ok(())
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::IRCS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[test]
    fn test_irc_negotiator_creation() {
        let negotiator = IrcNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IRC);
    }

    #[test]
    fn test_ircs_negotiator_creation() {
        let negotiator = IrcsNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::IRCS);
    }

    async fn spawn_irc_server() -> (u16, JoinHandle<()>) {
        spawn_irc_server_with_cap_line(b"CAP * LS :multi-prefix tls\r\n").await
    }

    async fn spawn_irc_server_with_cap_line(cap_line: &'static [u8]) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();

                let _ = reader.read_line(&mut line).await;
                let _ = reader.get_mut().write_all(cap_line).await;
                let _ = reader.get_mut().flush().await;

                line.clear();
                let _ = reader.read_line(&mut line).await;
                let _ = reader
                    .get_mut()
                    .write_all(b":server 670 Begin TLS\r\n")
                    .await;
                let _ = reader.get_mut().flush().await;
            }
        });

        (port, handle)
    }

    #[tokio::test]
    async fn test_irc_negotiation_success() {
        let (port, handle) = spawn_irc_server().await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = IrcNegotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_irc_negotiation_accepts_lowercase_cap_ls_final_line() {
        let (port, handle) =
            spawn_irc_server_with_cap_line(b"cap * ls :multi-prefix tls\r\n").await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = IrcNegotiator::new();
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            negotiator.negotiate_starttls(&mut stream),
        )
        .await
        .expect("negotiation should not wait for more CAP LS lines")
        .expect("test assertion should succeed");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_irc_negotiation_does_not_treat_notls_as_tls_capability() {
        let (port, handle) =
            spawn_irc_server_with_cap_line(b"CAP * LS :multi-prefix notls\r\n").await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = IrcNegotiator::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            negotiator.negotiate_starttls(&mut stream),
        )
        .await
        .expect("negotiation should not wait for STARTTLS");

        assert!(
            result.is_err(),
            "notls must not be accepted as the tls capability"
        );
        drop(stream);

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_ircs_negotiation_noop() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let negotiator = IrcsNegotiator::new();
        negotiator
            .negotiate_starttls(&mut stream)
            .await
            .expect("test assertion should succeed");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_irc_negotiation_missing_starttls() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();

                let _ = reader.read_line(&mut line).await;
                let _ = reader
                    .get_mut()
                    .write_all(b"CAP * LS :multi-prefix\r\n")
                    .await;
                let _ = reader.get_mut().flush().await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");

        let negotiator = IrcNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut stream).await;
        assert!(result.is_err());

        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_irc_read_response_line() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"CAP * LS :tls\r\n").await;
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("test assertion should succeed");
        let mut reader = BufReader::new(&mut stream);
        let line = IrcNegotiator::read_response(&mut reader)
            .await
            .expect("test assertion should succeed");
        assert!(line.contains("CAP"));

        let _ = handle.await;
    }
}
