// Telnet STARTTLS Negotiator
// RFC 2817 - Upgrading to TLS Within HTTP/1.1

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Telnet STARTTLS negotiator
pub struct TelnetNegotiator;

impl Default for TelnetNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl TelnetNegotiator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StarttlsNegotiator for TelnetNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // Telnet option negotiation (RFC 854); STARTTLS option per RFC 2817.
        const IAC: u8 = 0xFF;
        const WILL: u8 = 0xFB;
        const WONT: u8 = 0xFC;
        const DO: u8 = 0xFD;
        const DONT: u8 = 0xFE;
        const SB: u8 = 0xFA;
        const SE: u8 = 0xF0;
        const START_TLS: u8 = 0x2E;
        // Bound how many commands we scan so a misbehaving server cannot make us
        // loop forever (read timeouts are enforced by the caller).
        const MAX_COMMANDS: usize = 256;

        // Send IAC WILL START_TLS.
        stream.write_all(&[IAC, WILL, START_TLS]).await?;
        stream.flush().await?;

        // Telnet servers routinely interleave other option negotiations (ECHO,
        // SGA, NAWS, ...) before answering ours. The previous fixed 3-byte read
        // mistook the first such option for the START_TLS verdict and reported a
        // false negative. Scan IAC commands until we see the verdict for the
        // START_TLS option specifically.
        for _ in 0..MAX_COMMANDS {
            if stream.read_u8().await? != IAC {
                // Data byte outside an IAC command — ignore.
                continue;
            }
            match stream.read_u8().await? {
                command @ (WILL | WONT | DO | DONT) => {
                    let option = stream.read_u8().await?;
                    if option == START_TLS {
                        return if command == DO {
                            Ok(())
                        } else {
                            Err(crate::error::TlsError::StarttlsError {
                                protocol: "Telnet".to_string(),
                                details: "STARTTLS negotiation failed: server refused the option"
                                    .to_string(),
                            })
                        };
                    }
                    // Negotiation for an unrelated option — skip it.
                }
                SB => {
                    // Subnegotiation: skip until the terminating IAC SE.
                    let mut prev_iac = false;
                    loop {
                        let b = stream.read_u8().await?;
                        if prev_iac && b == SE {
                            break;
                        }
                        prev_iac = b == IAC;
                    }
                }
                // IAC IAC is an escaped data byte; any other command (GA, NOP,
                // AYT, ...) is a 2-byte sequence with no option — skip either.
                _ => {}
            }
        }

        Err(crate::error::TlsError::StarttlsError {
            protocol: "Telnet".to_string(),
            details: "STARTTLS negotiation failed: no verdict within option-negotiation limit"
                .to_string(),
        })
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::Telnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_telnet_negotiator_creation() {
        let negotiator = TelnetNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::Telnet);
    }

    #[test]
    fn test_telnet_negotiator_default() {
        let negotiator = TelnetNegotiator;
        assert_eq!(negotiator.protocol(), StarttlsProtocol::Telnet);
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0xFF, 0xFB, 0x2E]);
            stream.write_all(&[0xFF, 0xFD, 0x2E]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&[0xFF, 0xFE, 0x2E]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        let err = negotiator
            .negotiate_starttls(&mut client)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("STARTTLS negotiation failed"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_telnet_negotiate_starttls_succeeds_after_interleaved_options() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            // Server negotiates unrelated options (DO ECHO, WILL SGA) and a
            // subnegotiation before answering START_TLS. A correct client must
            // skip these and still detect the DO START_TLS verdict.
            stream
                .write_all(&[
                    0xFF, 0xFD, 0x01, // IAC DO ECHO
                    0xFF, 0xFB, 0x03, // IAC WILL SGA
                    0xFF, 0xFA, 0x18, 0x00, 0xFF, 0xF0, // IAC SB TERMINAL-TYPE ... IAC SE
                    0xFF, 0xFD, 0x2E, // IAC DO START_TLS
                ])
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = TelnetNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }
}
