// LDAP STARTTLS Negotiator

use super::protocols::{StarttlsNegotiator, StarttlsProtocol};
use crate::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// LDAP STARTTLS negotiator
pub struct LdapNegotiator;

impl Default for LdapNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapNegotiator {
    pub fn new() -> Self {
        Self
    }

    /// Create LDAP StartTLS extended request
    fn create_starttls_request() -> Vec<u8> {
        // LDAP StartTLS Extended Request
        // OID: 1.3.6.1.4.1.1466.20037 (STARTTLS)

        // Simplified LDAP BER encoding for StartTLS request
        // Sequence, messageID=1, ExtendedRequest with StartTLS OID
        vec![
            0x30, 0x1d, // SEQUENCE, length 29
            0x02, 0x01, 0x01, // INTEGER messageID = 1
            0x77, 0x18, // ExtendedRequest [23], length 24
            0x80, 0x16, // requestName [0] (OID), length 22
            // OID 1.3.6.1.4.1.1466.20037
            0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34,
            0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
        ]
    }

    fn read_ber_length(
        bytes: &[u8],
        offset: usize,
        context: &str,
    ) -> Result<Option<(usize, usize)>> {
        let Some(&first) = bytes.get(offset) else {
            return Ok(None);
        };

        if first & 0x80 == 0 {
            return Ok(Some((first as usize, 1)));
        }

        let len_bytes = (first & 0x7f) as usize;
        if len_bytes == 0 {
            return Err(crate::error::TlsError::ParseError {
                message: format!("{context} uses indefinite length"),
            });
        }

        let end = offset
            .checked_add(1)
            .and_then(|value| value.checked_add(len_bytes))
            .ok_or_else(|| crate::error::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        let Some(length_bytes) = bytes.get(offset + 1..end) else {
            return Ok(None);
        };

        let mut len = 0usize;
        for &byte in length_bytes {
            len = len
                .checked_mul(256)
                .and_then(|value| value.checked_add(byte as usize))
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: format!("{context} length overflow"),
                })?;
        }

        Ok(Some((len, 1 + len_bytes)))
    }

    fn parse_starttls_response(bytes: &[u8]) -> Result<Option<bool>> {
        if bytes.len() < 2 {
            return Ok(None);
        }

        if bytes[0] != 0x30 {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is not a sequence".to_string(),
            });
        }

        let Some((seq_len, seq_len_bytes)) =
            Self::read_ber_length(bytes, 1, "LDAP sequence length")?
        else {
            return Ok(None);
        };
        let content_start = 1 + seq_len_bytes;
        let seq_end = content_start.checked_add(seq_len).ok_or_else(|| {
            crate::error::TlsError::ParseError {
                message: "LDAP sequence length overflow".to_string(),
            }
        })?;

        if bytes.len() < seq_end {
            return Ok(None);
        }
        if bytes.len() > seq_end {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response contains trailing bytes".to_string(),
            });
        }

        let mut offset = content_start;
        if bytes.get(offset) != Some(&0x02) {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is missing messageID".to_string(),
            });
        }
        offset += 1;

        let Some((msg_len, msg_len_bytes)) =
            Self::read_ber_length(bytes, offset, "LDAP messageID length")?
        else {
            return Ok(None);
        };
        if msg_len == 0 {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP messageID has zero length".to_string(),
            });
        }
        offset += msg_len_bytes;
        offset = offset
            .checked_add(msg_len)
            .ok_or_else(|| crate::error::TlsError::ParseError {
                message: "LDAP messageID length overflow".to_string(),
            })?;
        if offset > seq_end {
            return Ok(None);
        }

        if bytes.get(offset) != Some(&0x78) {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is not an extended response".to_string(),
            });
        }
        offset += 1;

        let Some((ext_len, ext_len_bytes)) =
            Self::read_ber_length(bytes, offset, "LDAP extended response length")?
        else {
            return Ok(None);
        };
        offset += ext_len_bytes;
        let ext_end =
            offset
                .checked_add(ext_len)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "LDAP extended response length overflow".to_string(),
                })?;
        if ext_end > seq_end {
            return Ok(None);
        }

        if bytes.get(offset) != Some(&0x0a) {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is missing resultCode".to_string(),
            });
        }
        offset += 1;

        let Some((result_len, result_len_bytes)) =
            Self::read_ber_length(bytes, offset, "LDAP resultCode length")?
        else {
            return Ok(None);
        };
        if result_len == 0 {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP resultCode has zero length".to_string(),
            });
        }
        if result_len != 1 {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP resultCode length must be 1".to_string(),
            });
        }
        offset += result_len_bytes;
        let result_end =
            offset
                .checked_add(result_len)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "LDAP resultCode length overflow".to_string(),
                })?;
        if result_end > ext_end {
            return Ok(None);
        }
        let result_code = bytes[offset];
        offset = result_end;

        if bytes.get(offset) != Some(&0x04) {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is missing matchedDN".to_string(),
            });
        }
        offset += 1;

        let Some((dn_len, dn_len_bytes)) =
            Self::read_ber_length(bytes, offset, "LDAP matchedDN length")?
        else {
            return Ok(None);
        };
        offset += dn_len_bytes;
        offset = offset
            .checked_add(dn_len)
            .ok_or_else(|| crate::error::TlsError::ParseError {
                message: "LDAP matchedDN length overflow".to_string(),
            })?;
        if offset > ext_end {
            return Ok(None);
        }

        if bytes.get(offset) != Some(&0x04) {
            return Err(crate::error::TlsError::ParseError {
                message: "LDAP STARTTLS response is missing diagnosticMessage".to_string(),
            });
        }
        offset += 1;

        let Some((diag_len, diag_len_bytes)) =
            Self::read_ber_length(bytes, offset, "LDAP diagnosticMessage length")?
        else {
            return Ok(None);
        };
        offset += diag_len_bytes;
        offset =
            offset
                .checked_add(diag_len)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "LDAP diagnosticMessage length overflow".to_string(),
                })?;
        if offset > ext_end {
            return Ok(None);
        }

        if result_code == 0 {
            Ok(Some(true))
        } else {
            Ok(Some(false))
        }
    }
}

#[async_trait]
impl StarttlsNegotiator for LdapNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // Send LDAP StartTLS extended request
        let starttls_request = Self::create_starttls_request();
        stream.write_all(&starttls_request).await?;
        stream.flush().await?;

        let mut response = Vec::with_capacity(64);
        let mut chunk = [0u8; 256];
        const MAX_RESPONSE_LEN: usize = 4096;

        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(crate::error::TlsError::ConnectionClosed {
                    details: "LDAP server closed connection".to_string(),
                });
            }

            response.extend_from_slice(&chunk[..n]);
            if response.len() > MAX_RESPONSE_LEN {
                return Err(crate::error::TlsError::ParseError {
                    message: "LDAP STARTTLS response exceeds maximum length".to_string(),
                });
            }

            match Self::parse_starttls_response(&response)? {
                Some(true) => return Ok(()),
                Some(false) => break,
                None => continue,
            }
        }

        Err(crate::error::TlsError::StarttlsError {
            protocol: "LDAP".to_string(),
            details: "STARTTLS negotiation failed".to_string(),
        })
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::LDAP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_ldap_negotiator_creation() {
        let negotiator = LdapNegotiator::new();
        assert_eq!(negotiator.protocol(), StarttlsProtocol::LDAP);
    }

    #[test]
    fn test_starttls_request_format() {
        let request = LdapNegotiator::create_starttls_request();
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_starttls_request_contains_oid_tail() {
        let request = LdapNegotiator::create_starttls_request();
        assert!(request.ends_with(&[0x33, 0x37])); // "...20037"
    }

    #[tokio::test]
    async fn test_ldap_negotiate_starttls_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = stream.read(&mut buf).await.unwrap();

            // LDAP ExtendedResponse with resultCode=0 (success), empty matchedDN,
            // and empty diagnosticMessage.
            let response = [
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ];
            stream.write_all(&response).await.unwrap();
            // Ensure all data is sent before the socket is closed
            let _ = stream.flush().await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = LdapNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_ldap_negotiate_starttls_rejects_malformed_success_shape() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = stream.read(&mut buf).await.unwrap();

            // This payload had previously been accepted by the fixed-offset check
            // even though the outer tag is wrong.
            let response = [
                0x31, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ];
            stream.write_all(&response).await.unwrap();
            let _ = stream.flush().await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = LdapNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;

        assert!(result.is_err(), "Expected malformed LDAP response to fail");

        server.await.unwrap();
    }

    #[test]
    fn test_ldap_parse_rejects_multi_byte_result_code() {
        let response = [
            0x30, 0x0d, // SEQUENCE, length 13
            0x02, 0x01, 0x01, // messageID = 1
            0x78, 0x08, // ExtendedResponse, length 8
            0x0a, 0x02, 0x00, 0x00, // malformed resultCode length 2
            0x04, 0x00, // matchedDN
            0x04, 0x00, // diagnosticMessage
        ];

        let err = LdapNegotiator::parse_starttls_response(&response)
            .expect_err("multi-byte LDAP resultCode should fail");

        assert!(err.to_string().contains("resultCode length"));
    }

    #[tokio::test]
    async fn test_ldap_negotiate_starttls_succeeds_with_fragmented_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = stream.read(&mut buf).await.unwrap();

            let first_half = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x78];
            let second_half = [0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
            stream.write_all(&first_half).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stream.write_all(&second_half).await.unwrap();
            let _ = stream.flush().await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = LdapNegotiator::new();
        negotiator.negotiate_starttls(&mut client).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_ldap_negotiate_starttls_connection_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Immediately drop - server closes connection without response
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let negotiator = LdapNegotiator::new();
        let result = negotiator.negotiate_starttls(&mut client).await;

        // Should fail because server closed connection
        assert!(result.is_err(), "Expected error for closed connection");
        let err = result.unwrap_err();
        let err_str = err.to_string();
        // Error could be: "connection reset", "connection closed", "STARTTLS", or "LDAP"
        assert!(
            err_str.contains("closed")
                || err_str.contains("reset")
                || err_str.contains("STARTTLS")
                || err_str.contains("LDAP")
                || err_str.contains("Connection"),
            "Unexpected error message: {}",
            err_str
        );

        server.await.unwrap();
    }
}
