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
}

#[async_trait]
impl StarttlsNegotiator for LdapNegotiator {
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()> {
        // Send LDAP StartTLS extended request
        let starttls_request = Self::create_starttls_request();
        stream.write_all(&starttls_request).await?;
        stream.flush().await?;

        // Read response
        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;

        if n == 0 {
            return Err(crate::error::TlsError::ConnectionClosed { details: "LDAP server closed connection".to_string() });
        }

        // Check for successful response
        // LDAP response should contain resultCode = success (0)
        // Simplified check: look for success indicator in response
        if n >= 10 {
            // Check if response contains ExtendedResponse (tag 0x78)
            // and resultCode = 0 (success)
            if response[5] == 0x78 && response[7..9].contains(&0x00) {
                return Ok(());
            }
        }

        Err(crate::error::TlsError::StarttlsError { protocol: "LDAP".to_string(), details: "STARTTLS negotiation failed".to_string() })
    }

    fn protocol(&self) -> StarttlsProtocol {
        StarttlsProtocol::LDAP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
