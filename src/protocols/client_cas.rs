// Client CAs List - Extract acceptable CAs for client authentication

use crate::Result;
use crate::utils::network::Target;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCA {
    pub distinguished_name: String,
    pub organization: Option<String>,
    pub common_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCAsResult {
    pub cas: Vec<ClientCA>,
    pub requires_client_auth: bool,
}

pub struct ClientCAsTester {
    target: Target,
}

impl ClientCAsTester {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    pub async fn enumerate_client_cas(&self) -> Result<ClientCAsResult> {
        let addr = self.target.socket_addrs()[0];
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(5);

        // Try to connect and trigger CertificateRequest
        let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                return Ok(ClientCAsResult {
                    cas: Vec::new(),
                    requires_client_auth: false,
                });
            }
        };

        // Build ClientHello without client certificate
        let mut builder =
            crate::protocols::handshake::ClientHelloBuilder::new(crate::protocols::Protocol::TLS12);

        // Add common cipher that requires authentication
        builder.add_cipher(0xc030); // ECDHE-RSA-AES256-GCM-SHA384

        if let Ok(client_hello) = builder.build_with_defaults(Some(&self.target.hostname)) {
            // Send ClientHello and read server response
            if let Ok(response) = timeout(read_timeout, async {
                stream.write_all(&client_hello).await?;

                // Read ServerHello and subsequent messages
                let mut response = vec![0u8; 16384]; // Larger buffer for certificates
                let n = stream.read(&mut response).await?;

                Ok::<Vec<u8>, anyhow::Error>(response[..n].to_vec())
            })
            .await
                && let Ok(data) = response
            {
                // Parse TLS messages looking for CertificateRequest (type 13)
                let cas = self.parse_certificate_request(&data);

                return Ok(ClientCAsResult {
                    requires_client_auth: !cas.is_empty(),
                    cas,
                });
            }
        }

        Ok(ClientCAsResult {
            cas: Vec::new(),
            requires_client_auth: false,
        })
    }

    fn parse_certificate_request(&self, data: &[u8]) -> Vec<ClientCA> {
        let mut cas = Vec::new();
        let mut pos = 0;

        // Walk through TLS records
        while pos + 5 < data.len() {
            // Check for Handshake record (0x16)
            if data[pos] != 0x16 {
                pos += 1;
                continue;
            }

            // Get record length
            let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            pos += 5;

            if pos + record_len > data.len() {
                break;
            }

            let record_data = &data[pos..pos + record_len];

            // Look for CertificateRequest message (type 13)
            if !record_data.is_empty() && record_data[0] == 13 {
                // Parse CertificateRequest
                if let Some(parsed_cas) = self.parse_ca_list(record_data) {
                    cas.extend(parsed_cas);
                }
            }

            pos += record_len;
        }

        cas
    }

    fn parse_ca_list(&self, data: &[u8]) -> Option<Vec<ClientCA>> {
        // CertificateRequest structure:
        // - Handshake type (1 byte): 13
        // - Length (3 bytes)
        // - Certificate types length (1 byte)
        // - Certificate types (variable)
        // - Signature algorithms length (2 bytes)
        // - Signature algorithms (variable)
        // - Certificate authorities length (2 bytes)
        // - Certificate authorities (variable)

        if data.len() < 10 {
            return None;
        }

        let mut pos = 4; // Skip message type and length

        // Skip certificate types
        if pos >= data.len() {
            return None;
        }
        let cert_types_len = data[pos] as usize;
        pos += 1 + cert_types_len;

        // Skip signature algorithms (TLS 1.2+)
        if pos + 2 > data.len() {
            return None;
        }
        let sig_algs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + sig_algs_len;

        // Parse certificate authorities
        if pos + 2 > data.len() {
            return None;
        }

        let ca_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + ca_list_len > data.len() {
            return None;
        }

        let mut cas = Vec::new();
        let ca_data = &data[pos..pos + ca_list_len];
        let mut ca_pos = 0;

        // Parse each DN
        while ca_pos + 2 < ca_data.len() {
            let dn_len = u16::from_be_bytes([ca_data[ca_pos], ca_data[ca_pos + 1]]) as usize;
            ca_pos += 2;

            if ca_pos + dn_len > ca_data.len() {
                break;
            }

            let dn_data = &ca_data[ca_pos..ca_pos + dn_len];

            // Parse DN (simplified - just extract as hex for now)
            let dn_hex = hex::encode(dn_data);

            // Try to extract common name and organization (basic parsing)
            let (cn, org) = self.extract_dn_fields(dn_data);

            cas.push(ClientCA {
                distinguished_name: dn_hex,
                common_name: cn,
                organization: org,
            });

            ca_pos += dn_len;
        }

        Some(cas)
    }

    fn extract_dn_fields(&self, dn_data: &[u8]) -> (Option<String>, Option<String>) {
        // Very basic DN parsing - in production would use x509_parser
        // This is a simplified version that looks for printable strings

        let mut cn = None;
        let mut org = None;

        // Look for PrintableString or UTF8String
        for i in 0..dn_data.len().saturating_sub(10) {
            // Common Name (2.5.4.3)
            if dn_data[i..].len() > 8
                && dn_data[i..i + 3] == [0x06, 0x03, 0x55]
                && (dn_data[i+3..i+6] == [0x04, 0x03, 0x0c] || // UTF8String
                   dn_data[i+3..i+6] == [0x04, 0x03, 0x13])
            {
                // PrintableString
                let len = dn_data[i + 6] as usize;
                if i + 7 + len <= dn_data.len()
                    && let Ok(s) = std::str::from_utf8(&dn_data[i + 7..i + 7 + len])
                {
                    cn = Some(s.to_string());
                }
            }

            // Organization (2.5.4.10)
            if dn_data[i..].len() > 8
                && dn_data[i..i + 3] == [0x06, 0x03, 0x55]
                && (dn_data[i+3..i+6] == [0x04, 0x0a, 0x0c] || // UTF8String
                   dn_data[i+3..i+6] == [0x04, 0x0a, 0x13])
            {
                // PrintableString
                let len = dn_data[i + 6] as usize;
                if i + 7 + len <= dn_data.len()
                    && let Ok(s) = std::str::from_utf8(&dn_data[i + 7..i + 7 + len])
                {
                    org = Some(s.to_string());
                }
            }
        }

        (cn, org)
    }
}
