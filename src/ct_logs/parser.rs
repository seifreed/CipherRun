// CT Log Entry Parser
//
// Parses CT log entries (Merkle Tree Leaf format) and extracts certificates

use super::client::CtLogEntryResponse;
use super::Result;
use crate::error::TlsError;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

/// Certificate type in CT log
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertType {
    /// Precertificate (embedded in TLS extension)
    PreCertificate,
    /// X.509 certificate
    X509Certificate,
}

/// Parsed certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// DER-encoded certificate
    pub der: Vec<u8>,
    /// Subject Common Name (CN)
    pub subject_cn: Option<String>,
    /// Subject Alternative Names (DNS names)
    pub subject_an: Vec<String>,
    /// Issuer Common Name
    pub issuer_cn: Option<String>,
    /// Not before timestamp
    pub not_before: DateTime<Utc>,
    /// Not after timestamp
    pub not_after: DateTime<Utc>,
    /// Serial number (hex)
    pub serial: String,
}

/// Parsed CT log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtLogEntry {
    /// Log source ID
    pub log_source: String,
    /// Entry index in log
    pub index: u64,
    /// Timestamp from Merkle Tree Leaf
    pub timestamp: DateTime<Utc>,
    /// Certificate type
    pub cert_type: CertType,
    /// Parsed certificate
    pub certificate: Certificate,
}

/// CT Log Parser
pub struct Parser {
    log_source_id: String,
}

impl Parser {
    /// Create a new parser for a specific log source
    pub fn new(log_source_id: String) -> Self {
        Self { log_source_id }
    }

    /// Parse a CT log entry response
    pub fn parse_entry(
        &self,
        entry: &CtLogEntryResponse,
        index: u64,
    ) -> Result<CtLogEntry> {
        // Decode base64 leaf_input
        let leaf_bytes = base64::engine::general_purpose::STANDARD
            .decode(&entry.leaf_input)
            .map_err(|e| {
                TlsError::ParseError { message: format!("Failed to decode leaf_input: {}", e) }
            })?;

        if leaf_bytes.len() < 43 {
            return Err(TlsError::ParseError {
                message: format!("Leaf input too short: {} bytes", leaf_bytes.len())
            });
        }

        // Parse Merkle Tree Leaf structure (RFC 6962)
        // Byte 0: Version (should be 0)
        // Byte 1: MerkleLeafType (should be 0 for timestamped_entry)
        // Bytes 2-9: Timestamp (milliseconds since epoch)
        // Bytes 10-11: LogEntryType (0 = X509, 1 = PreCert)
        // Rest: Certificate data

        let version = leaf_bytes[0];
        if version != 0 {
            return Err(TlsError::ParseError {
                message: format!("Unsupported CT version: {}", version)
            });
        }

        let leaf_type = leaf_bytes[1];
        if leaf_type != 0 {
            return Err(TlsError::ParseError {
                message: format!("Unsupported leaf type: {}", leaf_type)
            });
        }

        // Parse timestamp (8 bytes, big-endian)
        let timestamp_ms = u64::from_be_bytes([
            leaf_bytes[2],
            leaf_bytes[3],
            leaf_bytes[4],
            leaf_bytes[5],
            leaf_bytes[6],
            leaf_bytes[7],
            leaf_bytes[8],
            leaf_bytes[9],
        ]);

        let timestamp = DateTime::<Utc>::from_timestamp(
            (timestamp_ms / 1000) as i64,
            ((timestamp_ms % 1000) * 1_000_000) as u32,
        )
        .unwrap_or_else(Utc::now);

        // Parse log entry type
        let entry_type = u16::from_be_bytes([leaf_bytes[10], leaf_bytes[11]]);
        let cert_type = match entry_type {
            0 => CertType::X509Certificate,
            1 => CertType::PreCertificate,
            _ => {
                return Err(TlsError::ParseError {
                    message: format!("Unknown entry type: {}", entry_type)
                })
            }
        };

        // Extract certificate DER
        // For X509: next 3 bytes are length (24-bit big-endian), then DER
        // For PreCert: similar structure
        if leaf_bytes.len() < 15 {
            return Err(TlsError::ParseError {
                message: "Leaf too short for certificate".to_string()
            });
        }

        let cert_len = u32::from_be_bytes([0, leaf_bytes[12], leaf_bytes[13], leaf_bytes[14]]);
        let cert_start = 15;
        let cert_end = cert_start + cert_len as usize;

        if cert_end > leaf_bytes.len() {
            return Err(TlsError::ParseError {
                message: format!(
                    "Certificate length {} exceeds leaf size {}",
                    cert_len,
                    leaf_bytes.len()
                )
            });
        }

        let cert_der = leaf_bytes[cert_start..cert_end].to_vec();

        // Parse certificate to extract metadata
        let certificate = self.parse_certificate(&cert_der)?;

        Ok(CtLogEntry {
            log_source: self.log_source_id.clone(),
            index,
            timestamp,
            cert_type,
            certificate,
        })
    }

    /// Parse DER-encoded certificate
    fn parse_certificate(&self, der: &[u8]) -> Result<Certificate> {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            TlsError::ParseError { message: format!("Failed to parse X.509 certificate: {}", e) }
        })?;

        // Extract subject CN
        let subject_cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        // Extract Subject Alternative Names (DNS names only)
        let mut subject_an = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    subject_an.push(dns.to_string());
                }
            }
        }

        // Extract issuer CN
        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        // Extract validity period
        let not_before = DateTime::<Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        // Extract serial number
        let serial = cert
            .serial
            .to_str_radix(16)
            .to_uppercase();

        Ok(Certificate {
            der: der.to_vec(),
            subject_cn,
            subject_an,
            issuer_cn,
            not_before,
            not_after,
            serial,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = Parser::new("test-log".to_string());
        assert_eq!(parser.log_source_id, "test-log");
    }

    #[test]
    fn test_cert_type_serialization() {
        let cert_type = CertType::X509Certificate;
        let json = serde_json::to_string(&cert_type).unwrap();
        assert!(json.contains("X509Certificate"));

        let precert_type = CertType::PreCertificate;
        let json2 = serde_json::to_string(&precert_type).unwrap();
        assert!(json2.contains("PreCertificate"));
    }
}
