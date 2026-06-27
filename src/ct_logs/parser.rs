// CT Log Entry Parser
//
// Parses CT log entries (Merkle Tree Leaf format) and extracts certificates

use super::Result;
use super::client::CtLogEntryResponse;
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

fn datetime_from_unix(timestamp_secs: i64, nanos: u32, field: &str) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(timestamp_secs, nanos).ok_or_else(|| TlsError::ParseError {
        message: format!("Invalid {field} timestamp: {timestamp_secs}.{nanos:09}"),
    })
}

fn datetime_from_millis(timestamp_ms: u64, field: &str) -> Result<DateTime<Utc>> {
    let secs = timestamp_ms / 1000;
    if secs > i64::MAX as u64 {
        return Err(TlsError::ParseError {
            message: format!("Invalid {field} timestamp: {timestamp_ms}ms"),
        });
    }

    datetime_from_unix(
        i64::try_from(secs).map_err(|_| TlsError::ParseError {
            message: format!("Invalid {field} timestamp: {timestamp_ms}ms"),
        })?,
        u32::try_from((timestamp_ms % 1000) * 1_000_000).map_err(|_| TlsError::ParseError {
            message: format!("Invalid {field} timestamp nanos: {timestamp_ms}ms"),
        })?,
        field,
    )
}

fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or_else(|| TlsError::ParseError {
            message: format!("{context} truncated"),
        })
}

fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
    let end = offset.checked_add(2).ok_or_else(|| TlsError::ParseError {
        message: format!("{context} length overflow"),
    })?;
    let bytes = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .ok_or_else(|| TlsError::ParseError {
            message: format!("{context} truncated"),
        })?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<u32> {
    let end = offset.checked_add(3).ok_or_else(|| TlsError::ParseError {
        message: format!("{context} length overflow"),
    })?;
    let [high, mid, low] = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
        .ok_or_else(|| TlsError::ParseError {
            message: format!("{context} truncated"),
        })?;
    Ok(((high as u32) << 16) | ((mid as u32) << 8) | low as u32)
}

fn read_u64_at(data: &[u8], offset: usize, context: &str) -> Result<u64> {
    let end = offset.checked_add(8).ok_or_else(|| TlsError::ParseError {
        message: format!("{context} length overflow"),
    })?;
    let bytes = data
        .get(offset..end)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .ok_or_else(|| TlsError::ParseError {
            message: format!("{context} truncated"),
        })?;
    Ok(u64::from_be_bytes(bytes))
}

impl Parser {
    /// Create a new parser for a specific log source
    pub fn new(log_source_id: String) -> Self {
        Self { log_source_id }
    }

    /// Parse a CT log entry response
    pub fn parse_entry(&self, entry: &CtLogEntryResponse, index: u64) -> Result<CtLogEntry> {
        // Decode base64 leaf_input
        let leaf_bytes = base64::engine::general_purpose::STANDARD
            .decode(&entry.leaf_input)
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to decode leaf_input: {}", e),
            })?;

        if leaf_bytes.len() < 15 {
            return Err(TlsError::ParseError {
                message: format!("Leaf input too short: {} bytes", leaf_bytes.len()),
            });
        }

        // Parse Merkle Tree Leaf structure (RFC 6962)
        // Byte 0: Version (should be 0)
        // Byte 1: MerkleLeafType (should be 0 for timestamped_entry)
        // Bytes 2-9: Timestamp (milliseconds since epoch)
        // Bytes 10-11: LogEntryType (0 = X509, 1 = PreCert)
        // Rest: Certificate data

        let version = read_u8_at(&leaf_bytes, 0, "CT leaf version")?;
        if version != 0 {
            return Err(TlsError::ParseError {
                message: format!("Unsupported CT version: {}", version),
            });
        }

        let leaf_type = read_u8_at(&leaf_bytes, 1, "CT leaf type")?;
        if leaf_type != 0 {
            return Err(TlsError::ParseError {
                message: format!("Unsupported leaf type: {}", leaf_type),
            });
        }

        // Parse timestamp (8 bytes, big-endian)
        let timestamp_ms = read_u64_at(&leaf_bytes, 2, "CT leaf timestamp")?;

        let timestamp = datetime_from_millis(timestamp_ms, "CT leaf")?;

        // Parse log entry type
        let entry_type = read_u16_at(&leaf_bytes, 10, "CT leaf entry type")?;
        let cert_type = match entry_type {
            0 => CertType::X509Certificate,
            1 => CertType::PreCertificate,
            _ => {
                return Err(TlsError::ParseError {
                    message: format!("Unknown entry type: {}", entry_type),
                });
            }
        };

        // Extract certificate DER.
        // RFC 6962 TimestampedEntry layout after the entry_type (bytes 10-11):
        //   X.509:   3-byte length at bytes 12-14, DER starts at byte 15
        //   PreCert: 32-byte issuer_key_hash at bytes 12-43,
        //            then 3-byte TBS length at bytes 44-46, TBS starts at byte 47
        let (cert_len, cert_start) = match cert_type {
            CertType::X509Certificate => {
                if leaf_bytes.len() < 15 {
                    return Err(TlsError::ParseError {
                        message: "Leaf too short for X.509 certificate".to_string(),
                    });
                }
                let len = read_u24_at(&leaf_bytes, 12, "X.509 certificate length")?;
                (len, 15usize)
            }
            CertType::PreCertificate => {
                if leaf_bytes.len() < 47 {
                    return Err(TlsError::ParseError {
                        message:
                            "Leaf too short for PreCertificate (need issuer_key_hash + length)"
                                .to_string(),
                    });
                }
                let len = read_u24_at(&leaf_bytes, 44, "PreCertificate TBS length")?;
                (len, 47usize)
            }
        };
        let cert_end =
            cert_start
                .checked_add(cert_len as usize)
                .ok_or_else(|| TlsError::ParseError {
                    message: "Certificate length overflow".to_string(),
                })?;

        if cert_end > leaf_bytes.len() {
            return Err(TlsError::ParseError {
                message: format!(
                    "Certificate length {} exceeds leaf size {}",
                    cert_len,
                    leaf_bytes.len()
                ),
            });
        }
        if cert_end != leaf_bytes.len() {
            return Err(TlsError::ParseError {
                message: "CT leaf contains trailing bytes after certificate".to_string(),
            });
        }

        let cert_der = leaf_bytes
            .get(cert_start..cert_end)
            .ok_or_else(|| TlsError::ParseError {
                message: "Certificate range exceeds leaf size".to_string(),
            })?
            .to_vec();

        // Parse certificate to extract metadata
        let certificate = self.parse_certificate(&cert_der, cert_type)?;

        Ok(CtLogEntry {
            log_source: self.log_source_id.clone(),
            index,
            timestamp,
            cert_type,
            certificate,
        })
    }

    /// Parse a DER-encoded CT log entry certificate to extract metadata.
    ///
    /// X.509 entries carry a full `Certificate`, but RFC 6962 precertificate
    /// leaves carry a bare `TBSCertificate` (the to-be-signed cert with the CT
    /// poison extension), not wrapped in the outer `Certificate` SEQUENCE. The
    /// full-certificate parser rejects that, which previously caused every
    /// precert entry — the dominant entry type in modern CT logs — to be
    /// silently dropped. Parse each form with the matching decoder.
    fn parse_certificate(&self, der: &[u8], cert_type: CertType) -> Result<Certificate> {
        match cert_type {
            CertType::X509Certificate => {
                let (rest, cert) =
                    X509Certificate::from_der(der).map_err(|e| TlsError::ParseError {
                        message: format!("Failed to parse X.509 certificate: {}", e),
                    })?;
                if !rest.is_empty() {
                    return Err(TlsError::ParseError {
                        message: "X.509 certificate contains trailing bytes".to_string(),
                    });
                }
                Self::metadata_from_tbs(&cert.tbs_certificate, der)
            }
            CertType::PreCertificate => {
                let (rest, tbs) =
                    TbsCertificate::from_der(der).map_err(|e| TlsError::ParseError {
                        message: format!("Failed to parse precertificate TBS: {}", e),
                    })?;
                if !rest.is_empty() {
                    return Err(TlsError::ParseError {
                        message: "PreCertificate TBS contains trailing bytes".to_string(),
                    });
                }
                Self::metadata_from_tbs(&tbs, der)
            }
        }
    }

    /// Extract certificate metadata from a parsed `TBSCertificate`.
    fn metadata_from_tbs(tbs: &TbsCertificate, der: &[u8]) -> Result<Certificate> {
        // Extract subject CN
        let subject_cn = tbs
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        // Extract Subject Alternative Names (DNS names only)
        let mut subject_an = Vec::new();
        if let Some(san_ext) = tbs
            .subject_alternative_name()
            .map_err(|e| TlsError::ParseError {
                message: format!("Failed to parse subject alternative name: {}", e),
            })?
        {
            for name in &san_ext.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    subject_an.push(dns.to_string());
                }
            }
        }

        // Extract issuer CN
        let issuer_cn = tbs
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        // Extract validity period
        let not_before = datetime_from_unix(
            tbs.validity().not_before.timestamp(),
            0,
            "certificate notBefore",
        )?;

        let not_after = datetime_from_unix(
            tbs.validity().not_after.timestamp(),
            0,
            "certificate notAfter",
        )?;

        // Extract serial number
        let serial = tbs.serial.to_str_radix(16).to_uppercase();

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
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    #[test]
    fn test_parser_creation() {
        let parser = Parser::new("test-log".to_string());
        assert_eq!(parser.log_source_id, "test-log");
    }

    #[test]
    fn test_cert_type_serialization() {
        let cert_type = CertType::X509Certificate;
        let json = serde_json::to_string(&cert_type).expect("test assertion should succeed");
        assert!(json.contains("X509Certificate"));

        let precert_type = CertType::PreCertificate;
        let json2 = serde_json::to_string(&precert_type).expect("test assertion should succeed");
        assert!(json2.contains("PreCertificate"));
    }

    fn build_leaf_input(cert_der: &[u8]) -> String {
        let mut leaf = Vec::new();
        leaf.push(0u8); // version
        leaf.push(0u8); // leaf type
        leaf.extend_from_slice(&0u64.to_be_bytes()); // timestamp ms
        leaf.extend_from_slice(&0u16.to_be_bytes()); // entry type X509

        let len = cert_der.len() as u32;
        leaf.push(((len >> 16) & 0xff) as u8);
        leaf.push(((len >> 8) & 0xff) as u8);
        leaf.push((len & 0xff) as u8);
        leaf.extend_from_slice(cert_der);

        base64::engine::general_purpose::STANDARD.encode(leaf)
    }

    fn build_leaf_input_with_timestamp(timestamp_ms: u64, cert_der: &[u8]) -> String {
        let mut leaf = Vec::new();
        leaf.push(0u8); // version
        leaf.push(0u8); // leaf type
        leaf.extend_from_slice(&timestamp_ms.to_be_bytes());
        leaf.extend_from_slice(&0u16.to_be_bytes()); // entry type X509

        let len = cert_der.len() as u32;
        leaf.push(((len >> 16) & 0xff) as u8);
        leaf.push(((len >> 8) & 0xff) as u8);
        leaf.push((len & 0xff) as u8);
        leaf.extend_from_slice(cert_der);

        base64::engine::general_purpose::STANDARD.encode(leaf)
    }

    fn cert_with_raw_extension_der(oid: &str, contents: &[u8]) -> Vec<u8> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "malformed-extension.example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();

        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        let extension = X509Extension::new_from_der(&oid, false, &contents).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        builder.build().to_der().unwrap()
    }

    #[test]
    fn test_parse_entry_rejects_invalid_ct_timestamp() {
        let entry = CtLogEntryResponse {
            leaf_input: build_leaf_input_with_timestamp(u64::MAX, &[]),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let err = parser.parse_entry(&entry, 0).unwrap_err();

        assert!(format!("{err}").contains("Invalid CT leaf timestamp"));
    }

    #[test]
    fn test_certificate_timestamp_helper_rejects_out_of_range_values() {
        let err = datetime_from_unix(i64::MAX, 0, "certificate notAfter").unwrap_err();
        assert!(format!("{err}").contains("Invalid certificate notAfter timestamp"));
    }

    #[test]
    fn test_parse_entry_success() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "example.com").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let cert_der = cert.to_der().unwrap();

        let entry = CtLogEntryResponse {
            leaf_input: build_leaf_input(&cert_der),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let parsed = parser.parse_entry(&entry, 42).unwrap();

        assert_eq!(parsed.index, 42);
        assert_eq!(parsed.cert_type, CertType::X509Certificate);
        assert!(parsed.certificate.subject_cn.is_some());
        assert_eq!(parsed.certificate.der, cert_der);
    }

    /// Returns (content_start_index, content_length) for the DER length field
    /// beginning at `len_pos`.
    fn der_len(der: &[u8], len_pos: usize) -> (usize, usize) {
        let first = der[len_pos] as usize;
        if first < 0x80 {
            (len_pos + 1, first)
        } else {
            let num_bytes = first & 0x7f;
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | der[len_pos + 1 + i] as usize;
            }
            (len_pos + 1 + num_bytes, len)
        }
    }

    /// Extract the raw DER of the tbsCertificate (first element of the
    /// Certificate SEQUENCE), mirroring what a CT precert leaf carries.
    fn tbs_der_from_cert(cert_der: &[u8]) -> Vec<u8> {
        assert_eq!(cert_der[0], 0x30, "certificate must be a SEQUENCE");
        let (outer_content_start, _) = der_len(cert_der, 1);
        let tbs_start = outer_content_start;
        assert_eq!(
            cert_der[tbs_start], 0x30,
            "tbsCertificate must be a SEQUENCE"
        );
        let (tbs_content_start, tbs_len) = der_len(cert_der, tbs_start + 1);
        cert_der[tbs_start..tbs_content_start + tbs_len].to_vec()
    }

    fn build_precert_leaf_input(tbs_der: &[u8]) -> String {
        let mut leaf = Vec::new();
        leaf.push(0u8); // version
        leaf.push(0u8); // leaf type (timestamped entry)
        leaf.extend_from_slice(&0u64.to_be_bytes()); // timestamp ms
        leaf.extend_from_slice(&1u16.to_be_bytes()); // entry type: precert = 1
        leaf.extend_from_slice(&[0u8; 32]); // issuer_key_hash

        let len = tbs_der.len() as u32;
        leaf.push(((len >> 16) & 0xff) as u8);
        leaf.push(((len >> 8) & 0xff) as u8);
        leaf.push((len & 0xff) as u8);
        leaf.extend_from_slice(tbs_der);

        base64::engine::general_purpose::STANDARD.encode(leaf)
    }

    #[test]
    fn test_parse_entry_precertificate_extracts_metadata() {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "precert.example.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let cert_der = cert.to_der().unwrap();
        let tbs_der = tbs_der_from_cert(&cert_der);

        let entry = CtLogEntryResponse {
            leaf_input: build_precert_leaf_input(&tbs_der),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let parsed = parser.parse_entry(&entry, 7).unwrap();

        assert_eq!(parsed.cert_type, CertType::PreCertificate);
        assert_eq!(
            parsed.certificate.subject_cn.as_deref(),
            Some("precert.example.com")
        );
    }

    #[test]
    fn test_parse_entry_precertificate_rejects_malformed_san() {
        let cert_der = cert_with_raw_extension_der("2.5.29.17", b"\x05\x00");
        let tbs_der = tbs_der_from_cert(&cert_der);
        let entry = CtLogEntryResponse {
            leaf_input: build_precert_leaf_input(&tbs_der),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let err = parser.parse_entry(&entry, 7).unwrap_err();
        assert!(format!("{err}").contains("Failed to parse subject alternative name"));
    }

    #[test]
    fn test_parse_entry_rejects_x509_der_trailing_bytes() {
        let mut cert_der = cert_with_raw_extension_der("1.2.3.4", b"\x05\x00");
        cert_der.push(0xff);
        let entry = CtLogEntryResponse {
            leaf_input: build_leaf_input(&cert_der),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let err = parser.parse_entry(&entry, 7).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    #[test]
    fn test_parse_entry_rejects_precertificate_tbs_trailing_bytes() {
        let cert_der = cert_with_raw_extension_der("1.2.3.4", b"\x05\x00");
        let mut tbs_der = tbs_der_from_cert(&cert_der);
        tbs_der.push(0xff);
        let entry = CtLogEntryResponse {
            leaf_input: build_precert_leaf_input(&tbs_der),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let err = parser.parse_entry(&entry, 7).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    #[test]
    fn test_parse_entry_invalid_version() {
        let mut leaf = vec![1u8, 0u8];
        leaf.extend_from_slice(&0u64.to_be_bytes());
        leaf.extend_from_slice(&0u16.to_be_bytes());
        leaf.extend_from_slice(&[0, 0, 0]);
        let entry = CtLogEntryResponse {
            leaf_input: base64::engine::general_purpose::STANDARD.encode(leaf),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        assert!(parser.parse_entry(&entry, 0).is_err());
    }

    #[test]
    fn test_parse_entry_length_exceeds() {
        let mut leaf = vec![0u8, 0u8];
        leaf.extend_from_slice(&0u64.to_be_bytes());
        leaf.extend_from_slice(&0u16.to_be_bytes());
        leaf.extend_from_slice(&[0x00, 0x00, 0x10]); // length 16
        leaf.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes present
        let entry = CtLogEntryResponse {
            leaf_input: base64::engine::general_purpose::STANDARD.encode(leaf),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        assert!(parser.parse_entry(&entry, 0).is_err());
    }

    #[test]
    fn test_parse_entry_rejects_trailing_leaf_bytes() {
        let mut leaf = vec![0u8, 0u8];
        leaf.extend_from_slice(&0u64.to_be_bytes());
        leaf.extend_from_slice(&0u16.to_be_bytes());
        leaf.extend_from_slice(&[0x00, 0x00, 0x01]); // length 1
        leaf.push(0x30); // declared certificate byte
        leaf.push(0xff); // trailing byte outside declared certificate
        let entry = CtLogEntryResponse {
            leaf_input: base64::engine::general_purpose::STANDARD.encode(leaf),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        let err = parser.parse_entry(&entry, 0).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    #[test]
    fn test_parse_entry_invalid_base64() {
        let entry = CtLogEntryResponse {
            leaf_input: "not-base64!!".to_string(),
            extra_data: String::new(),
        };

        let parser = Parser::new("test-log".to_string());
        assert!(parser.parse_entry(&entry, 0).is_err());
    }
}
