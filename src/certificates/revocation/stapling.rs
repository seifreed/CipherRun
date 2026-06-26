use super::{OcspStaplingResult, RevocationChecker};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use tracing::trace;
use x509_parser::prelude::*;

impl RevocationChecker {
    fn read_u8_at(data: &[u8], offset: usize, context: &str) -> Result<u8> {
        data.get(offset)
            .copied()
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })
    }

    fn read_u16_at(data: &[u8], offset: usize, context: &str) -> Result<u16> {
        let bytes = data
            .get(offset..offset + 2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24_at(data: &[u8], offset: usize, context: &str) -> Result<usize> {
        let [high, mid, low] = data
            .get(offset..offset + 3)
            .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} truncated"),
            })?;
        Ok(((high as usize) << 16) | ((mid as usize) << 8) | low as usize)
    }

    fn slice_range<'a>(
        data: &'a [u8],
        start: usize,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8]> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length overflow"),
            })?;
        data.get(start..end)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: format!("{context} length exceeds available data"),
            })
    }

    /// Check if certificate has OCSP Must-Staple extension
    pub(crate) fn check_must_staple(&self, cert: &CertificateInfo) -> Result<bool> {
        // Handle empty DER bytes gracefully
        if cert.der_bytes.is_empty() {
            return Ok(false);
        }

        let (_, parsed_cert) = X509Certificate::from_der(&cert.der_bytes).map_err(|e| {
            crate::error::TlsError::ParseError {
                message: format!("Failed to parse certificate: {:?}", e),
            }
        })?;

        // Look for TLS Feature extension (OCSP Must-Staple)
        // OID: 1.3.6.1.5.5.7.1.24
        use x509_parser::der_parser::oid::Oid;
        let tls_feature_oid = Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 24]).map_err(|_| {
            crate::error::TlsError::ParseError {
                message: "Invalid OID".into(),
            }
        })?;

        if let Some(ext) = parsed_cert
            .get_extension_unique(&tls_feature_oid)
            .map_err(|error| crate::TlsError::ParseError {
                message: format!("Failed to parse TLS Feature extension: {error}"),
            })?
        {
            // Parse the TLS Feature extension value to check for Must-Staple.
            // The value is ASN.1: SEQUENCE OF INTEGER.
            // Feature ID 5 = status_request (OCSP Must-Staple, RFC 7633).
            // We must verify the extension actually contains feature 5,
            // not just assume any TLS Feature extension means Must-Staple.
            let ext_value = ext.value;
            let (_, seq) = der_parser::der::parse_der_sequence(ext_value).map_err(|error| {
                crate::TlsError::ParseError {
                    message: format!("Failed to parse TLS Feature extension: {error}"),
                }
            })?;
            let items = seq
                .as_sequence()
                .map_err(|error| crate::TlsError::ParseError {
                    message: format!("Failed to parse TLS Feature extension: {error}"),
                })?;
            for item in items {
                let val = item.as_u64().map_err(|error| crate::TlsError::ParseError {
                    message: format!("Failed to parse TLS Feature extension: {error}"),
                })?;
                if val == 5 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check OCSP stapling support by analyzing TLS handshake data
    ///
    /// This function parses the TLS handshake to detect:
    /// 1. status_request extension (0x0005) in ServerHello - indicates server CAN staple
    /// 2. Certificate Status message (type 22) - indicates server DID staple
    ///
    /// # Arguments
    /// * `tls_handshake_data` - Raw bytes from the TLS handshake (ServerHello and subsequent messages)
    ///
    /// # Returns
    /// * `OcspStaplingResult` with detection results
    pub fn check_ocsp_stapling(&self, tls_handshake_data: &[u8]) -> Result<OcspStaplingResult> {
        let mut result = OcspStaplingResult {
            stapling_supported: false,
            stapled_response_present: false,
            stapled_response_valid: None,
            details: String::new(),
        };

        // TLS Handshake message types
        const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
        const HANDSHAKE_TYPE_CERTIFICATE_STATUS: u8 = 0x16; // 22 decimal

        // Extension type for status_request (OCSP stapling)
        const EXTENSION_STATUS_REQUEST: u16 = 0x0005;

        // Parse through the handshake data looking for ServerHello
        let mut offset = 0;
        while offset + 5 <= tls_handshake_data.len() {
            // TLS record header: type (1) + version (2) + length (2)
            let record_type = Self::read_u8_at(tls_handshake_data, offset, "TLS record header")?;

            // Skip non-handshake records by reading their full record header and length
            if record_type != 0x16 {
                // Handshake
                // Read the 5-byte TLS record header to skip the entire record
                let record_len =
                    Self::read_u16_at(tls_handshake_data, offset + 3, "TLS record length")?
                        as usize;
                if offset + 5 + record_len > tls_handshake_data.len() {
                    return Err(crate::TlsError::ParseError {
                        message: "TLS record length exceeds available data".to_string(),
                    });
                }
                offset += 5 + record_len;
                continue;
            }

            if offset + 5 > tls_handshake_data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "TLS record header truncated".to_string(),
                });
            }

            // Get record length
            let record_len =
                Self::read_u16_at(tls_handshake_data, offset + 3, "TLS record length")? as usize;

            if offset + 5 + record_len > tls_handshake_data.len() {
                return Err(crate::TlsError::ParseError {
                    message: "TLS record length exceeds available data".to_string(),
                });
            }

            let handshake_start = offset + 5;
            let handshake_end = handshake_start + record_len;
            let handshake_data = Self::slice_range(
                tls_handshake_data,
                handshake_start,
                record_len,
                "TLS handshake record",
            )?;

            // Parse handshake messages within this record
            let mut msg_offset = 0;
            while msg_offset + 4 <= handshake_data.len() {
                let msg_type =
                    Self::read_u8_at(handshake_data, msg_offset, "Handshake message type")?;
                let msg_len =
                    Self::read_u24_at(handshake_data, msg_offset + 1, "Handshake message length")?;

                if msg_offset + 4 + msg_len > handshake_data.len() {
                    return Err(crate::TlsError::ParseError {
                        message: "Handshake message length exceeds available data".to_string(),
                    });
                }

                match msg_type {
                    HANDSHAKE_TYPE_SERVER_HELLO => {
                        // Check for status_request extension in ServerHello
                        let body = Self::slice_range(
                            handshake_data,
                            msg_offset + 4,
                            msg_len,
                            "ServerHello body",
                        )?;
                        if let Some(has_extension) =
                            Self::parse_server_hello_extensions(body, EXTENSION_STATUS_REQUEST)?
                        {
                            result.stapling_supported = has_extension;
                            if has_extension {
                                result.details.push_str("Server advertised OCSP stapling support (status_request extension). ");
                            }
                        }
                    }
                    HANDSHAKE_TYPE_CERTIFICATE_STATUS => {
                        // Certificate Status message indicates stapled OCSP response
                        result.stapled_response_present = true;
                        result
                            .details
                            .push_str("Stapled OCSP response found (Certificate Status message). ");

                        // Try to validate the response structure
                        // Certificate Status body: status_type (1 byte) + response_length (3 bytes) = 4 bytes minimum
                        // Body starts at msg_offset + 4 (after 4-byte handshake header)
                        if msg_len >= 4 && msg_offset + 8 <= handshake_data.len() {
                            // Skip status_type (1 byte at msg_offset+4), read response_length (3 bytes at msg_offset+5..8)
                            let response_len = Self::read_u24_at(
                                handshake_data,
                                msg_offset + 5,
                                "OCSP response length",
                            )?;

                            // Certificate Status structure: status_type (1 byte) + response_length (3 bytes) + response
                            // Total overhead is 4 bytes, so check response_len + 4 <= msg_len
                            if response_len > 0 && response_len + 4 <= msg_len {
                                result.stapled_response_valid = Some(true);
                                result.details.push_str(&format!(
                                    "OCSP response length: {} bytes. ",
                                    response_len
                                ));
                            } else {
                                result.stapled_response_valid = Some(false);
                                result.details.push_str("Invalid OCSP response structure. ");
                            }
                        }
                    }
                    _ => {
                        trace!(
                            "Skipping unknown handshake message type: 0x{:02x}",
                            msg_type
                        );
                    }
                }

                msg_offset += 4 + msg_len;
            }

            offset = handshake_end;
        }

        // Finalize result
        if result.details.is_empty() {
            result.details = "No OCSP stapling detected in TLS handshake".to_string();
        }

        if result.stapling_supported && !result.stapled_response_present {
            result.details.push_str("(Note: Server supports stapling but did not provide stapled response - may be intentional or first connection)");
        }

        Ok(result)
    }

    /// Parse ServerHello to find specific extension
    fn parse_server_hello_extensions(
        server_hello: &[u8],
        extension_type: u16,
    ) -> Result<Option<bool>> {
        // ServerHello structure: version (2) + random (32) + session_id_len (1) +
        // session_id (variable) + cipher_suites_len (2) + cipher_suites (variable) +
        // compression_method (1) + extensions_len (2) + extensions (variable)

        let mut offset = 0;

        // Version (2 bytes)
        if offset + 2 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before version".to_string(),
            });
        }
        offset += 2;

        // Random (32 bytes)
        if offset + 32 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before random".to_string(),
            });
        }
        offset += 32;

        // Session ID length
        if offset + 1 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before session ID length".to_string(),
            });
        }
        let session_id_len =
            Self::read_u8_at(server_hello, offset, "ServerHello session ID length")? as usize;
        offset += 1;

        // Session ID
        if offset + session_id_len > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before session ID".to_string(),
            });
        }
        offset += session_id_len;

        // Cipher suite (2 bytes)
        if offset + 2 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before cipher suite".to_string(),
            });
        }
        offset += 2;

        // Compression method (1 byte)
        if offset + 1 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before compression".to_string(),
            });
        }
        offset += 1;

        // Extensions length (2 bytes)
        if offset + 2 > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated before extensions length".to_string(),
            });
        }
        let extensions_len =
            Self::read_u16_at(server_hello, offset, "ServerHello extensions length")? as usize;
        offset += 2;

        // Parse extensions
        let extensions_end = offset + extensions_len;
        if extensions_end > server_hello.len() {
            return Err(crate::TlsError::ParseError {
                message: "ServerHello truncated in extensions".to_string(),
            });
        }

        while offset + 4 <= extensions_end {
            let ext_type = Self::read_u16_at(server_hello, offset, "ServerHello extension type")?;
            let ext_len =
                Self::read_u16_at(server_hello, offset + 2, "ServerHello extension length")?
                    as usize;

            if ext_type == extension_type {
                return Ok(Some(true));
            }

            if offset + 4 + ext_len > extensions_end {
                return Err(crate::TlsError::ParseError {
                    message: "ServerHello truncated in extension data".to_string(),
                });
            }
            offset += 4 + ext_len;
        }

        Ok(Some(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_with_raw_extension_der(oid: &str, contents: &[u8]) -> CertificateInfo {
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::hash::MessageDigest as OpensslMessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

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
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        let extension = X509Extension::new_from_der(&oid, false, &contents).unwrap();
        builder.append_extension(extension).unwrap();
        builder.sign(&pkey, OpensslMessageDigest::sha256()).unwrap();

        CertificateInfo {
            der_bytes: builder.build().to_der().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn test_ocsp_stapling_empty_data() {
        let checker = RevocationChecker::new(true);
        let result = checker.check_ocsp_stapling(&[]).unwrap();
        assert!(!result.stapling_supported);
        assert!(!result.stapled_response_present);
        assert!(result.details.contains("No OCSP stapling"));
    }

    #[test]
    fn test_check_ocsp_stapling_rejects_truncated_server_hello_extension() {
        let checker = RevocationChecker::new(true);
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x31, // TLS record, length 49
            0x02, 0x00, 0x00, 0x2d, // ServerHello, length 45
            0x03, 0x03, // version
        ];
        data.extend_from_slice(&[0x00; 32]); // random
        data.push(0x00); // session id len
        data.extend_from_slice(&[0x00, 0x9c]); // cipher
        data.push(0x00); // compression
        data.extend_from_slice(&[0x00, 0x07]); // extensions len
        data.extend_from_slice(&[0x00, 0x05]); // status_request
        data.extend_from_slice(&[0x00, 0x02]); // ext len claims 2
        data.push(0x01); // truncated ext data (1 byte instead of 2)

        let err = checker.check_ocsp_stapling(&data).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn test_check_ocsp_stapling_rejects_truncated_record() {
        let checker = RevocationChecker::new(true);
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00];

        let err = checker.check_ocsp_stapling(&data).unwrap_err();
        assert!(
            err.to_string()
                .contains("TLS record length exceeds available data")
        );
    }

    #[test]
    fn test_check_ocsp_stapling_rejects_truncated_alert_record() {
        let checker = RevocationChecker::new(true);
        let data = vec![0x15, 0x03, 0x03, 0x00, 0x05, 0x02];

        let err = checker.check_ocsp_stapling(&data).unwrap_err();
        assert!(
            err.to_string()
                .contains("TLS record length exceeds available data")
        );
    }

    #[test]
    fn test_ocsp_stapling_result_structure() {
        let result = OcspStaplingResult {
            stapling_supported: true,
            stapled_response_present: true,
            stapled_response_valid: Some(true),
            details: "Test details".to_string(),
        };
        assert!(result.stapling_supported);
        assert!(result.stapled_response_present);
        assert!(result.stapled_response_valid.unwrap_or(false));
    }

    #[test]
    fn test_check_must_staple_empty_der() {
        let checker = RevocationChecker::new(true);
        let cert = CertificateInfo {
            der_bytes: vec![],
            ..Default::default()
        };
        assert!(!checker.check_must_staple(&cert).unwrap());
    }

    #[test]
    fn test_check_must_staple_invalid_der_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = CertificateInfo {
            der_bytes: vec![0x30, 0x01, 0x00],
            ..Default::default()
        };

        let err = checker.check_must_staple(&cert).unwrap_err();
        assert!(format!("{err}").contains("Failed to parse certificate"));
    }

    #[test]
    fn test_check_must_staple_malformed_tls_feature_returns_error() {
        let checker = RevocationChecker::new(false);
        let cert = cert_with_raw_extension_der("1.3.6.1.5.5.7.1.24", b"\x05\x00");

        let err = checker.check_must_staple(&cert).unwrap_err();
        assert!(format!("{err}").contains("TLS Feature extension"));
    }
}
