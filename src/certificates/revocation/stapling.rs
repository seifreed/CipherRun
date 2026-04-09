use super::{OcspStaplingResult, RevocationChecker};
use crate::Result;
use crate::certificates::parser::CertificateInfo;
use tracing::trace;
use x509_parser::prelude::*;

impl RevocationChecker {
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

        if let Ok(Some(ext)) = parsed_cert.get_extension_unique(&tls_feature_oid) {
            // Parse the TLS Feature extension value to check for Must-Staple.
            // The value is ASN.1: SEQUENCE OF INTEGER.
            // Feature ID 5 = status_request (OCSP Must-Staple, RFC 7633).
            // We must verify the extension actually contains feature 5,
            // not just assume any TLS Feature extension means Must-Staple.
            let ext_value = ext.value;
            if let Ok((_, seq)) = der_parser::der::parse_der_sequence(ext_value)
                && let Ok(items) = seq.as_sequence()
            {
                for item in items {
                    if let Ok(val) = item.as_u64()
                        && val == 5
                    {
                        return Ok(true);
                    }
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
    pub fn check_ocsp_stapling(&self, tls_handshake_data: &[u8]) -> OcspStaplingResult {
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
            let record_type = tls_handshake_data[offset];

            // Skip non-handshake records by reading their full record header and length
            if record_type != 0x16 {
                // Handshake
                // Read the 5-byte TLS record header to skip the entire record
                let record_len = ((tls_handshake_data[offset + 3] as usize) << 8)
                    | (tls_handshake_data[offset + 4] as usize);
                offset += 5 + record_len;
                continue;
            }

            if offset + 5 > tls_handshake_data.len() {
                break;
            }

            // Get record length
            let record_len = ((tls_handshake_data[offset + 3] as usize) << 8)
                | (tls_handshake_data[offset + 4] as usize);

            if offset + 5 + record_len > tls_handshake_data.len() {
                break;
            }

            let handshake_start = offset + 5;
            let handshake_end = handshake_start + record_len;
            let handshake_data =
                &tls_handshake_data[handshake_start..handshake_end.min(tls_handshake_data.len())];

            // Parse handshake messages within this record
            let mut msg_offset = 0;
            while msg_offset + 4 <= handshake_data.len() {
                let msg_type = handshake_data[msg_offset];
                let msg_len = ((handshake_data[msg_offset + 1] as usize) << 16)
                    | ((handshake_data[msg_offset + 2] as usize) << 8)
                    | (handshake_data[msg_offset + 3] as usize);

                if msg_offset + 4 + msg_len > handshake_data.len() {
                    break;
                }

                match msg_type {
                    HANDSHAKE_TYPE_SERVER_HELLO => {
                        // Check for status_request extension in ServerHello
                        if let Some(has_extension) = Self::parse_server_hello_extensions(
                            &handshake_data[msg_offset + 4..msg_offset + 4 + msg_len],
                            EXTENSION_STATUS_REQUEST,
                        ) {
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
                            let response_len = ((handshake_data[msg_offset + 5] as usize) << 16)
                                | ((handshake_data[msg_offset + 6] as usize) << 8)
                                | (handshake_data[msg_offset + 7] as usize);

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

        result
    }

    /// Parse ServerHello to find specific extension
    fn parse_server_hello_extensions(server_hello: &[u8], extension_type: u16) -> Option<bool> {
        // ServerHello structure: version (2) + random (32) + session_id_len (1) +
        // session_id (variable) + cipher_suites_len (2) + cipher_suites (variable) +
        // compression_method (1) + extensions_len (2) + extensions (variable)

        let mut offset = 0;

        // Version (2 bytes)
        if offset + 2 > server_hello.len() {
            return None;
        }
        offset += 2;

        // Random (32 bytes)
        if offset + 32 > server_hello.len() {
            return None;
        }
        offset += 32;

        // Session ID length
        if offset + 1 > server_hello.len() {
            return None;
        }
        let session_id_len = server_hello[offset] as usize;
        offset += 1;

        // Session ID
        if offset + session_id_len > server_hello.len() {
            return None;
        }
        offset += session_id_len;

        // Cipher suite (2 bytes)
        if offset + 2 > server_hello.len() {
            return None;
        }
        offset += 2;

        // Compression method (1 byte)
        if offset + 1 > server_hello.len() {
            return None;
        }
        offset += 1;

        // Extensions length (2 bytes)
        if offset + 2 > server_hello.len() {
            return None;
        }
        let extensions_len =
            ((server_hello[offset] as usize) << 8) | (server_hello[offset + 1] as usize);
        offset += 2;

        // Parse extensions
        let extensions_end = offset + extensions_len;
        if extensions_end > server_hello.len() {
            return None;
        }

        while offset + 4 <= extensions_end {
            let ext_type = ((server_hello[offset] as u16) << 8) | (server_hello[offset + 1] as u16);
            let ext_len =
                ((server_hello[offset + 2] as usize) << 8) | (server_hello[offset + 3] as usize);

            if ext_type == extension_type {
                return Some(true);
            }

            if offset + 4 + ext_len > extensions_end {
                break;
            }
            offset += 4 + ext_len;
        }

        Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_stapling_empty_data() {
        let checker = RevocationChecker::new(true);
        let result = checker.check_ocsp_stapling(&[]);
        assert!(!result.stapling_supported);
        assert!(!result.stapled_response_present);
        assert!(result.details.contains("No OCSP stapling"));
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
}
