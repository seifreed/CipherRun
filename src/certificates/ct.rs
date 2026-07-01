// Certificate Transparency (CT) verification
// RFC 6962 - Certificate Transparency

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

/// Certificate Transparency verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtVerificationResult {
    pub has_sct: bool,
    pub sct_count: usize,
    pub sct_sources: Vec<SctSource>,
    pub compliant: bool,
    pub details: Vec<String>,
    #[serde(default)]
    pub log_lookup_inconclusive: bool,
}

/// SCT (Signed Certificate Timestamp) source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SctSource {
    /// SCT embedded in certificate extension
    X509Extension,
    /// SCT in TLS extension
    TlsExtension,
    /// SCT stapled in OCSP response
    OcspStapling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CtLogLookup {
    Found,
    NotFound,
    Inconclusive(String),
}

/// Certificate Transparency verifier
pub struct CtVerifier {
    phone_out: bool,
}

impl CtVerifier {
    pub fn new(phone_out: bool) -> Self {
        Self { phone_out }
    }

    /// Verify Certificate Transparency for a certificate
    pub async fn verify(&self, cert: &CertificateInfo) -> Result<CtVerificationResult> {
        let mut result = CtVerificationResult {
            has_sct: false,
            sct_count: 0,
            sct_sources: Vec::new(),
            compliant: false,
            details: Vec::new(),
            log_lookup_inconclusive: false,
        };

        // Check for SCT in X.509 certificate extension
        if let Some(sct_count) = self.check_x509_sct_extension(cert)? {
            result.has_sct = true;
            result.sct_count += sct_count;
            result.sct_sources.push(SctSource::X509Extension);
            result
                .details
                .push(format!("Found {} SCT(s) in X.509 extension", sct_count));
        }

        // Check if certificate is in CT logs (requires network access)
        if self.phone_out {
            match self.check_ct_logs(cert).await {
                Ok(CtLogLookup::Found) => {
                    result
                        .details
                        .push("Certificate found in public CT logs".to_string());
                }
                Ok(CtLogLookup::NotFound) => {
                    result
                        .details
                        .push("Certificate NOT found in public CT logs".to_string());
                }
                Ok(CtLogLookup::Inconclusive(reason)) => {
                    result.log_lookup_inconclusive = true;
                    result
                        .details
                        .push(format!("CT log lookup inconclusive: {}", reason));
                }
                Err(err) => {
                    result.log_lookup_inconclusive = true;
                    result
                        .details
                        .push(format!("CT log lookup inconclusive: {}", err));
                }
            }
        }

        // Determine compliance
        // Modern browsers require at least 2 SCTs from different logs
        result.compliant = result.sct_count >= 2;

        if result.sct_count == 0 {
            result
                .details
                .push("WARNING: No SCTs found - not CT compliant".to_string());
        } else if result.sct_count == 1 {
            result
                .details
                .push("WARNING: Only 1 SCT found - browsers require at least 2".to_string());
        } else {
            result.details.push(format!(
                "✓ Certificate is CT compliant ({} SCTs)",
                result.sct_count
            ));
        }

        Ok(result)
    }

    /// Check for SCT extension in X.509 certificate
    fn check_x509_sct_extension(&self, cert: &CertificateInfo) -> Result<Option<usize>> {
        // SCT extension OID: 1.3.6.1.4.1.11129.2.4.2
        const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

        // Parse the raw certificate to check extensions
        let (rest, parsed_cert) = X509Certificate::from_der(&cert.der_bytes).map_err(|_| {
            crate::error::TlsError::ParseError {
                message: "Failed to parse certificate".into(),
            }
        })?;
        if !rest.is_empty() {
            return Err(crate::error::TlsError::ParseError {
                message: "Certificate DER contains trailing bytes".to_string(),
            });
        }

        // Look for SCT extension
        for ext in parsed_cert.extensions() {
            let oid_str = ext.oid.to_id_string();
            if oid_str == SCT_EXTENSION_OID {
                return Ok(Some(self.count_scts_in_extension_value(ext.value)?));
            }
        }

        Ok(None)
    }

    /// Count SCTs given the raw certificate-extension value bytes.
    ///
    /// RFC 6962 §3.3: after x509-parser strips the mandatory extnValue OCTET
    /// STRING, the SCT extension still wraps the SignedCertificateTimestampList
    /// in an inner DER OCTET STRING. It must be unwrapped first; counting against
    /// the raw value would read the inner OCTET STRING tag/length as the SCT-list
    /// length and yield a wrong (usually zero) count.
    fn count_scts_in_extension_value(&self, ext_value: &[u8]) -> Result<usize> {
        let parsed_inner = der_parser::der::parse_der_octetstring(ext_value);
        let sct_list: &[u8] = match &parsed_inner {
            Ok((rest, _)) if !rest.is_empty() => {
                return Err(crate::TlsError::ParseError {
                    message: "Malformed SCT extension: trailing bytes after inner OCTET STRING"
                        .to_string(),
                });
            }
            Ok((_, obj)) => obj.as_slice().unwrap_or(ext_value),
            Err(_) => ext_value,
        };

        self.count_scts_in_list(sct_list)
    }

    /// Count SCTs in SCT list
    fn count_scts_in_list(&self, sct_list: &[u8]) -> Result<usize> {
        if sct_list.len() < 2 {
            return Err(crate::error::TlsError::ParseError {
                message: "Malformed SCT list: too short".to_string(),
            });
        }

        // Read total length (big-endian u16)
        let total_len_bytes = sct_list
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| crate::error::TlsError::ParseError {
                message: "Malformed SCT list: too short".to_string(),
            })?;
        let total_len = u16::from_be_bytes(total_len_bytes) as usize;

        // Validate that we have enough data for the declared length
        // The total_len represents the number of bytes that follow the 2-byte length field
        if total_len + 2 > sct_list.len() {
            return Err(crate::error::TlsError::ParseError {
                message: format!(
                    "Malformed SCT list: declared length {} exceeds data length {}",
                    total_len + 2,
                    sct_list.len()
                ),
            });
        }
        if total_len + 2 != sct_list.len() {
            return Err(crate::error::TlsError::ParseError {
                message: "Malformed SCT list: trailing bytes after declared length".to_string(),
            });
        }

        let mut count = 0;
        let mut pos = 2usize;
        let end_pos =
            2usize
                .checked_add(total_len)
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "Malformed SCT list: length overflow".to_string(),
                })?;

        // Parse each SCT entry within the declared length
        while let Some(len_end) = pos.checked_add(2).filter(|&end| end <= end_pos) {
            // Each SCT starts with 2-byte length
            let sct_len_bytes = sct_list
                .get(pos..len_end)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .ok_or_else(|| crate::error::TlsError::ParseError {
                    message: "Malformed SCT entry: missing length".to_string(),
                })?;
            let sct_len = u16::from_be_bytes(sct_len_bytes) as usize;
            pos = len_end;

            let next_pos =
                pos.checked_add(sct_len)
                    .ok_or_else(|| crate::error::TlsError::ParseError {
                        message: "Malformed SCT entry: length overflow".to_string(),
                    })?;

            if next_pos > end_pos {
                return Err(crate::error::TlsError::ParseError {
                    message: format!(
                        "Malformed SCT entry: SCT at offset {} with length {} extends past list end {}",
                        pos, sct_len, end_pos
                    ),
                });
            }

            // Skip SCT data
            pos = next_pos;
            count += 1;
        }
        if pos != end_pos {
            return Err(crate::error::TlsError::ParseError {
                message: "Malformed SCT entry: trailing bytes in SCT list".to_string(),
            });
        }

        Ok(count)
    }

    /// Check if certificate appears in public CT logs
    async fn check_ct_logs(&self, cert: &CertificateInfo) -> Result<CtLogLookup> {
        if !self.phone_out {
            return Ok(CtLogLookup::Inconclusive(
                "phone-out CT lookup disabled".to_string(),
            ));
        }

        // Use crt.sh API to check if certificate is logged
        // This is a public service that indexes CT logs
        let fingerprint = match &cert.fingerprint_sha256 {
            Some(fp) => fp.replace(':', ""),
            None => {
                return Ok(CtLogLookup::Inconclusive(
                    "certificate has no SHA-256 fingerprint".to_string(),
                ));
            }
        };
        let url = format!("https://crt.sh/?q={}&output=json", fingerprint);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    // Cap the body to avoid an unbounded read from a MITM'd or
                    // misbehaving crt.sh; a per-fingerprint query is small JSON.
                    const MAX_CRT_SH_BYTES: u64 = 16 * 1024 * 1024;
                    let body = crate::utils::http::read_response_body_capped(
                        response,
                        MAX_CRT_SH_BYTES,
                        "crt.sh",
                    )
                    .await?;
                    let text = String::from_utf8_lossy(&body);
                    Self::parse_ct_log_response(&text)
                } else {
                    Err(crate::TlsError::HttpError {
                        status: response.status().as_u16(),
                        details: "crt.sh CT lookup returned non-success status".to_string(),
                    })
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    fn parse_ct_log_response(text: &str) -> Result<CtLogLookup> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        match value {
            serde_json::Value::Array(entries) if entries.is_empty() => Ok(CtLogLookup::NotFound),
            serde_json::Value::Array(_) => Ok(CtLogLookup::Found),
            _ => Err(crate::TlsError::ParseError {
                message: "CT log response was not a JSON array".to_string(),
            }),
        }
    }

    /// Check CT policy compliance for different contexts
    pub fn check_policy_compliance(
        &self,
        result: &CtVerificationResult,
        validity_months: i64,
    ) -> CtPolicyCompliance {
        // Google CT Policy (Chrome requirement)
        // https://github.com/chromium/ct-policy
        let required_scts = if validity_months > 39 {
            3 // Certificates valid for > 39 months need 3 SCTs
        } else {
            2 // Certificates valid for ≤ 39 months need 2 SCTs
        };

        let chrome_compliant = result.sct_count >= required_scts;

        // Apple CT Policy (Safari requirement)
        // Similar to Google but with some differences
        let apple_compliant = result.sct_count >= 2;

        CtPolicyCompliance {
            chrome_compliant,
            safari_compliant: apple_compliant,
            required_scts,
            actual_scts: result.sct_count,
        }
    }
}

/// CT Policy compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtPolicyCompliance {
    pub chrome_compliant: bool,
    pub safari_compliant: bool,
    pub required_scts: usize,
    pub actual_scts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_verifier_creation() {
        let verifier = CtVerifier::new(false);
        assert!(!verifier.phone_out);
    }

    #[test]
    fn test_count_scts_in_list() {
        let verifier = CtVerifier::new(false);
        let sct_list = vec![
            0x00, 0x0c, // total length
            0x00, 0x03, 0x01, 0x02, 0x03, // entry 1
            0x00, 0x05, 0x04, 0x05, 0x06, 0x07, 0x08, // entry 2
        ];
        let count = verifier
            .count_scts_in_list(&sct_list)
            .expect("test assertion should succeed");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_scts_in_extension_value_unwraps_der_octet_string() {
        let verifier = CtVerifier::new(false);
        // Inner SignedCertificateTimestampList: 2-byte total length + 2 entries.
        let sct_list = [
            0x00, 0x0c, // total length
            0x00, 0x03, 0x01, 0x02, 0x03, // entry 1
            0x00, 0x05, 0x04, 0x05, 0x06, 0x07, 0x08, // entry 2
        ];
        // RFC 6962 double-wrap: the extension value is a DER OCTET STRING
        // (tag 0x04, length 14) wrapping the SCT list.
        let mut ext_value = vec![0x04, sct_list.len() as u8];
        ext_value.extend_from_slice(&sct_list);

        let count = verifier
            .count_scts_in_extension_value(&ext_value)
            .expect("test assertion should succeed");
        assert_eq!(
            count, 2,
            "must unwrap the inner OCTET STRING before counting"
        );
    }

    #[test]
    fn test_count_scts_in_extension_value_rejects_trailing_der_bytes() {
        let verifier = CtVerifier::new(false);
        let sct_list = [0x00, 0x00];
        let mut ext_value = vec![0x04, sct_list.len() as u8];
        ext_value.extend_from_slice(&sct_list);
        ext_value.push(0xff);

        let err = verifier
            .count_scts_in_extension_value(&ext_value)
            .expect_err("trailing DER bytes should fail");

        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn test_count_scts_in_extension_value_rejects_short_list() {
        let verifier = CtVerifier::new(false);

        let err = verifier
            .count_scts_in_extension_value(&[0x04, 0x01, 0x00])
            .expect_err("short SCT list should fail");

        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_count_scts_in_list_invalid_length() {
        let verifier = CtVerifier::new(false);
        // SCT list format: 2-byte total length + SCT entries
        // This test has a mismatch: declared length (4 bytes) but actual data is shorter
        // 0x00 0x04 = 4 bytes declared, but only 3 bytes follow (00 05 01)
        // The function should reject malformed data instead of silently counting 0.
        let sct_list = vec![0x00, 0x04, 0x00, 0x05, 0x01];
        let err = verifier
            .count_scts_in_list(&sct_list)
            .expect_err("Malformed SCT list should fail");
        assert!(err.to_string().contains("Malformed SCT list"));
    }

    #[test]
    fn test_count_scts_in_list_rejects_trailing_bytes() {
        let verifier = CtVerifier::new(false);
        let sct_list = vec![
            0x00, 0x05, // total length
            0x00, 0x03, 0x01, 0x02, 0x03, // entry
            0xff, // trailing byte outside declared length
        ];
        let err = verifier
            .count_scts_in_list(&sct_list)
            .expect_err("trailing bytes should fail");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn test_count_scts_in_list_rejects_trailing_entry_byte() {
        let verifier = CtVerifier::new(false);
        let sct_list = vec![
            0x00, 0x06, // total length
            0x00, 0x03, 0x01, 0x02, 0x03, // entry
            0xff, // trailing byte inside declared length
        ];
        let err = verifier
            .count_scts_in_list(&sct_list)
            .expect_err("trailing entry byte should fail");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[tokio::test]
    async fn test_verify_without_sct() {
        let verifier = CtVerifier::new(false);
        let cert = rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("test assertion should succeed");

        let cert_info = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial_number: "01".to_string(),
            not_before: "2024-01-01 00:00:00 +0000".to_string(),
            not_after: "2025-01-01 00:00:00 +0000".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["example.com".to_string()],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: cert.cert.der().as_ref().to_vec(),
        };

        let result = verifier
            .verify(&cert_info)
            .await
            .expect("test assertion should succeed");
        assert!(!result.has_sct);
        assert_eq!(result.sct_count, 0);
        assert!(!result.compliant);
        assert!(!result.log_lookup_inconclusive);
    }

    #[test]
    fn test_check_x509_sct_extension_rejects_trailing_der_bytes() {
        let verifier = CtVerifier::new(false);
        let cert = rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("test assertion should succeed");
        let mut der_bytes = cert.cert.der().as_ref().to_vec();
        der_bytes.push(0xff);

        let cert_info = CertificateInfo {
            der_bytes,
            ..Default::default()
        };

        let err = verifier
            .check_x509_sct_extension(&cert_info)
            .expect_err("trailing DER bytes should fail");
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[tokio::test]
    async fn test_verify_phone_out_without_fingerprint_marks_lookup_inconclusive() {
        let verifier = CtVerifier::new(true);
        let cert = rcgen::generate_simple_self_signed(["example.com".to_string()])
            .expect("test assertion should succeed");

        let cert_info = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial_number: "01".to_string(),
            not_before: "2024-01-01 00:00:00 +0000".to_string(),
            not_after: "2025-01-01 00:00:00 +0000".to_string(),
            expiry_countdown: None,
            signature_algorithm: "sha256".to_string(),
            public_key_algorithm: "rsaEncryption".to_string(),
            public_key_size: Some(2048),
            rsa_exponent: None,
            san: vec!["example.com".to_string()],
            is_ca: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            extended_validation: false,
            ev_oids: vec![],
            pin_sha256: None,
            fingerprint_sha256: None,
            debian_weak_key: None,
            aia_url: None,
            certificate_transparency: None,
            der_bytes: cert.cert.der().as_ref().to_vec(),
        };

        let result = verifier
            .verify(&cert_info)
            .await
            .expect("test assertion should succeed");

        assert!(result.log_lookup_inconclusive);
        assert!(
            result
                .details
                .iter()
                .any(|detail| detail.contains("CT log lookup inconclusive"))
        );
    }

    #[test]
    fn test_sct_source() {
        let source = SctSource::X509Extension;
        assert!(matches!(source, SctSource::X509Extension));
    }

    #[test]
    fn test_policy_compliance() {
        let verifier = CtVerifier::new(false);
        let result = CtVerificationResult {
            has_sct: true,
            sct_count: 3,
            sct_sources: vec![SctSource::X509Extension],
            compliant: true,
            details: vec![],
            log_lookup_inconclusive: false,
        };

        let compliance = verifier.check_policy_compliance(&result, 24);
        assert!(compliance.chrome_compliant);
        assert!(compliance.safari_compliant);
    }

    #[test]
    fn test_policy_compliance_requires_three_for_long_validity() {
        let verifier = CtVerifier::new(false);
        let result = CtVerificationResult {
            has_sct: true,
            sct_count: 2,
            sct_sources: vec![SctSource::X509Extension],
            compliant: false,
            details: vec![],
            log_lookup_inconclusive: false,
        };

        let compliance = verifier.check_policy_compliance(&result, 60);
        assert!(!compliance.chrome_compliant);
        assert!(compliance.safari_compliant);
        assert_eq!(compliance.required_scts, 3);
    }

    #[test]
    fn test_parse_ct_log_response_found_and_not_found() {
        assert_eq!(
            CtVerifier::parse_ct_log_response(r#"[{"id":1}]"#).expect("parse should succeed"),
            CtLogLookup::Found
        );
        assert_eq!(
            CtVerifier::parse_ct_log_response("[]").expect("parse should succeed"),
            CtLogLookup::NotFound
        );
    }

    #[test]
    fn test_parse_ct_log_response_rejects_non_array() {
        let err = CtVerifier::parse_ct_log_response(r#"{"error":"rate limited"}"#)
            .expect_err("non-array CT response should be inconclusive to caller");

        assert!(err.to_string().contains("not a JSON array"));
    }
}
