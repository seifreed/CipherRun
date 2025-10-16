// Certificate Transparency (CT) verification
// RFC 6962 - Certificate Transparency

use crate::Result;
use crate::certificates::parser::CertificateInfo;
use reqwest;
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
        if self.phone_out
            && let Ok(in_logs) = self.check_ct_logs(cert).await
        {
            if in_logs {
                result
                    .details
                    .push("Certificate found in public CT logs".to_string());
            } else {
                result
                    .details
                    .push("Certificate NOT found in public CT logs".to_string());
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
        let (_rem, parsed_cert) = X509Certificate::from_der(&cert.der_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to parse certificate"))?;

        // Look for SCT extension
        for ext in parsed_cert.extensions() {
            let oid_str = ext.oid.to_id_string();
            if oid_str == SCT_EXTENSION_OID {
                // Parse SCT list from extension value
                let sct_list = ext.value;

                // SCT list format (simplified):
                // - 2 bytes: total length
                // - N bytes: SCT entries
                if sct_list.len() >= 2 {
                    // Count SCTs (each SCT has specific structure)
                    // This is a simplified count - in production, should parse full structure
                    let count = self.count_scts_in_list(sct_list)?;
                    return Ok(Some(count));
                }
            }
        }

        Ok(None)
    }

    /// Count SCTs in SCT list
    fn count_scts_in_list(&self, sct_list: &[u8]) -> Result<usize> {
        if sct_list.len() < 2 {
            return Ok(0);
        }

        // Read total length (big-endian u16)
        let _total_len = u16::from_be_bytes([sct_list[0], sct_list[1]]);

        let mut count = 0;
        let mut pos = 2;

        // Parse each SCT entry
        while pos + 2 <= sct_list.len() {
            // Each SCT starts with 2-byte length
            if pos + 2 > sct_list.len() {
                break;
            }

            let sct_len = u16::from_be_bytes([sct_list[pos], sct_list[pos + 1]]) as usize;
            pos += 2;

            if pos + sct_len > sct_list.len() {
                break;
            }

            // Skip SCT data
            pos += sct_len;
            count += 1;
        }

        Ok(count)
    }

    /// Check if certificate appears in public CT logs
    async fn check_ct_logs(&self, cert: &CertificateInfo) -> Result<bool> {
        if !self.phone_out {
            return Ok(false);
        }

        // Use crt.sh API to check if certificate is logged
        // This is a public service that indexes CT logs
        let url = format!("https://crt.sh/?q={}&output=json", cert.serial_number);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;
                    // If we get a JSON array back with entries, cert is in CT logs
                    Ok(text.len() > 2 && text.starts_with('['))
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
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
        };

        let compliance = verifier.check_policy_compliance(&result, 24);
        assert!(compliance.chrome_compliant);
        assert!(compliance.safari_compliant);
    }
}
