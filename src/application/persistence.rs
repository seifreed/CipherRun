use crate::scanner::ScanResults;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct PersistedScan {
    pub target_hostname: String,
    pub target_port: u16,
    pub overall_grade: Option<String>,
    pub overall_score: Option<u8>,
    pub scan_duration_ms: u64,
    pub protocols: Vec<PersistedProtocol>,
    pub ciphers: Vec<PersistedCipher>,
    pub vulnerabilities: Vec<PersistedVulnerability>,
    pub ratings: Vec<PersistedRating>,
    pub certificates: Vec<PersistedCertificate>,
}

#[derive(Debug, Clone)]
pub struct PersistedProtocol {
    pub protocol_name: String,
    pub enabled: bool,
    pub preferred: bool,
}

#[derive(Debug, Clone)]
pub struct PersistedCipher {
    pub protocol_name: String,
    pub cipher_name: String,
    pub key_exchange: Option<String>,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub mac: Option<String>,
    pub bits: Option<i32>,
    pub forward_secrecy: bool,
    pub strength: String,
}

#[derive(Debug, Clone)]
pub struct PersistedVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PersistedRating {
    pub category: String,
    pub score: i32,
    pub grade: Option<String>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PersistedCertificate {
    pub fingerprint_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: Option<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub public_key_size: Option<i32>,
    pub san_domains: Vec<String>,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub der_bytes: Option<Vec<u8>>,
    pub chain_position: i32,
}

impl PersistedScan {
    pub fn from_scan_results(results: &ScanResults) -> Self {
        let parts: Vec<&str> = results.target.split(':').collect();
        let target_hostname = parts.first().unwrap_or(&"unknown").to_string();
        let target_port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

        let overall_grade = results.ssl_rating().map(|rating| rating.grade.to_string());
        let overall_score = results.ssl_rating().map(|rating| rating.score);

        let protocols = results
            .protocols
            .iter()
            .map(|protocol| PersistedProtocol {
                protocol_name: protocol.protocol.name().to_string(),
                enabled: protocol.supported,
                preferred: protocol.preferred,
            })
            .collect();

        let ciphers = results
            .ciphers
            .iter()
            .flat_map(|(protocol, summary)| {
                summary
                    .supported_ciphers
                    .iter()
                    .map(move |cipher| PersistedCipher {
                        protocol_name: protocol.name().to_string(),
                        cipher_name: cipher.iana_name.clone(),
                        key_exchange: Some(cipher.key_exchange.clone()),
                        authentication: Some(cipher.authentication.clone()),
                        encryption: Some(cipher.encryption.clone()),
                        mac: Some(cipher.mac.clone()),
                        bits: Some(cipher.bits as i32),
                        forward_secrecy: cipher.has_forward_secrecy(),
                        strength: match cipher.strength() {
                            crate::ciphers::CipherStrength::NULL => "null".to_string(),
                            crate::ciphers::CipherStrength::Export => "export".to_string(),
                            crate::ciphers::CipherStrength::Low => "low".to_string(),
                            crate::ciphers::CipherStrength::Medium => "medium".to_string(),
                            crate::ciphers::CipherStrength::High => "high".to_string(),
                        },
                    })
            })
            .collect();

        let vulnerabilities = results
            .vulnerabilities
            .iter()
            .filter(|v| v.vulnerable)
            .map(|v| PersistedVulnerability {
                vulnerability_type: format!("{:?}", v.vuln_type),
                severity: match v.severity {
                    crate::vulnerabilities::Severity::Critical => "critical".to_string(),
                    crate::vulnerabilities::Severity::High => "high".to_string(),
                    crate::vulnerabilities::Severity::Medium => "medium".to_string(),
                    crate::vulnerabilities::Severity::Low => "low".to_string(),
                    crate::vulnerabilities::Severity::Info => "info".to_string(),
                },
                description: Some(v.details.clone()),
                cve_id: v.cve.clone(),
            })
            .collect();

        let ratings = results
            .ssl_rating()
            .map(|rating| {
                vec![
                    PersistedRating {
                        category: "certificate".to_string(),
                        score: i32::from(rating.certificate_score),
                        grade: None,
                        rationale: None,
                    },
                    PersistedRating {
                        category: "protocol".to_string(),
                        score: i32::from(rating.protocol_score),
                        grade: None,
                        rationale: None,
                    },
                    PersistedRating {
                        category: "key_exchange".to_string(),
                        score: i32::from(rating.key_exchange_score),
                        grade: None,
                        rationale: None,
                    },
                    PersistedRating {
                        category: "cipher".to_string(),
                        score: i32::from(rating.cipher_strength_score),
                        grade: None,
                        rationale: None,
                    },
                ]
            })
            .unwrap_or_default();

        let certificates = results
            .certificate_chain
            .as_ref()
            .map(|cert_data| {
                cert_data
                    .chain
                    .certificates
                    .iter()
                    .enumerate()
                    .map(|(position, cert)| PersistedCertificate {
                        fingerprint_sha256: cert
                            .fingerprint_sha256
                            .clone()
                            .unwrap_or_else(|| format!("unknown_{}", position)),
                        subject: cert.subject.clone(),
                        issuer: cert.issuer.clone(),
                        serial_number: Some(cert.serial_number.clone()),
                        not_before: DateTime::parse_from_rfc3339(&cert.not_before)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now),
                        not_after: DateTime::parse_from_rfc3339(&cert.not_after)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now),
                        signature_algorithm: Some(cert.signature_algorithm.clone()),
                        public_key_algorithm: Some(cert.public_key_algorithm.clone()),
                        public_key_size: cert.public_key_size.map(|s| s as i32),
                        san_domains: cert.san.clone(),
                        is_ca: cert.is_ca,
                        key_usage: cert.key_usage.clone(),
                        extended_key_usage: cert.extended_key_usage.clone(),
                        der_bytes: Some(cert.der_bytes.clone()),
                        chain_position: position as i32,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            target_hostname,
            target_port,
            overall_grade,
            overall_score,
            scan_duration_ms: results.scan_time_ms,
            protocols,
            ciphers,
            vulnerabilities,
            ratings,
            certificates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_minimal_scan_results() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 123,
            ..Default::default()
        };

        let persisted = PersistedScan::from_scan_results(&results);
        assert_eq!(persisted.target_hostname, "example.com");
        assert_eq!(persisted.target_port, 443);
        assert_eq!(persisted.scan_duration_ms, 123);
    }
}
