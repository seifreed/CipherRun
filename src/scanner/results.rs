use crate::Result;
use crate::certificates::{
    parser::CertificateChain, revocation::RevocationResult, validator::ValidationResult,
};
use crate::ciphers::tester::ProtocolCipherSummary;
use crate::client_sim::simulator::ClientSimulationResult;
use crate::http::tester::HeaderAnalysisResult;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::rating::RatingResult;
use crate::vulnerabilities::VulnerabilityResult;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

pub(crate) fn serialize_sorted_map<S, K, V>(
    map: &HashMap<K, V>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    K: Ord + Serialize + Eq + Hash,
    V: Serialize,
{
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));

    let mut map_serializer = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries {
        map_serializer.serialize_entry(key, value)?;
    }
    map_serializer.end()
}

/// Certificate analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAnalysisResult {
    pub chain: CertificateChain,
    pub validation: ValidationResult,
    pub revocation: Option<RevocationResult>,
}

/// Fingerprint results - TLS fingerprinting data (JA3, JA3S, JARM)
///
/// Groups all fingerprinting-related fields together for Interface Segregation.
/// Consumers that only need fingerprint data can work with this struct directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintResults {
    pub ja3_fingerprint: Option<crate::fingerprint::Ja3Fingerprint>,
    pub ja3_match: Option<crate::fingerprint::Ja3Signature>,
    pub ja3s_fingerprint: Option<crate::fingerprint::Ja3sFingerprint>,
    pub ja3s_match: Option<crate::fingerprint::Ja3sSignature>,
    pub jarm_fingerprint: Option<crate::fingerprint::JarmFingerprint>,
    pub client_hello_raw: Option<Vec<u8>>,
    pub server_hello_raw: Option<Vec<u8>>,
}

/// HTTP results - HTTP header analysis data
///
/// Groups HTTP-related fields for Interface Segregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResults {
    pub http_headers: Option<HeaderAnalysisResult>,
}

/// Rating results - SSL Labs rating data
///
/// Groups rating-related fields for Interface Segregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RatingResults {
    pub ssl_rating: Option<RatingResult>,
}

/// Advanced results - Optional advanced analysis data
///
/// Groups optional/advanced fields for Interface Segregation.
/// These are typically only populated when specific flags are used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvancedResults {
    pub intolerance: Option<crate::protocols::intolerance::IntoleranceTestResult>,
    pub alpn_result: Option<crate::protocols::alpn::AlpnReport>,
    pub signature_algorithms: Option<crate::protocols::signatures::SignatureEnumerationResult>,
    pub key_exchange_groups: Option<crate::protocols::groups::GroupEnumerationResult>,
    pub client_simulations: Option<Vec<ClientSimulationResult>>,
    pub client_cas: Option<crate::protocols::client_cas::ClientCAsResult>,
    pub cdn_detection: Option<crate::fingerprint::CdnDetection>,
    pub load_balancer_info: Option<crate::fingerprint::LoadBalancerInfo>,
    /// CT log source (if certificate discovered via CT logs)
    pub ct_log_source: Option<String>,
    /// CT log index (if certificate discovered via CT logs)
    pub ct_log_index: Option<u64>,
}

/// Scan metadata - Multi-IP scan information and connection metadata
///
/// Groups multi-IP scan metadata, SNI info, and probe status for ISP compliance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub pre_handshake_used: bool,
    pub scanned_ips: Vec<crate::utils::anycast::IpScanResult>,
    pub sni_used: Option<String>,
    pub sni_generation_method: Option<SniMethod>,
    pub probe_status: crate::scanner::probe_status::ProbeStatus,
    pub inconsistencies: Option<Vec<crate::scanner::inconsistency::Inconsistency>>,

    /// Full multi-IP scan report (only populated for multi-IP scans)
    /// This is used by the command layer for JSON export of per-IP results.
    #[serde(skip)]
    pub multi_ip_report: Option<crate::scanner::multi_ip::MultiIpScanReport>,
}

/// Scan results - Main struct with ISP-compliant composition
///
/// Uses composition of sub-structs for Interface Segregation Principle compliance.
/// Consumers can access only the data they need through the appropriate sub-struct.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResults {
    // Core results (always present)
    pub target: String,
    pub scan_time_ms: u64,

    // Protocol & Cipher results
    pub protocols: Vec<ProtocolTestResult>,
    #[serde(serialize_with = "serialize_sorted_map")]
    pub ciphers: HashMap<Protocol, ProtocolCipherSummary>,

    // Certificate results (optional group)
    pub certificate_chain: Option<CertificateAnalysisResult>,

    // Fingerprint results (optional group)
    pub fingerprints: Option<FingerprintResults>,

    // HTTP results (optional group)
    pub http: Option<HttpResults>,

    // Vulnerability results
    pub vulnerabilities: Vec<VulnerabilityResult>,

    // Rating
    pub rating: Option<RatingResults>,

    // Advanced/Optional results
    pub advanced: Option<AdvancedResults>,

    // Scan metadata (multi-IP, SNI, probe status)
    #[serde(flatten)]
    pub scan_metadata: ScanMetadata,
}

impl ScanResults {
    /// Get HTTP headers (convenience accessor)
    pub fn http_headers(&self) -> Option<&HeaderAnalysisResult> {
        self.http.as_ref().and_then(|h| h.http_headers.as_ref())
    }

    /// Get SSL rating (convenience accessor)
    pub fn ssl_rating(&self) -> Option<&RatingResult> {
        self.rating.as_ref().and_then(|r| r.ssl_rating.as_ref())
    }

    /// Get JA3 fingerprint (convenience accessor)
    pub fn ja3_fingerprint(&self) -> Option<&crate::fingerprint::Ja3Fingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3_fingerprint.as_ref())
    }

    /// Get JA3 match (convenience accessor)
    pub fn ja3_match(&self) -> Option<&crate::fingerprint::Ja3Signature> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3_match.as_ref())
    }

    /// Get JA3S fingerprint (convenience accessor)
    pub fn ja3s_fingerprint(&self) -> Option<&crate::fingerprint::Ja3sFingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3s_fingerprint.as_ref())
    }

    /// Get JA3S match (convenience accessor)
    pub fn ja3s_match(&self) -> Option<&crate::fingerprint::Ja3sSignature> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.ja3s_match.as_ref())
    }

    /// Get JARM fingerprint (convenience accessor)
    pub fn jarm_fingerprint(&self) -> Option<&crate::fingerprint::JarmFingerprint> {
        self.fingerprints
            .as_ref()
            .and_then(|f| f.jarm_fingerprint.as_ref())
    }

    /// Get client simulations (convenience accessor)
    pub fn client_simulations(&self) -> Option<&Vec<ClientSimulationResult>> {
        self.advanced
            .as_ref()
            .and_then(|a| a.client_simulations.as_ref())
    }

    /// Get intolerance results (convenience accessor)
    pub fn intolerance(&self) -> Option<&crate::protocols::intolerance::IntoleranceTestResult> {
        self.advanced.as_ref().and_then(|a| a.intolerance.as_ref())
    }

    /// Get ALPN result (convenience accessor)
    pub fn alpn_result(&self) -> Option<&crate::protocols::alpn::AlpnReport> {
        self.advanced.as_ref().and_then(|a| a.alpn_result.as_ref())
    }

    /// Get signature algorithms (convenience accessor)
    pub fn signature_algorithms(
        &self,
    ) -> Option<&crate::protocols::signatures::SignatureEnumerationResult> {
        self.advanced
            .as_ref()
            .and_then(|a| a.signature_algorithms.as_ref())
    }

    /// Get key exchange groups (convenience accessor)
    pub fn key_exchange_groups(&self) -> Option<&crate::protocols::groups::GroupEnumerationResult> {
        self.advanced
            .as_ref()
            .and_then(|a| a.key_exchange_groups.as_ref())
    }

    /// Get client CAs (convenience accessor)
    pub fn client_cas(&self) -> Option<&crate::protocols::client_cas::ClientCAsResult> {
        self.advanced.as_ref().and_then(|a| a.client_cas.as_ref())
    }

    /// Get CDN detection (convenience accessor)
    pub fn cdn_detection(&self) -> Option<&crate::fingerprint::CdnDetection> {
        self.advanced
            .as_ref()
            .and_then(|a| a.cdn_detection.as_ref())
    }

    /// Get load balancer info (convenience accessor)
    pub fn load_balancer_info(&self) -> Option<&crate::fingerprint::LoadBalancerInfo> {
        self.advanced
            .as_ref()
            .and_then(|a| a.load_balancer_info.as_ref())
    }

    /// Returns true when later phases clearly established a working network path.
    pub fn has_connection_evidence(&self) -> bool {
        self.protocols.iter().any(|result| result.supported)
            || self.ciphers
                .values()
                .any(|summary| !summary.supported_ciphers.is_empty())
            || self.certificate_chain.is_some()
            || self.http_headers().is_some()
            // A completed vulnerability batch implies the scanner got far enough
            // to exercise network-dependent checks, even when findings are negative.
            || !self.vulnerabilities.is_empty()
            || self.ja3_fingerprint().is_some()
            || self.ja3s_fingerprint().is_some()
            || self.jarm_fingerprint().is_some()
            || self
                .client_simulations()
                .is_some_and(|simulations| simulations.iter().any(|simulation| simulation.success))
            || self.signature_algorithms().is_some_and(|result| {
                result.algorithms.iter().any(|algorithm| algorithm.supported)
            })
            || self.key_exchange_groups().is_some_and(|result| {
                result.measured || result.groups.iter().any(|group| group.supported)
            })
            || self.client_cas().is_some_and(|result| {
                result.requires_client_auth || !result.cas.is_empty()
            })
            || self.intolerance().is_some_and(|result| {
                result.extension_intolerance
                    || result.version_intolerance
                    || result.long_handshake_intolerance
                    || result.incorrect_sni_alerts
                    || result.uses_common_dh_primes
            })
            || self
                .alpn_result()
                .is_some_and(|report| report.alpn_enabled)
    }

    /// Ensure fingerprints sub-struct exists and return mutable reference
    pub fn fingerprints_mut(&mut self) -> &mut FingerprintResults {
        self.fingerprints
            .get_or_insert_with(FingerprintResults::default)
    }

    /// Ensure http sub-struct exists and return mutable reference
    pub fn http_mut(&mut self) -> &mut HttpResults {
        self.http.get_or_insert_with(HttpResults::default)
    }

    /// Ensure rating sub-struct exists and return mutable reference
    pub fn rating_mut(&mut self) -> &mut RatingResults {
        self.rating.get_or_insert_with(RatingResults::default)
    }

    /// Ensure advanced sub-struct exists and return mutable reference
    pub fn advanced_mut(&mut self) -> &mut AdvancedResults {
        self.advanced.get_or_insert_with(AdvancedResults::default)
    }
}

/// SNI generation method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SniMethod {
    Hostname,
    ReversePTR,
    Random,
    Custom(String),
}

impl ScanResults {
    /// Export to JSON
    pub fn to_json(&self, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(self)?)
        } else {
            Ok(serde_json::to_string(self)?)
        }
    }

    /// Export to CSV (simplified)
    pub fn to_csv(&self) -> Result<String> {
        let mut csv = String::new();

        // Vulnerabilities CSV
        csv.push_str("Type,Severity,Status,CVE,Details\n");
        for vuln in &self.vulnerabilities {
            csv.push_str(&format!(
                "{:?},{:?},{},{},{}\n",
                vuln.vuln_type,
                vuln.severity,
                vuln.status_csv_value(),
                vuln.cve.as_deref().unwrap_or("N/A"),
                vuln.details.replace(',', ";")
            ));
        }

        Ok(csv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_metadata_serializes_flat() {
        let results = ScanResults::default();
        let json = serde_json::to_value(&results).unwrap();
        // Fields from ScanMetadata should appear at the root level (not nested)
        assert!(json.get("pre_handshake_used").is_some());
        assert!(json.get("probe_status").is_some());
        assert!(json.get("scanned_ips").is_some());
        // There should be no "scan_metadata" wrapper key
        assert!(json.get("scan_metadata").is_none());
    }
}
