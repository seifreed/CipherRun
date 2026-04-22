// PQC Readiness Assessment and Scoring

use crate::certificates::parser::CertificateChain;
use crate::protocols::{Protocol, ProtocolTestResult};
use crate::protocols::groups::GroupEnumerationResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcLevel {
    None,
    Partial,
    Hybrid,
    Full,
}

impl PqcLevel {
    pub fn label(&self) -> &'static str {
        match self {
            PqcLevel::None => "None",
            PqcLevel::Partial => "Partial",
            PqcLevel::Hybrid => "Hybrid",
            PqcLevel::Full => "Full",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcReadinessAssessment {
    pub score: u8,
    pub level: PqcLevel,
    pub pq_safe_groups: Vec<String>,
    /// True if zero PQC-safe groups were negotiated
    pub quantum_vulnerable_only: bool,
    /// True when only quantum-vulnerable key exchanges are used — intercepted traffic
    /// can be decrypted retroactively once a large-scale quantum computer exists
    pub hndl_risk: bool,
    pub recommendations: Vec<String>,
}

pub struct PqcReadinessScorer;

impl PqcReadinessScorer {
    pub fn assess(
        groups: Option<&GroupEnumerationResult>,
        cert_chain: Option<&CertificateChain>,
        protocols: &[ProtocolTestResult],
    ) -> PqcReadinessAssessment {
        let mut score: u8 = 0;
        let mut pq_safe_groups = Vec::new();
        let mut recommendations = Vec::new();

        // --- Key exchange group check ---
        if let Some(g) = groups {
            let supported_total = g.groups.iter().filter(|grp| grp.supported).count();
            let pq_supported: Vec<_> = g
                .groups
                .iter()
                .filter(|grp| grp.supported && !grp.quantum_vulnerable)
                .collect();

            for grp in &pq_supported {
                pq_safe_groups.push(grp.name.clone());
            }

            if !pq_supported.is_empty() {
                score = score.saturating_add(30);
                // Bonus: majority of supported groups are PQC-safe
                if supported_total > 0 && pq_supported.len() * 2 > supported_total {
                    score = score.saturating_add(20);
                }
            } else {
                recommendations.push(
                    "Deploy X25519MLKEM768 as a preferred key share in TLS 1.3 (IANA 0x11EC).".to_string(),
                );
            }
        } else {
            recommendations.push(
                "Run with --show-groups to assess key exchange group PQC readiness.".to_string(),
            );
        }

        // --- Certificate signature algorithm check ---
        let cert_is_pqc = cert_chain
            .and_then(|c| c.leaf())
            .map(|leaf| is_pqc_sig(&leaf.signature_algorithm))
            .unwrap_or(false);

        if cert_is_pqc {
            score = score.saturating_add(30);
        } else {
            recommendations.push(
                "Migrate to a hybrid/PQC certificate (ML-DSA, Falcon) when your CA supports it.".to_string(),
            );
        }

        // --- TLS 1.3 exclusive bonus ---
        let has_tls13 = protocols.iter().any(|p| p.protocol == Protocol::TLS13 && p.supported);
        let has_legacy = protocols.iter().any(|p| {
            matches!(p.protocol, Protocol::SSLv2 | Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11 | Protocol::TLS12)
                && p.supported
        });

        if has_tls13 && !has_legacy {
            score = score.saturating_add(20);
        } else if has_tls13 {
            recommendations.push(
                "Disable TLS 1.2 and earlier; TLS 1.3-only strengthens PQC posture.".to_string(),
            );
        } else {
            recommendations.push(
                "Enable TLS 1.3 support — required for PQC hybrid key exchange groups.".to_string(),
            );
        }

        let quantum_vulnerable_only = pq_safe_groups.is_empty();
        let hndl_risk = quantum_vulnerable_only;
        if hndl_risk {
            recommendations.push(
                "HNDL risk: intercepted traffic can be decrypted retroactively once a quantum computer exists; deploy X25519MLKEM768 immediately.".to_string(),
            );
        }
        let level = match score {
            0..=24 => PqcLevel::None,
            25..=49 => PqcLevel::Partial,
            50..=74 => PqcLevel::Hybrid,
            _ => PqcLevel::Full,
        };

        PqcReadinessAssessment {
            score,
            level,
            pq_safe_groups,
            quantum_vulnerable_only,
            hndl_risk,
            recommendations,
        }
    }
}

fn is_pqc_sig(sig_alg: &str) -> bool {
    let lower = sig_alg.to_lowercase();
    lower.contains("dilithium")
        || lower.contains("falcon")
        || lower.contains("sphincs")
        || lower.contains("ml-dsa")
        || lower.contains("mldsa")
        || lower.contains("slh-dsa")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_level_none_when_no_data() {
        let assessment = PqcReadinessScorer::assess(None, None, &[]);
        assert_eq!(assessment.level, PqcLevel::None);
        assert_eq!(assessment.score, 0);
        assert!(assessment.quantum_vulnerable_only);
    }

    #[test]
    fn test_hndl_risk_true_when_quantum_vulnerable_only() {
        let assessment = PqcReadinessScorer::assess(None, None, &[]);
        assert!(assessment.hndl_risk);
        assert!(assessment.recommendations.iter().any(|r| r.contains("HNDL")));
    }

    #[test]
    fn test_pqc_level_labels() {
        assert_eq!(PqcLevel::None.label(), "None");
        assert_eq!(PqcLevel::Partial.label(), "Partial");
        assert_eq!(PqcLevel::Hybrid.label(), "Hybrid");
        assert_eq!(PqcLevel::Full.label(), "Full");
    }

    #[test]
    fn test_is_pqc_sig_detects_pqc_algorithms() {
        assert!(is_pqc_sig("dilithium3"));
        assert!(is_pqc_sig("Falcon-512"));
        assert!(is_pqc_sig("ML-DSA-65"));
        assert!(!is_pqc_sig("sha256WithRSAEncryption"));
        assert!(!is_pqc_sig("ecdsa-with-SHA256"));
    }
}
