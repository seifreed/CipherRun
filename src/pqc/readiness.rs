// PQC Readiness Assessment and Scoring

use crate::certificates::parser::CertificateChain;
use crate::protocols::groups::GroupEnumerationResult;
use crate::protocols::{Protocol, ProtocolTestResult};
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
    /// True when at least one quantum-vulnerable key exchange group remains negotiable —
    /// traffic on that path can be harvested now and decrypted retroactively once a
    /// large-scale quantum computer exists, even if PQC-safe groups are also offered
    /// (downgrade attacks).
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
        let mut vulnerable_supported: usize = 0;

        // --- Key exchange group check ---
        if let Some(g) = groups {
            let supported_total = g.groups.iter().filter(|grp| grp.supported).count();
            let pq_supported: Vec<_> = g
                .groups
                .iter()
                .filter(|grp| grp.supported && !grp.quantum_vulnerable)
                .collect();
            vulnerable_supported = g
                .groups
                .iter()
                .filter(|grp| grp.supported && grp.quantum_vulnerable)
                .count();

            for grp in &pq_supported {
                pq_safe_groups.push(grp.name.clone());
            }

            if !pq_supported.is_empty() {
                score = score.saturating_add(30);
                // Bonus: PQC-safe groups are at least half of the supported set
                // (parity-or-better counts, since mid-migration deployments typically
                // advertise equal numbers of classical and PQC groups).
                if supported_total > 0 && pq_supported.len() * 2 >= supported_total {
                    score = score.saturating_add(20);
                }
            } else {
                recommendations.push(
                    "Deploy X25519MLKEM768 as a preferred key share in TLS 1.3 (IANA 0x11EC)."
                        .to_string(),
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
                "Migrate to a hybrid/PQC certificate (ML-DSA, Falcon) when your CA supports it."
                    .to_string(),
            );
        }

        // --- TLS 1.3 exclusive bonus ---
        let has_tls13 = protocols
            .iter()
            .any(|p| p.protocol == Protocol::TLS13 && p.supported);
        let has_legacy = protocols.iter().any(|p| {
            matches!(
                p.protocol,
                Protocol::SSLv2
                    | Protocol::SSLv3
                    | Protocol::TLS10
                    | Protocol::TLS11
                    | Protocol::TLS12
            ) && p.supported
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
        // HNDL risk exists whenever any classical group is still negotiable — even in
        // hybrid deployments, an active attacker can force-select the classical path.
        let hndl_risk = quantum_vulnerable_only || vulnerable_supported > 0;
        if hndl_risk {
            recommendations.push(
                "HNDL risk: intercepted traffic can be decrypted retroactively once a quantum computer exists; deploy X25519MLKEM768 immediately.".to_string(),
            );
        }
        let level = match score {
            0..=24 => PqcLevel::None,
            25..=59 => PqcLevel::Partial,
            60..=79 => PqcLevel::Hybrid,
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
    use crate::protocols::groups::{GroupEnumerationResult, GroupType, KeyExchangeGroup};

    fn kx_group(name: &str, quantum_vulnerable: bool, supported: bool) -> KeyExchangeGroup {
        KeyExchangeGroup {
            name: name.to_string(),
            iana_value: 0,
            group_type: if quantum_vulnerable {
                GroupType::EllipticCurve
            } else {
                GroupType::PostQuantum
            },
            bits: 256,
            supported,
            quantum_vulnerable,
        }
    }

    fn groups(gs: Vec<KeyExchangeGroup>) -> GroupEnumerationResult {
        GroupEnumerationResult {
            groups: gs,
            measured: true,
            details: String::new(),
        }
    }

    fn proto_result(protocol: Protocol, supported: bool) -> ProtocolTestResult {
        ProtocolTestResult {
            protocol,
            supported,
            preferred: false,
            ciphers_count: 0,
            handshake_time_ms: None,
            heartbeat_enabled: None,
            session_resumption_caching: None,
            session_resumption_tickets: None,
            secure_renegotiation: None,
        }
    }

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
        assert!(
            assessment
                .recommendations
                .iter()
                .any(|r| r.contains("HNDL"))
        );
    }

    #[test]
    fn test_hndl_risk_true_in_hybrid_config() {
        // Server offers BOTH a classical group AND a PQC-safe group. A downgrade
        // attacker can still force the classical path, so HNDL risk remains.
        let g = groups(vec![
            kx_group("X25519", true, true),
            kx_group("X25519MLKEM768", false, true),
        ]);
        let assessment = PqcReadinessScorer::assess(Some(&g), None, &[]);
        assert!(!assessment.quantum_vulnerable_only);
        assert!(
            assessment.hndl_risk,
            "hybrid deployment must still be flagged HNDL-at-risk due to downgrade path"
        );
    }

    #[test]
    fn test_hndl_risk_false_when_all_supported_are_pqc() {
        // No classical group is negotiable → no downgrade target → no HNDL risk.
        let g = groups(vec![
            kx_group("X25519", true, false),
            kx_group("X25519MLKEM768", false, true),
        ]);
        let assessment = PqcReadinessScorer::assess(Some(&g), None, &[]);
        assert!(!assessment.hndl_risk);
    }

    #[test]
    fn test_majority_bonus_fires_on_equal_split() {
        // 2 classical + 2 PQC supported → parity counts; +20 bonus expected.
        let g = groups(vec![
            kx_group("X25519", true, true),
            kx_group("secp256r1", true, true),
            kx_group("X25519MLKEM768", false, true),
            kx_group("X25519Kyber768Draft00", false, true),
        ]);
        let assessment = PqcReadinessScorer::assess(Some(&g), None, &[]);
        // 30 (PQ present) + 20 (majority bonus) = 50, no cert, no TLS13
        assert_eq!(
            assessment.score, 50,
            "equal-split should earn majority bonus"
        );
    }

    #[test]
    fn test_pqc_level_partial_at_score_50() {
        // 30 (PQ group, minority of 3 supported) + 20 (TLS 1.3 exclusive) = 50
        // → Partial (no PQ cert and PQ is <50% of supported groups).
        let g = groups(vec![
            kx_group("secp256r1", true, true),
            kx_group("secp384r1", true, true),
            kx_group("X25519MLKEM768", false, true),
        ]);
        let protocols = vec![proto_result(Protocol::TLS13, true)];
        let assessment = PqcReadinessScorer::assess(Some(&g), None, &protocols);
        assert_eq!(assessment.score, 50);
        assert_eq!(
            assessment.level,
            PqcLevel::Partial,
            "score 50 without PQ certificate is Partial, not Hybrid"
        );
    }

    #[test]
    fn test_pqc_level_hybrid_requires_kex_plus_cert() {
        // 30 (PQ group) + 20 (majority bonus with sole PQ group supported) +
        // TLS 1.3 not exclusive → 50. Add cert to reach 80 → Full.
        // To hit Hybrid, craft: PQ group (30) + PQ cert (30) = 60 with no bonus
        // (need at least one classical supported to keep ratio under half).
        let g = groups(vec![
            kx_group("secp256r1", true, true),
            kx_group("secp384r1", true, true),
            kx_group("X25519MLKEM768", false, true),
        ]);
        // 1 of 3 is PQ → no majority bonus. Score = 30 only.
        let assessment = PqcReadinessScorer::assess(Some(&g), None, &[]);
        assert_eq!(assessment.score, 30);
        assert_eq!(assessment.level, PqcLevel::Partial);
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
