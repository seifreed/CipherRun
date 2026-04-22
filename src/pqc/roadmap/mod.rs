// PQC Migration Roadmap Generator
//
// Produces a prioritized 4-phase migration plan from scan results.

use crate::scanner::ScanResults;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoadmapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl RoadmapSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            RoadmapSeverity::Critical => "CRITICAL",
            RoadmapSeverity::High => "HIGH",
            RoadmapSeverity::Medium => "MEDIUM",
            RoadmapSeverity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub severity: RoadmapSeverity,
    pub phase: u8,
    pub title: String,
    pub action: String,
    pub timeline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRoadmap {
    pub target: String,
    pub steps: Vec<MigrationStep>,
}

pub struct RoadmapGenerator;

impl RoadmapGenerator {
    pub fn from_scan(results: &ScanResults) -> MigrationRoadmap {
        let mut steps = Vec::new();

        // Check for legacy protocols
        let has_sslv2 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::SSLv2) && p.supported);
        let has_sslv3 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::SSLv3) && p.supported);
        let has_tls10 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS10) && p.supported);
        let has_tls11 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS11) && p.supported);
        let has_tls13 = results
            .protocols
            .iter()
            .any(|p| matches!(p.protocol, crate::protocols::Protocol::TLS13) && p.supported);

        if has_sslv2 || has_sslv3 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::Critical,
                phase: 1,
                title: "Disable SSLv2/SSLv3".to_string(),
                action: "Remove SSLv2 and SSLv3 support immediately — broken protocols vulnerable to POODLE/DROWN.".to_string(),
                timeline: "Immediate".to_string(),
            });
        }

        if has_tls10 || has_tls11 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 1,
                title: "Disable TLS 1.0 / TLS 1.1".to_string(),
                action: "Remove TLS 1.0 and TLS 1.1 support (deprecated by RFC 8996).".to_string(),
                timeline: "0-30 days".to_string(),
            });
        }

        // Check for PQC group support
        let has_pqc_group = results
            .advanced
            .as_ref()
            .and_then(|a| a.key_exchange_groups.as_ref())
            .map(|g| g.groups.iter().any(|grp| grp.supported && !grp.quantum_vulnerable))
            .unwrap_or(false);

        if !has_pqc_group {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 2,
                title: "Deploy X25519MLKEM768 hybrid key exchange".to_string(),
                action: "Configure X25519MLKEM768 (IANA 0x11EC) as preferred TLS 1.3 key share. Cloudflare/Google already deploy this by default.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        if !has_tls13 {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::High,
                phase: 2,
                title: "Enable TLS 1.3".to_string(),
                action: "TLS 1.3 is required for PQC hybrid key exchange groups.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        // Certificate RSA key size
        let rsa_small = results
            .certificate_chain
            .as_ref()
            .and_then(|c| c.chain.leaf())
            .and_then(|leaf| leaf.public_key_size)
            .map(|bits| bits < 3072)
            .unwrap_or(false);

        if rsa_small {
            steps.push(MigrationStep {
                severity: RoadmapSeverity::Medium,
                phase: 2,
                title: "Upgrade RSA certificate key to ≥ 3072 bits".to_string(),
                action: "RSA-2048 provides ~112-bit classical security; upgrade to RSA-3072 for SP 800-131A compliance.".to_string(),
                timeline: "0-6 months".to_string(),
            });
        }

        steps.push(MigrationStep {
            severity: RoadmapSeverity::Medium,
            phase: 3,
            title: "Plan hybrid PQC certificate migration".to_string(),
            action: "Monitor CA/Browser Forum for hybrid certificate issuance (ML-DSA + ECDSA dual-sig). Plan internal PKI migration timeline.".to_string(),
            timeline: "6-18 months".to_string(),
        });

        steps.push(MigrationStep {
            severity: RoadmapSeverity::Low,
            phase: 4,
            title: "Full PQC certificate deployment".to_string(),
            action: "Deploy pure ML-DSA or Falcon certificates when ecosystem (browsers, CAs, load balancers) fully supports them.".to_string(),
            timeline: "18+ months".to_string(),
        });

        MigrationRoadmap {
            target: results.target.clone(),
            steps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanResults;

    #[test]
    fn test_roadmap_empty_scan_has_pqc_steps() {
        let results = ScanResults::default();
        let roadmap = RoadmapGenerator::from_scan(&results);
        assert!(!roadmap.steps.is_empty());
        assert!(roadmap.steps.iter().any(|s| s.title.contains("X25519MLKEM768")));
    }
}
