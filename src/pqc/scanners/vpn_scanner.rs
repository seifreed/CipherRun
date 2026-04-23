use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnScanResult {
    pub path: String,
    pub vpn_type: String,
    pub quantum_vulnerable: Vec<String>,
    pub pqc_safe: Vec<String>,
    pub score: u8,
    pub recommendations: Vec<String>,
}

pub struct VpnScanner;

impl VpnScanner {
    pub fn scan(path: &Path) -> Result<VpnScanResult> {
        let content = std::fs::read_to_string(path)?;
        let mut vulnerable = Vec::new();
        let mut recommendations = Vec::new();
        let vpn_type = detect_vpn_type(&content);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            if lower.starts_with("cipher ") || lower.starts_with("tls-cipher ") {
                vulnerable.push(trimmed.to_string());
            }
        }

        // WireGuard uses X25519 (classical) — inherently quantum-vulnerable
        if vpn_type == "WireGuard" {
            vulnerable.push("X25519 key exchange (WireGuard default — quantum-vulnerable)".to_string());
            recommendations.push("WireGuard does not yet support PQC. Monitor wireguard-go for ML-KEM integration.".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Migrate VPN to a stack supporting hybrid PQC key exchange when available.".to_string());
        }

        // `pqc_safe` is not populated by this scanner yet, so we cannot credit any
        // positive PQC posture — a config with no detected cipher directives is
        // "unknown", not "partially ready". Score = 0 until we have real evidence.
        if vulnerable.is_empty() {
            recommendations.push(
                "No cipher directives detected; VPN crypto configuration is unknown — audit deployment defaults and explicit `cipher`/`tls-cipher` settings.".to_string(),
            );
        }
        let score: u8 = 0;

        Ok(VpnScanResult {
            path: path.display().to_string(),
            vpn_type,
            quantum_vulnerable: vulnerable,
            pqc_safe: Vec::new(),
            score,
            recommendations,
        })
    }
}

fn detect_vpn_type(content: &str) -> String {
    if content.contains("[Interface]") && content.contains("PrivateKey") {
        "WireGuard".to_string()
    } else if content.contains("dev tun") || content.contains("dev tap") || content.contains("tls-auth") {
        "OpenVPN".to_string()
    } else {
        "Unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_config(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(contents.as_bytes()).expect("write config");
        f
    }

    #[test]
    fn test_vpn_no_evidence_scores_zero() {
        // Config with no `cipher`/`tls-cipher` directives — score must be 0, not 50.
        let f = tmp_config("# comment only\ndev tun\nremote vpn.example.com 1194\n");
        let result = VpnScanner::scan(f.path()).expect("scan should succeed");
        assert_eq!(
            result.score, 0,
            "absence of cipher evidence must not award a readiness score"
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("unknown")),
            "scanner should flag the unknown crypto state explicitly"
        );
    }

    #[test]
    fn test_vpn_wireguard_flagged_quantum_vulnerable() {
        let f = tmp_config("[Interface]\nPrivateKey = abc\n");
        let result = VpnScanner::scan(f.path()).expect("scan should succeed");
        assert_eq!(result.vpn_type, "WireGuard");
        assert!(
            result
                .quantum_vulnerable
                .iter()
                .any(|v| v.contains("X25519"))
        );
        assert_eq!(result.score, 0);
    }
}
