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

        let score = if vulnerable.is_empty() { 50u8 } else { 0 };

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
