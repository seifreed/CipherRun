use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_VPN_CONFIG_BYTES: u64 = 1024 * 1024;

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
        let size = std::fs::metadata(path)?.len();
        if size > MAX_VPN_CONFIG_BYTES {
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "VPN config '{}' is too large: {} bytes (max {})",
                    path.display(),
                    size,
                    MAX_VPN_CONFIG_BYTES
                ),
            });
        }

        let content = std::fs::read_to_string(path)?;
        let mut vulnerable = Vec::new();
        let mut recommendations = Vec::new();
        let vpn_type = detect_vpn_type(&content);
        let mut saw_cipher_directive = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            let directive = trimmed.split_whitespace().next().unwrap_or_default();
            if directive.eq_ignore_ascii_case("cipher")
                || directive.eq_ignore_ascii_case("tls-cipher")
            {
                saw_cipher_directive = true;
            }
            // Only the control-channel TLS suite (`tls-cipher`) encodes the
            // classical key exchange that is quantum-vulnerable. `cipher` selects
            // the symmetric data-channel cipher (e.g. AES-256-GCM), which is NOT
            // quantum-vulnerable — AES-256 retains ~128-bit strength under Grover
            // — so flagging it here was a false positive on essentially every
            // OpenVPN config.
            if directive.eq_ignore_ascii_case("tls-cipher") {
                vulnerable.push(trimmed.to_string());
            }
        }

        // WireGuard uses X25519 (classical) — inherently quantum-vulnerable
        if vpn_type == "WireGuard" {
            vulnerable
                .push("X25519 key exchange (WireGuard default — quantum-vulnerable)".to_string());
            recommendations.push(
                "WireGuard does not yet support PQC. Monitor wireguard-go for ML-KEM integration."
                    .to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations.push(
                "Migrate VPN to a stack supporting hybrid PQC key exchange when available."
                    .to_string(),
            );
        }

        // `pqc_safe` is not populated by this scanner yet, so we cannot credit any
        // positive PQC posture — a config with no detected cipher directives is
        // "unknown", not "partially ready". Score = 0 until we have real evidence.
        if !saw_cipher_directive && vpn_type != "WireGuard" {
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
    } else if content.contains("dev tun")
        || content.contains("dev tap")
        || content.contains("tls-auth")
    {
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
    fn test_vpn_scan_rejects_oversized_config_before_read() {
        let f = tempfile::NamedTempFile::new().expect("create temp file");
        f.as_file()
            .set_len(MAX_VPN_CONFIG_BYTES + 1)
            .expect("resize temp file");

        let err = VpnScanner::scan(f.path()).expect_err("oversized VPN config should fail");

        assert!(err.to_string().contains("VPN config"));
        assert!(err.to_string().contains("too large"));
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
            result.recommendations.iter().any(|r| r.contains("unknown")),
            "scanner should flag the unknown crypto state explicitly"
        );
    }

    #[test]
    fn test_vpn_symmetric_cipher_not_flagged_but_tls_kex_is() {
        // `cipher AES-256-GCM` is symmetric (quantum-safe) and must NOT be
        // flagged; the `tls-cipher` control-channel KEX is quantum-vulnerable.
        let f =
            tmp_config("cipher AES-256-GCM\ntls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\n");
        let result = VpnScanner::scan(f.path()).expect("scan should succeed");
        assert!(
            !result
                .quantum_vulnerable
                .iter()
                .any(|v| v.contains("AES-256-GCM") && v.starts_with("cipher")),
            "symmetric AES-256 cipher must not be flagged quantum-vulnerable: {:?}",
            result.quantum_vulnerable
        );
        assert!(
            result
                .quantum_vulnerable
                .iter()
                .any(|v| v.starts_with("tls-cipher")),
            "tls-cipher control-channel KEX must be flagged: {:?}",
            result.quantum_vulnerable
        );
    }

    #[test]
    fn test_vpn_cipher_directives_accept_tabs() {
        let f = tmp_config("tls-cipher\tTLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\n");
        let result = VpnScanner::scan(f.path()).expect("scan should succeed");

        assert!(
            result
                .quantum_vulnerable
                .iter()
                .any(|v| v.starts_with("tls-cipher")),
            "tab-separated tls-cipher must be detected: {:?}",
            result.quantum_vulnerable
        );
        assert!(
            !result.recommendations.iter().any(|r| r.contains("unknown")),
            "detected cipher directives must not be reported as absent"
        );
    }

    #[test]
    fn test_vpn_wireguard_flagged_quantum_vulnerable() {
        let f = tmp_config("[Interface]\nPrivateKey = abc\n");
        let result = VpnScanner::scan(f.path()).expect("scan should succeed");
        assert_eq!(result.vpn_type, "WireGuard");
        assert!(result
            .quantum_vulnerable
            .iter()
            .any(|v| v.contains("X25519")));
        assert_eq!(result.score, 0);
    }
}
